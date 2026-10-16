const std = @import("std");
const aes = std.crypto.core.aes;
const mem = std.mem;
const debug = std.debug;
const testing = std.testing;
const twofish = @import("../../ciphers/twofish/main.zig");
const serpent = @import("../../ciphers/serpent/main.zig");

pub fn XTS(
    comptime BlockCipher: anytype,
    comptime EncryptCtx: anytype,
    comptime DecryptCtx: anytype,
) type {
    const BLK = EncryptCtx(BlockCipher).block_length;
    const key_bits = BlockCipher.key_bits;
    if (key_bits != 128 and key_bits != 256) {
        @compileError("XTS supports only 128-bit and 256-bit keys");
    }

    return struct {
        const Self = @This();
        pub const key_length = key_bits / 8 * 2;
        pub const Error = error{InvalidLength};

        enc_ecb: EncryptCtx(BlockCipher),
        dec_ecb: DecryptCtx(BlockCipher),
        enc_tweak: EncryptCtx(BlockCipher),

        pub fn init(key: []const u8) Error!Self {
            if (key.len != key_length) return error.InvalidLength;
            const middle = key_bits / 8;
            // Explicit copies so they can be wiped, temporaries would stay on the stack
            var key1: [middle]u8 = key[0..middle].*;
            defer std.crypto.secureZero(u8, &key1);
            var key2: [middle]u8 = key[middle .. middle * 2].*;
            defer std.crypto.secureZero(u8, &key2);
            const enc_ecb = EncryptCtx(BlockCipher).init(key1);
            const dec_ecb = DecryptCtx(BlockCipher).init(key1);
            const enc_tweak = EncryptCtx(BlockCipher).init(key2);
            return .{
                .enc_ecb = enc_ecb,
                .dec_ecb = dec_ecb,
                .enc_tweak = enc_tweak,
            };
        }

        /// Zero all key schedules.
        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }

        fn initTweak(self: *const Self, IV: []const u8) [BLK]u8 {
            var tweak: [BLK]u8 = undefined;
            @memset(&tweak, 0);
            @memcpy(tweak[0..IV.len], IV);
            // 1) T ← AES-enc(Key2, i) ⊗ α^j
            self.enc_tweak.encrypt(&tweak, &tweak);
            return tweak;
        }

        fn encryptBlock(
            self: *const Self,
            dst: []u8,
            src: []const u8,
            tweak: []u8,
        ) void {
            std.debug.assert(dst.len == BLK and src.len == BLK);
            std.debug.assert(tweak.len == BLK);
            var x: [BLK]u8 = undefined;
            // 2) PP ← P ⊕ T
            xor(x[0..BLK], src[0..BLK], tweak[0..BLK]);
            // 3) CC ← AES-enc(Key1, PP)
            self.enc_ecb.encrypt(&x, &x);
            // 4) C ← CC ⊕ T
            xor(dst[0..BLK], x[0..BLK], tweak[0..BLK]);
            mul2(tweak[0..BLK]);
        }

        fn decryptBlock(
            self: *const Self,
            dst: []u8,
            src: []const u8,
            tweak: []u8,
        ) void {
            std.debug.assert(dst.len == BLK and src.len == BLK);
            std.debug.assert(tweak.len == BLK);
            var x: [BLK]u8 = undefined;
            // 2) CC ← C ⊕ T
            xor(x[0..BLK], src[0..BLK], tweak[0..BLK]);
            // 3) PP ← AES-dec(Key1, CC)
            self.dec_ecb.decrypt(&x, &x);
            // P ← PP ⊕ T
            xor(dst[0..BLK], x[0..BLK], tweak[0..BLK]);
            mul2(tweak[0..BLK]);
        }

        pub fn encrypt(
            self: *const Self,
            dst: []u8,
            src: []const u8,
            IV: []const u8,
        ) Error!void {
            try checkLengths(dst, src, IV);
            const len = src.len;
            var tweak: [BLK]u8 = self.initTweak(IV);
            var i: usize = 0;
            // 1) for q ← 0 to m-2 do
            while (i + 2 * BLK <= len) : (i += BLK) {
                // a) C_q ← XTS-AES-blockEnc(Key, P^j, i, q)
                self.encryptBlock(
                    dst[i .. i + BLK],
                    src[i .. i + BLK],
                    &tweak,
                );
            }
            // 2) b ← bit-size of P_m
            // but bytes
            const rem = len % BLK;
            // 3) if b = 0 then do
            if (rem == 0) {
                // a) C_{m–1} ← XTS–AES-blockEnc(Key, P_{m–1}, i, m–1)
                self.encryptBlock(
                    dst[i .. i + BLK],
                    src[i .. i + BLK],
                    &tweak,
                );
                // b) Cm ← empty
                // nothing
            } else {
                // Save P_m before dst is written, src and dst may be the same buffer
                var stealing: [BLK]u8 = undefined;
                @memcpy(stealing[0..rem], src[len - rem .. len]);
                // a) CC ← XTS-AES-blockEnc(Key, Pm–1, i, m–1)
                self.encryptBlock(
                    dst[i .. i + BLK],
                    src[i .. i + BLK],
                    &tweak,
                );
                // b) C_m ← first b bits of CC
                @memcpy(dst[len - rem ..], dst[i .. i + rem]);
                // c) CP ← last (128–b) bits of CC
                const last = dst[i .. i + BLK][rem..];
                // d) PP ← Pm | CP
                @memcpy(stealing[rem..], last);
                // e) C_{m–1} ← XTS-AES-blockEnc(Key, PP, i, m)
                self.encryptBlock(
                    dst[len - rem - BLK .. len - rem],
                    &stealing,
                    &tweak,
                );
            }
        }

        pub fn decrypt(
            self: *const Self,
            dst: []u8,
            src: []const u8,
            IV: []const u8,
        ) Error!void {
            try checkLengths(dst, src, IV);
            const len = src.len;
            var tweak: [BLK]u8 = self.initTweak(IV);
            var i: usize = 0;
            // 1) for q ← 0 to m-2 do
            while (i + 2 * BLK <= len) : (i += BLK) {
                // a) P_q ← XTS-AES-blockDec(Key, Cj, i, q)
                self.decryptBlock(
                    dst[i .. i + BLK],
                    src[i .. i + BLK],
                    &tweak,
                );
            }
            // 2) b ← bit-size of C_m
            // but bytes
            const rem = len % BLK;
            // 3) if b = 0 then do
            if (rem == 0) {
                // b) P_{m-1} ← XTS-AES-blockDec(Key, C_{m-1}, i, m-1)
                self.decryptBlock(
                    dst[i .. i + BLK],
                    src[i .. i + BLK],
                    &tweak,
                );
                // c) P_m ← empty
                // nothing
            } else {
                // Save C_m before dst is written, src and dst may be the same buffer
                var stealing: [BLK]u8 = undefined;
                @memcpy(stealing[0..rem], src[len - rem .. len]);
                var previous_tweak = tweak;
                mul2(&tweak);
                self.decryptBlock(
                    dst[i .. i + BLK],
                    src[i .. i + BLK],
                    &tweak,
                );
                // e) Pm ← first b bits of PP
                @memcpy(dst[len - rem ..], dst[i .. i + rem]);
                // f) CP ← last (128-b) bits of PP
                const last = dst[i .. i + BLK][rem..];
                // g) CC ← C_m | CP
                @memcpy(stealing[rem..], last);
                // h) P_{m-1} ← XTS-AES-blockDec(Key, CC, i, m-1)
                self.decryptBlock(
                    dst[len - rem - BLK .. len - rem],
                    &stealing,
                    &previous_tweak,
                );
            }
        }

        fn checkLengths(dst: []u8, src: []const u8, IV: []const u8) Error!void {
            // XTS needs at least one full block; shorter data can't be stolen from
            if (src.len < BLK or dst.len != src.len or IV.len > BLK) {
                return error.InvalidLength;
            }
        }

        inline fn xor(out: []u8, a: []const u8, b: []const u8) void {
            var i: usize = 0;
            while (i < a.len) : (i += 1) {
                out[i] = a[i] ^ b[i];
            }
        }

        // mul2 multiplies tweak by 2 in GF(2^128) with an irreducible polynomial
        // of x^128 + x^7 + x^2 + x + 1.
        fn mul2(tweak: *[16]u8) void {
            var carry_in: u8 = 0;
            var carry_out: u8 = 0;
            for (0..tweak.len) |j| {
                carry_out = tweak[j] >> 7;
                tweak[j] = (tweak[j] << 1) + carry_in;
                carry_in = carry_out;
            }
            if (carry_out != 0) {
                tweak[0] ^= 1 << 7 | 1 << 2 | 1 << 1 | 1;
            }
        }
    };
}

const Test = struct {
    key: []const u8,
    src: []const u8,
    dst: []const u8,
    iv: []const u8,
};
test "AES128" {
    const EncryptCtx = aes.AesEncryptCtx;
    const DecryptCtx = aes.AesDecryptCtx;
    const X = XTS(
        aes.Aes128,
        EncryptCtx,
        DecryptCtx,
    );
    const tests = [_]Test{
        Test{
            .key = "0000000000000000000000000000000000000000000000000000000000000000",
            .iv = "00",
            .src = "0000000000000000000000000000000000000000000000000000000000000000",
            .dst = "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e",
        },
        Test{
            .key = "1111111111111111111111111111111122222222222222222222222222222222",
            .iv = "3333333333",
            .src = "4444444444444444444444444444444444444444444444444444444444444444",
            .dst = "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
        },
        Test{
            .key = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
            .iv = "3333333333",
            .src = "4444444444444444444444444444444444444444444444444444444444444444",
            .dst = "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89",
        },
        Test{
            .key = "2718281828459045235360287471352631415926535897932384626433832795",
            .iv = "00",
            .src = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            .dst = "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568",
        },
        Test{
            .key = "2718281828459045235360287471352631415926535897932384626433832795",
            .iv = "01",
            .src = "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568",
            .dst = "264d3ca8512194fec312c8c9891f279fefdd608d0c027b60483a3fa811d65ee59d52d9e40ec5672d81532b38b6b089ce951f0f9c35590b8b978d175213f329bb1c2fd30f2f7f30492a61a532a79f51d36f5e31a7c9a12c286082ff7d2394d18f783e1a8e72c722caaaa52d8f065657d2631fd25bfd8e5baad6e527d763517501c68c5edc3cdd55435c532d7125c8614deed9adaa3acade5888b87bef641c4c994c8091b5bcd387f3963fb5bc37aa922fbfe3df4e5b915e6eb514717bdd2a74079a5073f5c4bfd46adf7d282e7a393a52579d11a028da4d9cd9c77124f9648ee383b1ac763930e7162a8d37f350b2f74b8472cf09902063c6b32e8c2d9290cefbd7346d1c779a0df50edcde4531da07b099c638e83a755944df2aef1aa31752fd323dcb710fb4bfbb9d22b925bc3577e1b8949e729a90bbafeacf7f7879e7b1147e28ba0bae940db795a61b15ecf4df8db07b824bb062802cc98a9545bb2aaeed77cb3fc6db15dcd7d80d7d5bc406c4970a3478ada8899b329198eb61c193fb6275aa8ca340344a75a862aebe92eee1ce032fd950b47d7704a3876923b4ad62844bf4a09c4dbe8b4397184b7471360c9564880aedddb9baa4af2e75394b08cd32ff479c57a07d3eab5d54de5f9738b8d27f27a9f0ab11799d7b7ffefb2704c95c6ad12c39f1e867a4b7b1d7818a4b753dfd2a89ccb45e001a03a867b187f225dd",
        },
        // stealing
        Test{
            .key = "2718281828459045235360287471352631415926535897932384626433832795",
            .iv = "0102",
            .src = "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568bb",
            .dst = "f96839ed30f60cdae10198c675c4dfd688985256515f82c91f24457234668e06887acb0c63256cd760cd5458671088caf6bcdacb8a9c8427aef4e6b618c42c7b7c5e06c0734000d2a64ae40bf6fe0f1dc4b61f89c4068c35f263471800217f6110af5bc033d91942a8936eb502d4ea869700cf1fe4a187959e39f31c339be3ab0a14d43baf4a6932c083e1508a682d6b8e8d67f7216b2498d51b91e6e79cacb9535f0e4ae4b44b383bbad49fb57e70fbfd625ae6b6566398973b6989f0a04bd9cd42523e320f96749df446d38e23b0991ced816809a2432dd5076482bc3769f6fb8ca38505207496b9e23531bb52c573769d4b9078239ec94e4b1d2b84af8c3f0d43c6005e9076fe32ff35a938146c5c3359688106ef41edaafa47e2d7a71395be907a0b2e8b58cc716d4c3fb54f4b791f6bfefa0624a0d66edcfbcc3daf1612ff140821bd028247508ca75561c23f6493bb38450f07435c2580a00d2ef9e5d862e173b2e7bd2f2c461ac0940dedcb68073f2ef1f978b3da57fae0e0798d7559ff19cc95db653a3c6eaed509ee74f0e1894ff65e96fd5b374cf51458848460698fc7409f797ca832f0e2a45460cd5e70f8474d7dc6f19089e63aad487df0e3ddfd0eabcc7edb987c7b8f193ab77b18783e85a85e5f25ec9ec053608b986bd91a873c2f7f1785c8e78a8786cba9d2b65d472cbf937c695db64d81154a9da1343f0a",
        },
        Test{
            .key = "6242c3c425823cfda74149928c5db5af96699fdfe631b65ea806077f98a80c7e",
            .iv = "35e724e8b4dc622e",
            .src = "a85dc432d4ef10b0095a69d8ee4cc0f6aa",
            .dst = "6ea3b4f4bb53142a61fe0df8fb98be2401",
        },
    };
    for (tests, 0..) |_, i| {
        var key: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, tests[i].key);
        var iv: [16]u8 = undefined;
        _ = try std.fmt.hexToBytes(&iv, tests[i].iv);
        const iv_len = tests[i].iv.len / 2;
        var dst: [1025]u8 = undefined;
        _ = try std.fmt.hexToBytes(&dst, tests[i].dst);
        var src: [1025]u8 = undefined;
        const len = (try std.fmt.hexToBytes(&src, tests[i].src)).len;
        var res_encrypted: [1025]u8 = undefined;
        var res_decrypted: [1025]u8 = undefined;
        var x = try X.init(&key);
        try x.encrypt(res_encrypted[0..len], src[0..len], iv[0..iv_len]);
        try testing.expectEqualSlices(u8, dst[0..len], res_encrypted[0..len]);
        try x.decrypt(res_decrypted[0..len], dst[0..len], iv[0..iv_len]);
        try testing.expectEqualSlices(u8, src[0..len], res_decrypted[0..len]);

        // in place: dst and src are the same buffer
        var buf: [1025]u8 = undefined;
        @memcpy(buf[0..len], src[0..len]);
        try x.encrypt(buf[0..len], buf[0..len], iv[0..iv_len]);
        try testing.expectEqualSlices(u8, dst[0..len], buf[0..len]);
        try x.decrypt(buf[0..len], buf[0..len], iv[0..iv_len]);
        try testing.expectEqualSlices(u8, src[0..len], buf[0..len]);
    }
}

test "deinit zeroes the key schedules" {
    const X = XTS(aes.Aes256, aes.AesEncryptCtx, aes.AesDecryptCtx);
    const key: [X.key_length]u8 = @splat(0x5c);
    var x = try X.init(&key);
    x.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&x), 0));
}

test "invalid lengths" {
    const X = XTS(aes.Aes128, aes.AesEncryptCtx, aes.AesDecryptCtx);
    const key: [X.key_length]u8 = @splat(0);
    var buf: [32]u8 = @splat(0);
    var out: [32]u8 = undefined;
    const iv: [16]u8 = @splat(0);

    try testing.expectError(error.InvalidLength, X.init(key[0..31]));
    try testing.expectError(error.InvalidLength, X.init(&([_]u8{0} ++ key)));

    const x = try X.init(&key);
    // shorter than one block, including empty input
    try testing.expectError(error.InvalidLength, x.encrypt(out[0..15], buf[0..15], &iv));
    try testing.expectError(error.InvalidLength, x.decrypt(out[0..0], buf[0..0], &iv));
    // dst and src of different lengths
    try testing.expectError(error.InvalidLength, x.encrypt(out[0..16], buf[0..32], &iv));
    try testing.expectError(error.InvalidLength, x.decrypt(out[0..32], buf[0..16], &iv));
    // IV longer than a block
    const long_iv: [17]u8 = @splat(0);
    try testing.expectError(error.InvalidLength, x.encrypt(&out, &buf, &long_iv));
    // exactly one block is fine
    try x.encrypt(out[0..16], buf[0..16], &iv);
}

fn testVectors(comptime X: type, tests: []const Test) !void {
    for (tests) |t| {
        var key: [X.key_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, t.key);
        var iv_buf: [16]u8 = undefined;
        const iv = try std.fmt.hexToBytes(&iv_buf, t.iv);
        var src_buf: [512]u8 = undefined;
        const src = try std.fmt.hexToBytes(&src_buf, t.src);
        var dst_buf: [512]u8 = undefined;
        const dst = try std.fmt.hexToBytes(&dst_buf, t.dst);
        var out_buf: [512]u8 = undefined;
        const out = out_buf[0..src.len];

        const x = try X.init(&key);
        try x.encrypt(out, src, iv);
        try testing.expectEqualSlices(u8, dst, out);
        try x.decrypt(out, dst, iv);
        try testing.expectEqualSlices(u8, src, out);

        // in place
        @memcpy(out, src);
        try x.encrypt(out, out, iv);
        try testing.expectEqualSlices(u8, dst, out);
        try x.decrypt(out, out, iv);
        try testing.expectEqualSlices(u8, src, out);
    }
}

// Test vectors: tf_xts_tv_template and serpent_xts_tv_template from Linux
// crypto/testmgr.h (all cross-checked with Botan 2.19.3). Vectors with a
// partial last block are not in testmgr.h and were generated with Botan.

test "Twofish128" {
    const X = XTS(twofish.Twofish128, twofish.TwofishEncryptCtx, twofish.TwofishDecryptCtx);
    try testVectors(X, &[_]Test{
        .{
            .key = "0000000000000000000000000000000000000000000000000000000000000000",
            .iv = "00000000000000000000000000000000",
            .src = "0000000000000000000000000000000000000000000000000000000000000000",
            .dst = "4bc9444a11a3efac3074e44452779743a760b2452ef900909faafd896e9d4ae0",
        },
        .{
            .key = "1111111111111111111111111111111122222222222222222222222222222222",
            .iv = "33333333330000000000000000000000",
            .src = "4444444444444444444444444444444444444444444444444444444444444444",
            .dst = "570e8fe52a35614f32d3bd360515442c5806f7f800a8b6d5c62892dbd834a2e9",
        },
        .{
            .key = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
            .iv = "33333333330000000000000000000000",
            .src = "4444444444444444444444444444444444444444444444444444444444444444",
            .dst = "96458f8d7a75b1de400c8956f64da70738bb5be9cd84aeb27b6a62f48cb537ea",
        },
        .{
            .key = "2718281828459045235360287471352631415926535897932384626433832795",
            .iv = "00000000000000000000000000000000",
            .src = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" ++
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" ++
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" ++
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" ++
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" ++
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" ++
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" ++
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" ++
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" ++
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" ++
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" ++
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            .dst = "a978ae1eeaa2444ca27a641faf46c1e06cb2f3929ad67d58b82db95d58076650" ++
                "ea35358cb24661065d65fc578f6974ab8a0669b56cda66c75290bb8e6d8bb5a2" ++
                "781dc2a9c27300c332367c976b4e8a50e49183968ff4941aa627e133cb91c65f" ++
                "9475bcd73e3e6f9ea931805ee5dbc853017368322519fafbe4cfb93ea2a08f31" ++
                "bf540693a8b10fb67c3cde6f0ffb0c11398039099765f283aee6a16f47b849de" ++
                "9936207d973becfab4336e7ac746844991cde1570ded400813f14e3ea4a45ce6" ++
                "d20c208f3edf3f479a2fde6d66c9994a2d9e9d4b1a27a21299f0f8b1b6f657c3" ++
                "ca1ca38eed3928b5101b4b0842004ad3ad5ac68ec8bb95c44baafed542a8a36d" ++
                "3cf334912db4dd200c906da39b669d2402a6a93f3f585d472465637ebd8ce652" ++
                "7def335363ecaa0b6415a9a61f10003835a8e7be237022e0d3b9e6fde6aa0350" ++
                "f33c27368bccfe9c9ca3b3e7689ba271e007d91f681fac5e7a7485a96a90ab2c" ++
                "3851bc1f434a561cf847034e67a81f9904397332b28679e7142870b8e27d6985" ++
                "b60fc5d0d0015ce6090f75f7b681d211209ca1ee114479d0b23477da109a6f6f" ++
                "ef7cd9dc35b761ddf1a4c61cbf0522acfe2f850044df331635b6a3d370df6935" ++
                "6ac7b4994527c88e5a1430d0553e4f640d38e3df8ba8932675aef6b5230b1731" ++
                "bf27b8b59431a78f43c44624224f8f7ee5f46d1e0e187abba68ffb4949d87e5a",
        },
        // partial last block (Botan)
        .{
            .key = "2718281828459045235360287471352631415926535897932384626433832795",
            .iv = "00000000000000000000000000000000",
            .src = "000102030405060708090a0b0c0d0e0f10",
            .dst = "d1b920b60aed31c4925bdc59d283c423a9",
        },
    });
}

test "Twofish256" {
    const X = XTS(twofish.Twofish256, twofish.TwofishEncryptCtx, twofish.TwofishDecryptCtx);
    try testVectors(X, &[_]Test{
        .{
            .key = "2718281828459045235360287471352662497757247093699959574966967627" ++
                "3141592653589793238462643383279502884197169399375105820974944592",
            .iv = "ff000000000000000000000000000000",
            .src = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" ++
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" ++
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" ++
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" ++
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" ++
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" ++
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" ++
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" ++
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" ++
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" ++
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" ++
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            .dst = "d74b937d13a2a2e135397188761ec9ea86adf314483d5ee9e92db25659359dec" ++
                "84fa7e9d6d33368fcef4a9210b5f96eccbf95768338839bf2fbb5903bd668b11" ++
                "1165512eb86705d127115cd4cc97c2b3a955af0756d1dcf585dc46e6f024eb93" ++
                "4df09bf5731cda0322c83a4fb4199109540bf6fe173d1a53726079cb0e328a77" ++
                "d5eddb33d762166963e0abb5f69c5f3d69356186f886b9896e5935acf66b33a0" ++
                "eaef9662d8a9cf56bfdb8afda18277733d944a49426d0860a1eaabb6881394b8" ++
                "5198db3585dff6b98fcddf80d3402d72b8b26c024335222a31edcd1619df620f" ++
                "29cf8704ec024fe4a2ed73c669d37e890b76107cd6f96a25edcc605d6120c197" ++
                "56915728be710dcddec49e5591bed1289b90eb73f36851c6df82ccd81fce5b27" ++
                "c0605e33d6a720eab254c75d6a3b6747cfa0e3ab86afc142e6b0234aaf53dfa0" ++
                "ad12323103f721be2dd58242b64a3dcdd88177a949986c09c5a3611262856bcd" ++
                "b3f4200c41c40537465feb718bf1af6ebaf3502efea837ebe88c4fa40cf131c8" ++
                "6e714fa5d79773e0934a2fda7be020541f8d85790b7b5e75b90767ccc8e72115" ++
                "a7c898ff4b801c12a854e13852e674819747a1410ec050e3550ec3a77077ce07" ++
                "ed8c88e6a15b14ece6de066d74c5d9fae52f5affc805ee273561bf0b19789bd2" ++
                "04c705b179b4ff5ff3ea675278c2ce70a4050bb2b3a830973730e1918db32aff",
        },
        // partial last block (Botan)
        .{
            .key = "2718281828459045235360287471352662497757247093699959574966967627" ++
                "3141592653589793238462643383279502884197169399375105820974944592",
            .iv = "ff000000000000000000000000000000",
            .src = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e",
            .dst = "d74b937d13a2a2e135397188761ec9ea6f118a26d9fa062208ab21aeaeb29632" ++
                "86adf314483d5ee9e92db25659359d",
        },
    });
}

test "Serpent128" {
    const X = XTS(serpent.Serpent128, serpent.SerpentEncryptCtx, serpent.SerpentDecryptCtx);
    try testVectors(X, &[_]Test{
        .{
            .key = "0000000000000000000000000000000000000000000000000000000000000000",
            .iv = "00000000000000000000000000000000",
            .src = "0000000000000000000000000000000000000000000000000000000000000000",
            .dst = "e108b81d2cf53364c81204c7b370e8c46a31c5f300cab916dee27766f7fe6208",
        },
        .{
            .key = "1111111111111111111111111111111122222222222222222222222222222222",
            .iv = "33333333330000000000000000000000",
            .src = "4444444444444444444444444444444444444444444444444444444444444444",
            .dst = "1a0a095fcd070798418612afb3d76813ed81cd0687431abb133dd61e2be177be",
        },
        .{
            .key = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
            .iv = "33333333330000000000000000000000",
            .src = "4444444444444444444444444444444444444444444444444444444444444444",
            .dst = "f99b28b85caf8c61b61c818f2c8760890d8d7ae86048cc86c16845aa00e924c5",
        },
        .{
            .key = "2718281828459045235360287471352631415926535897932384626433832795",
            .iv = "00000000000000000000000000000000",
            .src = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" ++
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" ++
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" ++
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" ++
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" ++
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" ++
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" ++
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" ++
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" ++
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" ++
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" ++
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            .dst = "fe474ac8607eb48b0d10f4b00dbaf853656e384bdbaab19e28cab022b38575f4" ++
                "005c751406d62582e6cb08f72990238ea46857e4f0d832f3805167b50b8569e8" ++
                "19fec4c73eea90d38fa3f20aac174ba0635a160ff0ce661f2c2107f1a403a344" ++
                "4161875d6bb3efd4fcaa327e55580441c90733c6a268d65a55794b6fcf89b919" ++
                "e5541315b21afa15c2f00659faa0250558fa4391168540bb0d344dc51e20d508" ++
                "cd222241119f6c7c8d57c9ba57e82cf7a042a8defca3ca984b43b1ce4bbf0167" ++
                "6e2960bd1014848283820c637392027c553720801751c8bc4602cb38076de285" ++
                "aa29af24580df075080aa5342516f374a70b97bec1a9dc291a0a56c11a91978c" ++
                "0bc716ed5a22a62e8c2b4f547647538ee800ec92b955e6a2f3e24f6a6660d087" ++
                "e6d1cce36ac52d21cc9d6ab675aae219219fa15e4cfd72f9944e63c7aefced47" ++
                "e2fe7a6377fe9782b1106e361de1c480ec6941eca78ae02fe34926a241b2080f" ++
                "28b4a739a1992d1e434235d0cfec7767b23b9e1c35de4f5e733f5d6f074b2e50" ++
                "ab6c6bffea0067aa0e8232dd3db5e5762b773fbe1275fb92c689674dcaf7d450" ++
                "c07447ccd90ad4c63b172ee335bb53b586ad51ccd596b8dc0357e698522f6162" ++
                "c45c9c367107fb94e302c42b0875c735fb2e887bbb6700e1c9dd99b213531a4e" ++
                "768719041a2f383eef91641d18074e3188217cb0a5124c3cb020bddadff97cdd",
        },
        // partial last block (Botan)
        .{
            .key = "2718281828459045235360287471352631415926535897932384626433832795",
            .iv = "00000000000000000000000000000000",
            .src = "000102030405060708090a0b0c0d0e0f10",
            .dst = "63e1535dc9c6a65c3ee6b7c0c443fe55fe",
        },
    });
}

test "Serpent256" {
    const X = XTS(serpent.Serpent256, serpent.SerpentEncryptCtx, serpent.SerpentDecryptCtx);
    try testVectors(X, &[_]Test{
        .{
            .key = "2718281828459045235360287471352662497757247093699959574966967627" ++
                "3141592653589793238462643383279502884197169399375105820974944592",
            .iv = "ff000000000000000000000000000000",
            .src = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" ++
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" ++
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" ++
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" ++
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" ++
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" ++
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" ++
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" ++
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" ++
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" ++
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" ++
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            .dst = "2bc9b46b1094a932aab020c6443d741f7501a7f6f5f7621b801b82cb0159917f" ++
                "803a98f0d2cac4c334fde611f933451248c58c25f1c5c523d344b473d504c0b7" ++
                "ca2ff5cdc5b4ddb0f460e8fbc69cc578cdec7ddc199c7264630b382e76dd2d36" ++
                "49b01dea789e00ca20cc1b1e9874abed79f7d06cd8938029aca55e34a9aba055" ++
                "9aeaaa954d7bfe46268afd88a2a8a6ae254217bf768f1c3dec9ada6496b561ff" ++
                "99eb129685829dd5818514a859ac8c94bb3b852bdfb30cba82c64dca86ea5328" ++
                "4ce04e31e3732f799d42e103e38bc4ff05ca817bdaa2de633a10bec2ac32c405" ++
                "477eef67e25f5baeedf17034169a077bf2252bb0f83c159aa659555fc1f41ecd" ++
                "931f06bad49a2269fa8e950df323592cfe00baf00ebc6dd662f07a0e833edb32" ++
                "fd437dda425187439df9eff43097f80988fc3f9370c14aec275f11ac71c74846" ++
                "2ff9df8d9ff72e560d4eb03276ce8681cddfe400bffd5f24aff79adeff18ac14" ++
                "90c50139340f24f3132f5e4f309a3640eceabccd9e0e5b235088974069b137f5" ++
                "c315f93fb77964e87b1020b92b46835bd839fce4fa8852f272b0974e89b34800" ++
                "c116735077baa665202db0022789da9945fbe9d31d392fd62ada091211afe657" ++
                "01048aff868bacf8eee41c985bcf6b76a30e337440183972665031fd70dfe851" ++
                "962136b29bfa85d13005c8929880ff7aaf430bc520419220d4a09198115f4db1",
        },
        // partial last block (Botan)
        .{
            .key = "2718281828459045235360287471352662497757247093699959574966967627" ++
                "3141592653589793238462643383279502884197169399375105820974944592",
            .iv = "ff000000000000000000000000000000",
            .src = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
                "202122232425262728292a2b2c2d2e",
            .dst = "2bc9b46b1094a932aab020c6443d741fdac09a4d2ec3191bed1ed5909e20d51f" ++
                "7501a7f6f5f7621b801b82cb015991",
        },
    });
}
