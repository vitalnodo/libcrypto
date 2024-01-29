const std = @import("std");
const aes = std.crypto.core.aes;
const mem = std.mem;
const debug = std.debug;
const testing = std.testing;

pub fn XTS(
    comptime BlockCipher: anytype,
    comptime EncryptCtx: anytype,
    comptime DecryptCtx: anytype,
) type {
    const BLK = EncryptCtx(BlockCipher).block_length;
    const key_bits = BlockCipher.key_bits;

    return struct {
        const Self = @This();
        enc_ecb: EncryptCtx(BlockCipher),
        dec_ecb: DecryptCtx(BlockCipher),
        enc_tweak: EncryptCtx(BlockCipher),

        pub fn init(key: []const u8) Self {
            std.debug.assert(key_bits == 128 or key_bits == 256);
            std.debug.assert(key.len == key_bits / 8 * 2);
            const middle = key_bits / 8;
            const enc_ecb = EncryptCtx(BlockCipher).init(key[0..middle].*);
            const dec_ecb = DecryptCtx(BlockCipher).init(key[0..middle].*);
            const enc_tweak = EncryptCtx(BlockCipher).init(
                key[middle .. middle * 2].*,
            );
            return .{
                .enc_ecb = enc_ecb,
                .dec_ecb = dec_ecb,
                .enc_tweak = enc_tweak,
            };
        }

        fn initTweak(self: Self, IV: []const u8) [BLK]u8 {
            var tweak: [BLK]u8 = undefined;
            @memset(&tweak, 0);
            @memcpy(tweak[0..IV.len], IV);
            // 1) T ← AES-enc(Key2, i) ⊗ α^j
            self.enc_tweak.encrypt(&tweak, &tweak);
            return tweak;
        }

        fn encryptBlock(
            self: Self,
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
            self: Self,
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
            self: Self,
            dst: []u8,
            src: []const u8,
            IV: []const u8,
        ) void {
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
                var stealing: [BLK]u8 = undefined;
                @memcpy(stealing[0..rem], src[len - rem .. len]);
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
            self: Self,
            dst: []u8,
            src: []const u8,
            IV: []const u8,
        ) void {
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
                var stealing: [BLK]u8 = undefined;
                @memcpy(stealing[0..rem], src[len - rem .. len]);
                @memcpy(stealing[rem..], last);
                // h) P_{m-1} ← XTS-AES-blockDec(Key, CC, i, m-1)
                self.decryptBlock(
                    dst[len - rem - BLK .. len - rem],
                    &stealing,
                    &previous_tweak,
                );
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
        var x = X.init(&key);
        x.encrypt(res_encrypted[0..len], src[0..len], iv[0..iv_len]);
        try testing.expectEqualSlices(u8, dst[0..len], res_encrypted[0..len]);
        x.decrypt(res_decrypted[0..len], dst[0..len], iv[0..iv_len]);
        try testing.expectEqualSlices(u8, src[0..len], res_decrypted[0..len]);
    }
}
