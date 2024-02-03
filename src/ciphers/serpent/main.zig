const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const rotl = std.math.rotl;
const rotr = std.math.rotr;
const bufPrint = std.fmt.bufPrint;
const hexToBytes = std.fmt.hexToBytes;
const fmtSliceHexUpper = std.fmt.fmtSliceHexUpper;
const sBox = @import("sboxes.zig").sBox;
const sBoxInv = @import("sboxes.zig").sBoxInv;
const PHI: u32 = 0x9E3779B9;
const BlockVec = [4]u32;
const RoundKeys = [132]u32;

pub const Block = struct {
    pub const block_length = 16;
    repr: BlockVec align(16),

    /// Convert a byte sequence into an internal representation.
    pub inline fn fromBytes(bytes: *const [16]u8) Block {
        const s0 = mem.readInt(u32, bytes[0..4], .little);
        const s1 = mem.readInt(u32, bytes[4..8], .little);
        const s2 = mem.readInt(u32, bytes[8..12], .little);
        const s3 = mem.readInt(u32, bytes[12..16], .little);
        return Block{ .repr = BlockVec{ s0, s1, s2, s3 } };
    }

    /// Convert the internal representation of a block into a byte sequence.
    pub inline fn toBytes(block: Block) [16]u8 {
        var bytes: [16]u8 = undefined;
        mem.writeInt(u32, bytes[0..4], block.repr[0], .little);
        mem.writeInt(u32, bytes[4..8], block.repr[1], .little);
        mem.writeInt(u32, bytes[8..12], block.repr[2], .little);
        mem.writeInt(u32, bytes[12..16], block.repr[3], .little);
        return bytes;
    }

    /// XOR the block with a byte sequence.
    pub inline fn xorBytes(block: Block, bytes: *const [16]u8) [16]u8 {
        const block_bytes = block.toBytes();
        var x: [16]u8 = undefined;
        comptime var i: usize = 0;
        inline while (i < 16) : (i += 1) {
            x[i] = block_bytes[i] ^ bytes[i];
        }
        return x;
    }

    pub inline fn xor(a: Block, b: Block) Block {
        return .{ .repr = .{
            a.repr[0] ^ b.repr[0],
            a.repr[1] ^ b.repr[1],
            a.repr[2] ^ b.repr[2],
            a.repr[3] ^ b.repr[3],
        } };
    }

    pub fn linearTransform(block: Block) Block {
        var w0 = block.repr[0];
        var w1 = block.repr[1];
        var w2 = block.repr[2];
        var w3 = block.repr[3];
        w0 = rotl(u32, w0, 13);
        w2 = rotl(u32, w2, 3);
        w1 ^= w0 ^ w2;
        w3 ^= w2 ^ w0 << 3;
        w1 = rotl(u32, w1, 1);
        w3 = rotl(u32, w3, 7);
        w0 ^= w1 ^ w3;
        w2 ^= w3 ^ (w1 << 7);
        w0 = rotl(u32, w0, 5);
        w2 = rotl(u32, w2, 22);
        return Block{ .repr = BlockVec{ w0, w1, w2, w3 } };
    }

    pub fn inverseLinearTransform(block: Block) Block {
        var w0 = block.repr[0];
        var w1 = block.repr[1];
        var w2 = block.repr[2];
        var w3 = block.repr[3];
        w2 = rotr(u32, w2, 22);
        w0 = rotr(u32, w0, 5);
        w2 ^= w3 ^ (w1 << 7);
        w0 ^= w1 ^ w3;
        w3 = rotr(u32, w3, 7);
        w1 = rotr(u32, w1, 1);
        w3 ^= w2 ^ w0 << 3;
        w1 ^= w0 ^ w2;
        w2 = rotr(u32, w2, 3);
        w0 = rotr(u32, w0, 13);
        return Block{ .repr = BlockVec{ w0, w1, w2, w3 } };
    }
};

pub fn SerpentEncryptCtx(comptime Serpent: type) type {
    return struct {
        const Self = @This();
        pub const block = Serpent.block;
        pub const block_length = block.block_length;
        round_keys: RoundKeys,

        pub fn init(key: [Serpent.key_bits / 8]u8) Self {
            return .{ .round_keys = keySchedule(&key) };
        }

        pub fn encrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            var b: Block = Block.fromBytes(src);
            var i: usize = 0;
            while (i <= 30 * 4) {
                const round_key = Block{ .repr = ctx.round_keys[i .. i + 4][0..4].* };
                b = b.xor(round_key);
                b = Block{ .repr = sBox[(i / 4) % 8](b.repr) };
                b = b.linearTransform();
                i += 4;
            }
            b = b.xor(
                Block{ .repr = ctx.round_keys[4 * 31 .. 4 * 31 + 4][0..4].* },
            );
            b = Block{ .repr = sBox[7](b.repr) };
            b = b.xor(
                Block{ .repr = ctx.round_keys[4 * 32 .. 4 * 32 + 4][0..4].* },
            );
            dst.* = b.toBytes();
        }
    };
}

pub fn SerpentDecryptCtx(comptime Serpent: type) type {
    return struct {
        const Self = @This();
        pub const block = Serpent.block;
        pub const block_length = block.block_length;
        round_keys: RoundKeys,

        pub fn init(key: [Serpent.key_bits / 8]u8) Self {
            return .{ .round_keys = keySchedule(&key) };
        }

        pub fn decrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            var b: Block = Block.fromBytes(src);
            b = b.xor(
                Block{ .repr = ctx.round_keys[4 * 32 .. 4 * 32 + 4][0..4].* },
            );
            b = Block{ .repr = sBoxInv[7](b.repr) };
            b = b.xor(
                Block{ .repr = ctx.round_keys[4 * 31 .. 4 * 31 + 4][0..4].* },
            );
            var i: usize = 30 * 4;
            while (i >= 4) : (i -= 4) {
                b = b.inverseLinearTransform();
                b = Block{ .repr = sBoxInv[(i / 4) % 8](b.repr) };
                b = b.xor(
                    Block{ .repr = ctx.round_keys[i .. i + 4][0..4].* },
                );
            }
            b = b.inverseLinearTransform();
            b = Block{ .repr = sBoxInv[0](b.repr) };
            b = b.xor(
                Block{ .repr = ctx.round_keys[0..4][0..4].* },
            );
            dst.* = b.toBytes();
        }
    };
}

pub const Serpent128 = struct {
    pub const key_bits = 128;
    pub const rounds = 32;
    pub const block = Block;
};

pub const Serpent256 = struct {
    pub const key_bits = 256;
    pub const rounds = 32;
    pub const block = Block;
};

fn keySchedule(key: []const u8) RoundKeys {
    var res = blk: {
        var k = [_]u32{0} ** 32;
        var i: usize = 0;
        while (i <= key.len - 4) : (i += 4) {
            k[i / 4] = @as(u32, key[i]);
            k[i / 4] |= @as(u32, key[i + 1]) << 8;
            k[i / 4] |= @as(u32, key[i + 2]) << 16;
            k[i / 4] |= @as(u32, key[i + 3]) << 24;
        }
        if (i / 4 < 16) {
            k[i / 4] = 1;
        }

        var s = [_]u32{0} ** 132;
        i = 8;
        while (i < 16) : (i += 1) {
            const x: u32 = k[i - 8] ^ k[i - 5] ^ k[i - 3] ^ k[i - 1] ^ PHI ^ @as(u32, @intCast(i - 8));
            k[i] = rotl(u32, x, 11);
            s[i - 8] = k[i];
        }

        i = 8;
        while (i < 132) : (i += 1) {
            const x: u32 = s[i - 8] ^ s[i - 5] ^ s[i - 3] ^ s[i - 1] ^ PHI ^ @as(u32, @intCast(i));
            s[i] = rotl(u32, x, 11);
        }
        break :blk s;
    };
    var i: usize = 0;
    var j: usize = 3;
    while (i < 132) : (i += 4) {
        const x = sBox[j](res[i .. i + 4][0..4].*);
        res[i] = x[0];
        res[i + 1] = x[1];
        res[i + 2] = x[2];
        res[i + 3] = x[3];
        j = (j + 7) % 8;
    }
    return res;
}

// Nessie test vectors are standard,  the vectors on the floppy disks
// that were sent to the AES contest have the bytes in reverse order
// and this is called tnepres sometimes
// https://www.cs.technion.ac.il/~biham/Reports/Serpent/
test "128-bit keys" {
    const TestVector = struct { key: []const u8, plain: []const u8, cipher: []const u8 };

    const test_vectors = [_]TestVector{
        // Set 1, vector#  0:
        TestVector{
            .key = "80000000000000000000000000000000",
            .plain = "00000000000000000000000000000000",
            .cipher = "264E5481EFF42A4606ABDA06C0BFDA3D",
        },
        // Set 2, vector#  8:
        TestVector{
            .key = "00000000000000000000000000000000",
            .plain = "00800000000000000000000000000000",
            .cipher = "0DB0D17349C89E090C845CBEF963F225",
        },
        // Set 2, vector# 28:
        TestVector{
            .key = "00000000000000000000000000000000",
            .plain = "00000008000000000000000000000000",
            .cipher = "41ED367E96E013C651AF3FAEA764FE40",
        },
        // Set 3, vector# 46:
        TestVector{
            .key = "2E2E2E2E2E2E2E2E2E2E2E2E2E2E2E2E",
            .plain = "2E2E2E2E2E2E2E2E2E2E2E2E2E2E2E2E",
            .cipher = "E605C2EF7EFFDAC2316796EB7C15FAC7",
        },
        // Set 5, vector# 34:
        TestVector{
            .key = "00000000200000000000000000000000",
            .plain = "1B2A09A8CB69ECBAD8ACD593D27BCBDB",
            .cipher = "00000000000000000000000000000000",
        },
        // Set 7, vector# 35:
        TestVector{
            .key = "23232323232323232323232323232323",
            .plain = "0F66477951B1C27FBFFFA41E1B4E4764",
            .cipher = "23232323232323232323232323232323",
        },
        TestVector{
            .key = "000102030405060708090A0B0C0D0E0F",
            .plain = "33B3DC87EDDD9B0F6A1F407D14919365",
            .cipher = "00112233445566778899AABBCCDDEEFF",
        },
    };

    for (test_vectors) |vector| {
        var v_key: [16]u8 = undefined;
        _ = try hexToBytes(&v_key, vector.key);
        var v_plain: [16]u8 = undefined;
        _ = try hexToBytes(&v_plain, vector.plain);
        var v_cipher: [16]u8 = undefined;
        _ = try hexToBytes(&v_cipher, vector.cipher);

        const se = SerpentEncryptCtx(Serpent128).init(v_key);
        var cipher_res: [16]u8 = undefined;
        se.encrypt(&cipher_res, &v_plain);
        try testing.expectEqualSlices(u8, &v_cipher, &cipher_res);

        const sd = SerpentDecryptCtx(Serpent128).init(v_key);
        var plain_res: [16]u8 = undefined;
        sd.decrypt(&plain_res, &v_cipher);
        try testing.expectEqualSlices(u8, &v_plain, &plain_res);
    }
}

// TODO: add for 192-bits keys or probably create more generalized function

test "256-bit keys" {
    const TestVector = struct { key: []const u8, plain: []const u8, cipher: []const u8 };

    const test_vectors = [_]TestVector{
        // Set 7, vector#  15:
        TestVector{
            .key = "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            .plain = "752F945816DDB0E5ED15DA177EF5543F",
            .cipher = "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
        },
        // TODO: add more
    };

    for (test_vectors) |vector| {
        var v_key: [32]u8 = undefined;
        _ = try hexToBytes(&v_key, vector.key);
        var v_plain: [16]u8 = undefined;
        _ = try hexToBytes(&v_plain, vector.plain);
        var v_cipher: [16]u8 = undefined;
        _ = try hexToBytes(&v_cipher, vector.cipher);

        const se = SerpentEncryptCtx(Serpent256).init(v_key);
        var cipher_res: [16]u8 = undefined;
        se.encrypt(&cipher_res, &v_plain);
        try testing.expectEqualSlices(u8, &v_cipher, &cipher_res);

        const sd = SerpentDecryptCtx(Serpent256).init(v_key);
        var plain_res: [16]u8 = undefined;
        sd.decrypt(&plain_res, &v_cipher);
        try testing.expectEqualSlices(u8, &v_plain, &plain_res);
    }
}

comptime {
    testing.refAllDecls(@This());
}
