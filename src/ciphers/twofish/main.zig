const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const BlockVec = [4]u32;
const mem = std.mem;
const utils = @import("utils.zig");
const Q0 = utils.Q0;
const Q1 = utils.Q1;

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

    pub inline fn xor(a: Block, b: Block) Block {
        return .{ .repr = .{
            a.repr[0] ^ b.repr[0],
            a.repr[1] ^ b.repr[1],
            a.repr[2] ^ b.repr[2],
            a.repr[3] ^ b.repr[3],
        } };
    }
};

pub fn TwofishEncryptCtx(comptime Twofish: type) type {
    return struct {
        const Self = @This();
        pub const block = Twofish.block;
        pub const block_length = block.block_length;
        K: [40]u32 = undefined,
        S: [4]u32 = undefined,

        pub fn init(key: []const u8) Self {
            var self = Self{};
            keySchedule(Twofish.key_bits, key, &self.K, &self.S);
            return self;
        }

        pub fn encrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            var b: Block = Block.fromBytes(src);
            const R = &b.repr;
            b = b.xor(Block{ .repr = ctx.K[0..4].* });
            for (0..utils.rounds - 1) |r| {
                const F = F_function(
                    R[0],
                    R[1],
                    r,
                    ctx.K,
                    ctx.S,
                );
                var R_old: [4]u32 = undefined;
                @memcpy(&R_old, R);
                R[0] = std.math.rotr(u32, R_old[2] ^ F[0], 1);
                R[1] = std.math.rotl(u32, R_old[3], 1) ^ F[1];
                R[2] = R_old[0];
                R[3] = R_old[1];
            }
            const F = F_function(
                R[0],
                R[1],
                15,
                ctx.K,
                ctx.S,
            );
            R[2] = std.math.rotr(u32, R[2] ^ F[0], 1);
            R[3] = std.math.rotl(u32, R[3], 1) ^ F[1];
            b = b.xor(Block{ .repr = ctx.K[4..8].* });
            dst.* = b.toBytes();
        }
    };
}

pub fn TwofishDecryptCtx(comptime Twofish: type) type {
    return struct {
        const Self = @This();
        pub const block = Twofish.block;
        pub const block_length = block.block_length;
        K: [40]u32 = undefined,
        S: [4]u32 = undefined,

        pub fn init(key: []const u8) Self {
            var self = Self{};
            keySchedule(Twofish.key_bits, key, &self.K, &self.S);
            return self;
        }

        pub fn decrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            var b: Block = Block.fromBytes(src);
            const R = &b.repr;
            b = b.xor(Block{ .repr = ctx.K[4..8].* });
            for (0..utils.rounds - 1) |r| {
                const F = F_function(
                    R[0],
                    R[1],
                    15 - r,
                    ctx.K,
                    ctx.S,
                );
                var R_old: [4]u32 = undefined;
                @memcpy(&R_old, R);
                R[2] = std.math.rotl(u32, R_old[2], 1) ^ F[0];
                R[3] = std.math.rotr(u32, R_old[3] ^ F[1], 1);
                R[0] = R[2];
                R[1] = R[3];
                R[2] = R_old[0];
                R[3] = R_old[1];
            }
            const F = F_function(
                R[0],
                R[1],
                0,
                ctx.K,
                ctx.S,
            );
            R[2] = std.math.rotl(u32, R[2], 1) ^ F[0];
            R[3] = std.math.rotr(u32, R[3] ^ F[1], 1);
            b = b.xor(Block{ .repr = ctx.K[0..4].* });
            dst.* = b.toBytes();
        }
    };
}

fn keySchedule(comptime N: u10, key: []const u8, K: *[40]u32, S: *[4]u32) void {
    assert(N == 128 or N == 192 or N == 256);
    var M: [N / 8]u8 = undefined;
    @memset(&M, 0);
    @memcpy(M[0..key.len], key);
    const k = N / 64;
    var Mi: [2 * k]u32 = undefined;
    for (0..Mi.len) |i| {
        var tmp: u32 = 0;
        for (0..4) |j| {
            tmp += M[4 * i + j] * std.math.pow(u32, 2, @intCast(8 * j));
        }
        Mi[i] = tmp;
    }
    var Me: [k]u32, var Mo: [k]u32 = .{ undefined, undefined };
    var c1: usize, var c2: usize = .{ 0, 1 };
    for (0..k) |n| {
        Me[n] = Mi[c1];
        Mo[n] = Mi[c2];
        const m = M[8 * n .. 8 * n + 8][0..8].*;
        var m_T: [8][1]u8 = undefined;
        for (0..m.len) |i| {
            m_T[i][0] = m[i];
        }
        const tmp = utils.matmult(
            4,
            8,
            1,
            utils.RS.*,
            m_T,
            utils.POLYNOM_W,
        );
        const tmp_T = [4]u8{ tmp[0][0], tmp[1][0], tmp[2][0], tmp[3][0] };
        S[n] = std.mem.readInt(u32, &tmp_T, .little);
        c1 += 2;
        c2 += 2;
    }
    std.mem.reverse(u32, S);

    const rho = utils.rho;
    var i: usize = 0;
    while (i < 20) {
        const a: u32 = @intCast(2 * i * rho);
        const A = h(k, a, Me);
        const b: u32 = @intCast((2 * i + 1) * rho);
        const B = std.math.rotl(u32, h(k, b, Mo), 8);
        K[2 * i] = A +% B;
        K[2 * i + 1] = std.math.rotl(u32, A +% (2 *% B), 9);
        i += 1;
    }
}

fn h(comptime k: usize, X: u32, L: [k]u32) u32 {
    var l: [k][4]u8 = undefined;
    for (0..k) |l_i| {
        std.mem.writeInt(u32, &l[l_i], L[l_i], .little);
    }

    var x: [k]u8 = undefined;
    std.mem.writeInt(u32, &x, X, .little);

    var y: [k + 1][4]u8 = undefined;
    @memcpy(y[0..k], l[0..k]);
    @memcpy(&y[k], &x);

    if (k == 4) {
        y[3][0] = Q1[y[4][0]] ^ l[3][0];
        y[3][1] = Q0[y[4][1]] ^ l[3][1];
        y[3][2] = Q0[y[4][2]] ^ l[3][2];
        y[3][3] = Q1[y[4][3]] ^ l[3][3];
    }
    if (k >= 3) {
        y[2][0] = Q1[y[3][0]] ^ l[2][0];
        y[2][1] = Q1[y[3][1]] ^ l[2][1];
        y[2][2] = Q0[y[3][2]] ^ l[2][2];
        y[2][3] = Q0[y[3][3]] ^ l[2][3];
    }

    var y_ = [4]u8{ 0, 0, 0, 0 };
    y_[0] = Q1[Q0[Q0[y[2][0]] ^ l[1][0]] ^ l[0][0]];
    y_[1] = Q0[Q0[Q1[y[2][1]] ^ l[1][1]] ^ l[0][1]];
    y_[2] = Q1[Q1[Q0[y[2][2]] ^ l[1][2]] ^ l[0][2]];
    y_[3] = Q0[Q1[Q1[y[2][3]] ^ l[1][3]] ^ l[0][3]];
    const y_T = [4][1]u8{
        [1]u8{y_[0]},
        [1]u8{y_[1]},
        [1]u8{y_[2]},
        [1]u8{y_[3]},
    };

    const C = utils.matmult(
        4,
        4,
        1,
        utils.MDS,
        y_T,
        utils.POLYNOM_V,
    );
    const C_t = [4]u8{ C[0][0], C[1][0], C[2][0], C[3][0] };
    const Z = std.mem.readInt(u32, &C_t, .little);
    return Z;
}

pub fn F_function(R0: u32, R1: u32, r: usize, K: [40]u32, S: [4]u32) [2]u32 {
    const k = 4;
    const T0 = h(k, R0, S); // g
    const T1 = h(k, std.math.rotl(u32, R1, 8), S);
    const F0 = T0 +% T1 +% K[2 * r + 8];
    const F1 = T0 +% 2 *% T1 +% K[2 * r + 9];
    return .{ F0, F1 };
}

pub const Twofish256 = struct {
    pub const key_bits = 256;
    pub const rounds = 16;
    pub const block = Block;
};

test {
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "248A7F3528B168ACFDD1386E3F51E30C2E2158BC3E5FC714C1EEECA0EA696D48");
    var msg: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg, "431058F4DBC7F734DA4F02F04CC4F459");
    const se = TwofishEncryptCtx(Twofish256).init(&key);
    var encrypted: [16]u8 = undefined;
    se.encrypt(&encrypted, msg[0..]);
    var decrypted: [16]u8 = undefined;
    const sd = TwofishDecryptCtx(Twofish256).init(&key);
    sd.decrypt(&decrypted, encrypted[0..]);
    try testing.expectEqualSlices(u8, &msg, &decrypted);
}
