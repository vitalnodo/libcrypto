const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const sbox = block: {
    @setEvalBranchQuota(2048);
    const initial_sbox = &[_]u16{
        0x1823, 0xc6e8, 0x87b8, 0x014f, 0x36a6, 0xd2f5, 0x796f, 0x9152, 0x60bc,
        0x9b8e, 0xa30c, 0x7b35, 0x1de0, 0xd7c2, 0x2e4b, 0xfe57, 0x1577, 0x37e5,
        0x9ff0, 0x4ada, 0x58c9, 0x290a, 0xb1a0, 0x6b85, 0xbd5d, 0x10f4, 0xcb3e,
        0x0567, 0xe427, 0x418b, 0xa77d, 0x95d8, 0xfbee, 0x7c66, 0xdd17, 0x479e,
        0xca2d, 0xbf07, 0xad5a, 0x8333, 0x6302, 0xaa71, 0xc819, 0x49d9, 0xf2e3,
        0x5b88, 0x9a26, 0x32b0, 0xe90f, 0xd580, 0xbecd, 0x3448, 0xff7a, 0x905f,
        0x2068, 0x1aae, 0xb454, 0x9322, 0x64f1, 0x7312, 0x4008, 0xc3ec, 0xdba1,
        0x8d3d, 0x9700, 0xcf2b, 0x7682, 0xd61b, 0xb5af, 0x6a50, 0x45f3, 0x30ef,
        0x3f55, 0xa2ea, 0x65ba, 0x2fc0, 0xde1c, 0xfd4d, 0x9275, 0x068a, 0xb2e6,
        0x0e1f, 0x62d4, 0xa896, 0xf9c5, 0x2559, 0x8472, 0x394c, 0x5e78, 0x388c,
        0xd1a5, 0xe261, 0xb321, 0x9c1e, 0x43c7, 0xfc04, 0x5199, 0x6d0d, 0xfadf,
        0x7e24, 0x3bab, 0xce11, 0x8f4e, 0xb7eb, 0x3c81, 0x94f7, 0xb913, 0x2cd3,
        0xe76e, 0xc403, 0x5644, 0x7fa9, 0x2abb, 0xc153, 0xdc0b, 0x9d6c, 0x3174,
        0xf646, 0xac89, 0x14e1, 0x163a, 0x6909, 0x70b6, 0xd0ed, 0xcc42, 0x98a4,
        0x285c, 0xf886,
    };
    var result: [8][256]u64 = undefined;
    for (0..256) |x| {
        const c = initial_sbox[x / 2];
        const v1 = if ((x & 1) == 0) c >> 8 else c & 0xff;
        var v2 = v1 << 1;
        if (v2 >= 0x100) {
            v2 ^= 0x11d;
        }
        var v4 = v2 << 1;
        if (v4 >= 0x100) {
            v4 ^= 0x11d;
        }
        const v5 = v4 ^ v1;
        var v8 = v4 << 1;
        if (v8 >= 0x100) {
            v8 ^= 0x11d;
        }
        const v9 = v8 ^ v1;
        result[0][x] =
            (@as(u64, v1) << 56) |
            (@as(u64, v1) << 48) |
            (@as(u64, v4) << 40) |
            (@as(u64, v1) << 32) |
            (@as(u64, v8) << 24) |
            (@as(u64, v5) << 16) |
            (@as(u64, v2) << 8) | v9;
        for (1..8) |t| {
            result[t][x] = (result[t - 1][x] >> 8) | ((result[t - 1][x] << 56));
        }
    }
    break :block result;
};

fn generate_round_constants() [10]u64 {
    var table: [11]u64 = undefined;
    table[0] = 0;
    for (1..11) |r| {
        const i: usize = 8 * (r - 1);
        table[r] =
            (sbox[0][i + 0] & 0xff00000000000000) ^
            (sbox[1][i + 1] & 0x00ff000000000000) ^
            (sbox[2][i + 2] & 0x0000ff0000000000) ^
            (sbox[3][i + 3] & 0x000000ff00000000) ^
            (sbox[4][i + 4] & 0x00000000ff000000) ^
            (sbox[5][i + 5] & 0x0000000000ff0000) ^
            (sbox[6][i + 6] & 0x000000000000ff00) ^
            (sbox[7][i + 7] & 0x00000000000000ff);
    }
    return table[1..].*;
}

const ROUND_CONSTANTS = generate_round_constants();

inline fn blockFromBytes(bytes: *const [64]u8) [8]u64 {
    var block: [8]u64 = undefined;
    block[0] = mem.readInt(u64, bytes[0..8], .big);
    block[1] = mem.readInt(u64, bytes[8..16], .big);
    block[2] = mem.readInt(u64, bytes[16..24], .big);
    block[3] = mem.readInt(u64, bytes[24..32], .big);
    block[4] = mem.readInt(u64, bytes[32..40], .big);
    block[5] = mem.readInt(u64, bytes[40..48], .big);
    block[6] = mem.readInt(u64, bytes[48..56], .big);
    block[7] = mem.readInt(u64, bytes[56..64], .big);
    return block;
}

pub const Whirlpool = struct {
    const Self = @This();
    pub const block_length = 64;
    pub const digest_length = 64;
    pub const number_of_rounds = 10;
    pub const Options = struct {};

    s: [8]u64,
    buf: [64]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u256 = 0,
    pub fn init(options: Options) Self {
        _ = options;
        return .{ .s = undefined };
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Whirlpool.init(options);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Self, b: []const u8) void {
        var off: usize = 0;

        // Partial buffer exists from previous update. Copy into buffer then hash.
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

            d.round(d.buf[0..]);
            d.buf_len = 0;
        }

        // Full middle blocks.
        while (off + 64 <= b.len) : (off += 64) {
            d.round(b[off..][0..64]);
        }

        // Copy any remainder for next pass.
        const b_slice = b[off..];
        @memcpy(d.buf[d.buf_len..][0..b_slice.len], b_slice);
        d.buf_len += @as(u8, @intCast(b[off..].len));

        d.total_len += b.len;
    }

    fn round(d: *Self, b: *const [block_length]u8) void {
        var K: [2][8]u64 = undefined;
        var state: [2][8]u64 = undefined;
        const p_block = blockFromBytes(b);
        var m: u1 = 0;
        for (0..8) |i| {
            K[0][i] = d.s[i];
            state[0][i] = p_block[i] ^ d.s[i];
            d.s[i] = state[0][i];
        }

        for (0..number_of_rounds) |i| {
            for (0..8) |j| {
                K[m ^ 1][j] = whirlpoolOperation(K[m], j);
            }
            K[m ^ 1][0] ^= ROUND_CONSTANTS[i];

            for (0..8) |j| {
                state[m ^ 1][j] = whirlpoolOperation(
                    state[m],
                    j,
                ) ^ K[m ^ 1][j];
            }
            m = m ^ 1;
        }
        for (0..8) |i| {
            d.s[i] ^= state[0][i];
        }
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        // The buffer here will never be completely full.
        @memset(d.buf[d.buf_len..], 0);

        // Append padding bits.
        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;

        if (d.buf_len > 32) {
            d.round(d.buf[0..]);
            @memset(d.buf[0..], 0);
        }

        // Append message length.
        var i: usize = 1;
        var len = d.total_len >> 5;
        d.buf[63] = @as(u8, @intCast(d.total_len & 0x1f)) << 3;
        while (i < 32) : (i += 1) {
            d.buf[63 - i] = @as(u8, @intCast(len & 0xff));
            len >>= 8;
        }

        d.round(d.buf[0..]);

        for (d.s, 0..) |s, j| {
            mem.writeInt(u64, out[8 * j ..][0..8], s, .big);
        }
    }

    inline fn whirlpoolOperation(src: [8]u64, shift: usize) u64 {
        return sbox[0][(src[shift & 7] >> 56)] ^
            sbox[1][(src[(shift + 7) & 7] >> 48) & 0xff] ^
            sbox[2][(src[(shift + 6) & 7] >> 40) & 0xff] ^
            sbox[3][(src[(shift + 5) & 7] >> 32) & 0xff] ^
            sbox[4][(src[(shift + 4) & 7] >> 24) & 0xff] ^
            sbox[5][(src[(shift + 3) & 7] >> 16) & 0xff] ^
            sbox[6][(src[(shift + 2) & 7] >> 8) & 0xff] ^
            sbox[7][(src[(shift + 1) & 7]) & 0xff];
    }
};

test {
    const input = &[_][]const u8{
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "1234567890" ** 8,
        "abcdbcdecdefdefgefghfghighijhijk",
        "a" ** 1000000,
    };
    const output = &[_][]const u8{
        "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3",
        "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A",
        "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5",
        "378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B8421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E",
        "F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B08BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B",
        "DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467",
        "466EF18BABB0154D25B9D38A6414F5C08784372BCCB204D6549C4AFADB6014294D5BD8DF2A6C44E538CD047B2681A51A2C60481E88C5A20B2C2A80CF3A9A083B",
        "2A987EA40F917061F5D6F0A0E4644F488A7A5A52DEEE656207C562F988E95C6916BDC8031BC5BE1B7B947639FE050B56939BAAA0ADFF9AE6745B7B181C3BE3FD",
        "0C99005BEB57EFF50A7CF005560DDF5D29057FD86B20BFD62DECA0F1CCEA4AF51FC15490EDDC47AF32BB2B66C34FF9AD8C6008AD677F77126953B226E4ED8B01",
    };
    for (input, output, 0..) |_, _, i| {
        var expected: [Whirlpool.digest_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, output[i]);
        var actual: [Whirlpool.digest_length]u8 = undefined;
        Whirlpool.hash(input[i], &actual, .{});
        try testing.expectEqualSlices(u8, &expected, &actual);
    }
}
