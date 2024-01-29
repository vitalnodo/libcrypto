const std = @import("std");
const testing = std.testing;

const twofish_main = @import("ciphers/twofish/main.zig");
pub const ciphers = struct {
    pub const twofish = struct {
        pub const Twofish256 = twofish_main.Twofish256;
        pub const TwofishEncryptCtx = twofish_main.TwofishEncryptCtx;
        pub const TwofishDecryptCtx = twofish_main.TwofishDecryptCtx;
    };
};

test {
    _ = ciphers.twofish.Twofish256;
    _ = ciphers.twofish.TwofishEncryptCtx;
    _ = ciphers.twofish.TwofishDecryptCtx;
}

test {
    std.testing.refAllDecls(@This());
}
