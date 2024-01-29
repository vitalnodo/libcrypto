const std = @import("std");
const testing = std.testing;

const twofish_main = @import("ciphers/twofish/main.zig");
const serpent_main = @import("ciphers/serpent/main.zig");
pub const ciphers = struct {
    pub const twofish = struct {
        pub const Twofish256 = twofish_main.Twofish256;
        pub const TwofishEncryptCtx = twofish_main.TwofishEncryptCtx;
        pub const TwofishDecryptCtx = twofish_main.TwofishDecryptCtx;
    };
    pub const serpent = struct {
        pub const Serpent128 = serpent_main.Serpent128;
        pub const Serpent256 = serpent_main.Serpent256;
        pub const SerpentEncryptCtx = serpent_main.SerpentEncryptCtx;
        pub const SerpentDecryptCtx = serpent_main.SerpentDecryptCtx;
    };
};

test {
    _ = ciphers.twofish.Twofish256;
    _ = ciphers.twofish.TwofishEncryptCtx;
    _ = ciphers.twofish.TwofishDecryptCtx;

    _ = ciphers.serpent.Serpent128;
    _ = ciphers.serpent.Serpent256;
    _ = ciphers.serpent.SerpentEncryptCtx;
    _ = ciphers.serpent.SerpentDecryptCtx;
}

test {
    std.testing.refAllDecls(@This());
}
