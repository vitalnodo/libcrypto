# XTS mode for Zig

Currently the blockcipher must be AES (that has 128 bit block) with a key length of either 128 or 256 bits.

## XTS flow chart
[![Xilinx Inc XTS flow chart](https://xilinx.github.io/Vitis_Libraries/security/2020.1/_images/XTS_working_mode.png)](https://xilinx.github.io/Vitis_Libraries/security/2020.1/guide_L1/internals/xts.html)

## links
[1619-2007 - IEEE Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices](https://ieeexplore.ieee.org/document/4493450)

[Vitis Security Library XTS Mode](https://xilinx.github.io/Vitis_Libraries/security/2020.1/guide_L1/internals/xts.html)

[Evaluation of Some Blockcipher Modes of Operation](https://web.cs.ucdavis.edu/~rogaway/papers/modes.pdf)

[You Don't Want XTS](https://sockpuppet.org/blog/2014/04/30/you-dont-want-xts/)

[Public Comments on the XTS-AES Mode](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/xts/collected_xts_comments.pdf)

[Cryptographic Algorithm Validation Program XTS-AES Test Vectors (SP 800-38E)](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#XTS)

[XTS and 256-bit data blocks](https://crypto.stackexchange.com/questions/35490/xts-and-256-bit-data-blocks)