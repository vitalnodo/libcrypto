// https://www.ii.uib.no/~osvik/pub/aes3.pdf

// zig fmt: off
fn sbox0(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r3 ^= r0; r4 = r1;
    r1 &= r3; r4 ^= r2;
    r1 ^= r0; r0 |= r3;
    r0 ^= r4; r4 ^= r3;
    r3 ^= r2; r2 |= r1;
    r2 ^= r4; r4 = ~r4;
    r4 |= r1; r1 ^= r3;
    r1 ^= r4; r3 |= r0;
    r1 ^= r3; r4 ^= r3;
    return [4]u32{r1, r4, r2, r0};
}

fn sbox1(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r0 = ~r0; r2 = ~r2;
    r4 =  r0; r0 &= r1; 
    r2 ^= r0; r0 |= r3; 
    r3 ^= r2; r1 ^= r0; 
    r0 ^= r4; r4 |= r1; 
    r1 ^= r3; r2 |= r0; 
    r2 &= r4; r0 ^= r1;  
    r1 &= r2; 
    r1 ^= r0; r0 &= r2;
    r0 ^= r4; 
    return [4]u32{r2, r0, r3, r1};
} 

fn sbox2(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r4 = r0 ; r0 &= r2;
    r0 ^= r3; r2 ^= r1;
    r2 ^= r0; r3 |= r4;
    r3 ^= r1; r4 ^= r2;
    r1 =  r3; r3 |= r4;
    r3 ^= r0; r0 &= r1;
    r4 ^= r0; r1 ^= r3;
    r1 ^= r4; r4 = ~r4;
    return [4]u32{r2, r3, r1, r4};
}

fn sbox3(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r4 = r0; r0 |=  r3;
    r3 ^= r1; r1 &= r4; 
    r4 ^= r2; r2 ^= r3; 
    r3 &= r0; r4 |= r1; 
    r3 ^= r4; r0 ^= r1; 
    r4 &= r0; r1 ^= r3; 
    r4 ^= r2; r1 |= r0;
    r1 ^= r2; r0 ^= r3;
    r2 = r1; r1 |= r3; 
    r1 ^= r0;
    return [4]u32{r1, r2, r3, r4};
}

fn sbox4(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r1 ^= r3; r3 = ~r3; 
    r2 ^= r3; r3 ^= r0; 
    r4 = r1 ; r1 &= r3; 
    r1 ^= r2; r4 ^= r3; 
    r0 ^= r4; r2 &= r4;
    r2 ^= r0; r0 &= r1; 
    r3 ^= r0; r4 |= r1; 
    r4 ^= r0; r0 |= r3; 
    r0 ^= r2; r2 &= r3;
    r0 = ~r0; r4 ^= r2;

    return [4]u32{r1, r4, r0, r3};
} 

fn sbox5(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r0 ^= r1; r1 ^= r3;
    r3 = ~r3; r4 =  r1; 
    r1 &= r0; r2 ^= r3; 
    r1 ^= r2; r2 |= r4; 
    r4 ^= r3; r3 &= r1; 
    r3 ^= r0; r4 ^= r1; 
    r4 ^= r2; r2 ^= r0; 
    r0 &= r3; r2 = ~r2; 
    r0 ^= r4; r4 |= r3;
    r2 ^= r4;
    return [4]u32{r1, r3, r0, r2};
} 

fn sbox6(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r2 = ~r2; r4 =  r3;
    r3 &= r0; r0 ^= r4; 
    r3 ^= r2; r2 |= r4;
    r1 ^= r3; r2 ^= r0; 
    r0 |= r1; r2 ^= r1; 
    r4 ^= r0; r0 |= r3; 
    r0 ^= r2; r4 ^= r3; 
    r4 ^= r0; r3 = ~r3; 
    r2 &= r4;
    r2 ^= r3;
    return [4]u32{r0, r1, r4, r2};
}

fn sbox7(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r4 =  r1; r1 |= r2;
    r1 ^= r3; r4 ^= r2; 
    r2 ^= r1; r3 |= r4;
    r3 &= r0; r4 ^= r2; 
    r3 ^= r1; r1 |= r4; 
    r1 ^= r0; r0 |= r4; 
    r0 ^= r2; r1 ^= r4; 
    r2 ^= r1; r1 &= r0; 
    r1 ^= r4; r2 = ~r2;
    r2 |= r0; 
    r4 ^= r2;
    return [4]u32{r4, r3, r1, r0};
}

fn sbox0Inv(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r2 =~ r2; r4 =  r1;
    r1 |= r0; r4 = ~r4;
    r1 ^= r2; r2 |= r4;
    r1 ^= r3; r0 ^= r4;
    r2 ^= r0; r0 &= r3;
    r4 ^= r0; r0 |= r1;
    r0 ^= r2; r3 ^= r4;
    r2 ^= r1; r3 ^= r0;
    r3 ^= r1;
    r2 &= r3;
    r4 ^= r2;
    return [4]u32{r0, r4, r1, r3};
}

fn sbox1Inv(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r4 =  r1; r1 ^= r3;
    r3 &= r1; r4 ^= r2;
    r3 ^= r0; r0 |= r1;
    r2 ^= r3; r0 ^= r4;
    r0 |= r2; r1 ^= r3;
    r0 ^= r1; r1 |= r3;
    r1 ^= r0; r4 = ~r4;
    r4 ^= r1; r1 |= r0;
    r1 ^= r0;
    r1 |= r4;
    r3 ^= r1;
    return [4]u32{r4, r0, r3, r2};
}

fn sbox2Inv(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r2 ^= r3; r3 ^= r0;
    r4 =  r3; r3 &= r2;
    r3 ^= r1; r1 |= r2;
    r1 ^= r4; r4 &= r3;
    r2 ^= r3; r4 &= r0;
    r4 ^= r2; r2 &= r1;
    r2 |= r0; r3 = ~r3;
    r2 ^= r3; r0 ^= r3;
    r0 &= r1; r3 ^= r4;
    r3 ^= r0;
    return [4]u32{r1, r4, r2, r3};
}

fn sbox3Inv(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r4 =  r2; r2 ^= r1;
    r0 ^= r2; r4 &= r2;
    r4 ^= r0; r0 &= r1;
    r1 ^= r3; r3 |= r4;
    r2 ^= r3; r0 ^= r3;
    r1 ^= r4; r3 &= r2;
    r3 ^= r1; r1 ^= r0;
    r1 |= r2; r0 ^= r3;
    r1 ^= r4;
    r0 ^= r1;
    return [4]u32{r2, r1, r3, r0};
}

fn sbox4Inv(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r4 =  r2; r2 &= r3;
    r2 ^= r1; r1 |= r3;
    r1 &= r0; r4 ^= r2;
    r4 ^= r1; r1 &= r2;
    r0 =~ r0; r3 ^= r4;
    r1 ^= r3; r3 &= r0;
    r3 ^= r2; r0 ^= r1;
    r2 &= r0; r3 ^= r0;
    r2 ^= r4;
    r2 |= r3; r3 ^= r0;
    r2 ^= r1;
    return [4]u32{r0, r3, r2, r4};
}

fn sbox5Inv(input: [4]u32) [4]u32 {
    const r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r1 = ~r1; r4 =  r3;
    r2 ^= r1; r3 |= r0;
    r3 ^= r2; r2 |= r1;
    r2 &= r0; r4 ^= r3;
    r2 ^= r4; r4 |= r0;
    r4 ^= r1; r1 &= r2;
    r1 ^= r3; r4 ^= r2;
    r3 &= r4; r4 ^= r1;
    r3 ^= r4; r4 = ~r4;
    r3 ^= r0;
    return [4]u32{r1, r4, r3, r2};
}

fn sbox6Inv(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r0 ^= r2; r4 =  r2;
    r2 &= r0; r4 ^= r3;
    r2 = ~r2; r3 ^= r1;
    r2 ^= r3; r4 |= r0;
    r0 ^= r2; r3 ^= r4;
    r4 ^= r1; r1 &= r3;
    r1 ^= r0; r0 ^= r3;
    r0 |= r2; r3 ^= r1;
    r4 ^= r0;
    return [4]u32{r1, r2, r4, r3};
}

fn sbox7Inv(input: [4]u32) [4]u32 {
    var r0 = input[0];
    var r1 = input[1];
    var r2 = input[2];
    var r3 = input[3];
    var r4: u32 = undefined;
    r4 =  r2; r2 ^= r0;
    r0 &= r3; r4 |= r3;
    r2 = ~r2; r3 ^= r1;
    r1 |= r0; r0 ^= r2;
    r2 &= r4; r3 &= r4;
    r1 ^= r2; r2 ^= r0;
    r0 |= r2; r4 ^= r1;
    r0 ^= r3; r3 ^= r4;
    r4 |= r0; r3 ^= r2;
    r4 ^= r2;
    return [4]u32{r3, r0, r1, r4};
}
// zig fmt: on

pub const sBox = [_]*const fn ([4]u32) [4]u32{
    sbox0, sbox1, sbox2, sbox3,
    sbox4, sbox5, sbox6, sbox7,
};

pub const sBoxInv = [_]*const fn ([4]u32) [4]u32{
    sbox0Inv, sbox1Inv, sbox2Inv, sbox3Inv,
    sbox4Inv, sbox5Inv, sbox6Inv, sbox7Inv,
};
