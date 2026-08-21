//! Compile-time string obfuscation via XOR.
//!
//! The `s!("literal")` macro XORs every byte of a string literal with a
//! per-byte key derived from its position, producing an opaque `[u8; N]`
//! constant in .rodata.  At runtime `s!()` returns a `String` decoded on the
//! stack — no cleartext ever resides in the binary image.
//!
//! Key derivation: key[i] = K0 ^ rol8(i*M + i*i, 3)
//! K0=0xA7, M=0x6D — arbitrary primes, not secret, just anti-grep.

#[macro_export]
macro_rules! s {
    ($lit:literal) => {{
        const BYTES: &[u8] = $lit.as_bytes();
        const LEN:   usize = BYTES.len();
        const fn key(i: usize) -> u8 {
            let v = 0xA7u8
                ^ (i as u8).wrapping_mul(0x6D).wrapping_add((i as u8).wrapping_mul(i as u8));
            (v << 3) | (v >> 5)
        }
        const fn enc(i: usize) -> u8 { BYTES[i] ^ key(i) }
        // Encode at compile time into a const array.
        const ENC: [u8; LEN] = {
            let mut a = [0u8; LEN];
            let mut i = 0;
            while i < LEN { a[i] = enc(i); i += 1; }
            a
        };
        // Decode at runtime on the stack.
        let mut buf = [0u8; LEN];
        let mut i = 0;
        while i < LEN { buf[i] = ENC[i] ^ $crate::obfs::key_rt(i); i += 1; }
        // SAFETY: we XOR the same key back — result is the original valid UTF-8.
        unsafe { String::from_utf8_unchecked(buf.to_vec()) }
    }};
}

/// Runtime key — identical formula to the const `key()` above.
#[inline(always)]
pub fn key_rt(i: usize) -> u8 {
    let v = 0xA7u8
        ^ (i as u8).wrapping_mul(0x6D).wrapping_add((i as u8).wrapping_mul(i as u8));
    (v << 3) | (v >> 5)
}

#[macro_export]
macro_rules! sb {
    ($lit:literal) => {{
        let mut _s = $crate::s!($lit);
        _s.push('\0');
        _s.into_bytes()
    }};
}
