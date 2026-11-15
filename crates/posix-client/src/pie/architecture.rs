//! Decode CPU-specific ELF relocation numbers into shared loader operations.
//! These operations never escape as relocation numbers in the emitted ELF.
use super::Error;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum TlsValue {
    Module = 16,
    Offset = 17,
    ThreadOffset = 18,
    Descriptor = 36,
}

pub(super) enum Relocation {
    None,
    Relative,
    Indirect,
    Size(u8),
    Copy,
    Symbol { addend: bool },
    Tls(TlsValue),
}

pub(super) fn decode(number: u32) -> Result<Relocation, Error> {
    use Relocation::*;
    #[cfg(target_arch = "x86_64")]
    let operation = match number {
        0 => None,
        1 => Symbol { addend: true },
        5 => Copy,
        6 | 7 => Symbol { addend: false },
        8 => Relative,
        16 => Tls(TlsValue::Module),
        17 => Tls(TlsValue::Offset),
        18 => Tls(TlsValue::ThreadOffset),
        32 => Size(4),
        33 => Size(8),
        36 => Tls(TlsValue::Descriptor),
        37 => Indirect,
        _ => return Err(Error::Unsupported),
    };
    #[cfg(target_arch = "aarch64")]
    let operation = match number {
        0 => None,
        // AArch64 ABS64/GLOB_DAT/JUMP_SLOT all compute S + A. x86's latter
        // two compute S alone, so copying its numeric decoder is incorrect.
        257 | 1025 | 1026 => Symbol { addend: true },
        1024 => Copy,
        1027 => Relative,
        1028 => Tls(TlsValue::Module),
        1029 => Tls(TlsValue::Offset),
        1030 => Tls(TlsValue::ThreadOffset),
        1031 => Tls(TlsValue::Descriptor),
        1032 => Indirect,
        // Instruction, authenticated and narrow relocations need their own
        // validated writers; never treat an unknown record as an 8-byte write.
        _ => return Err(Error::Unsupported),
    };
    Ok(operation)
}
