//! ELF Signature v1 codec shared by userspace tools and verification consumers.
//! Operates only on supplied bytes; trust policy and file/key access are external.
#![no_std]

extern crate alloc;
mod codec;
pub use codec::*;
