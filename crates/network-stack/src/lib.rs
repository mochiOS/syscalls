#![no_std]

extern crate alloc;

mod arp;
mod checksum;
mod dhcp;
mod ethernet;
mod icmp;
mod ipv4;
mod route;
mod udp;

pub use arp::*;
pub use checksum::*;
pub use dhcp::*;
pub use ethernet::*;
pub use icmp::*;
pub use ipv4::*;
pub use route::*;
pub use udp::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    Truncated,
    InvalidHeader,
    InvalidLength,
    InvalidChecksum,
    Unsupported,
    Mismatch,
    Capacity,
}
