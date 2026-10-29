//! Process-local C resolver storage. Application pointers are copied; only
//! unpublished, owned allocations become Rust objects. The outer caller must
//! publish this List in an io_resources scope before acquiring resources.
use super::*;
use mochios_posix_client::{
    internet::{AF_INET, AF_INET6, Address},
    netdb::{self as policy, Entry, Error, Hints, ScopedAddress},
};

/// Linux-compatible application layout. This structure is never an IPC wire
/// object: its pointers refer only to the caller's own address space.
#[repr(C)]
pub(super) struct AddrInfo {
    pub flags: c_int,
    pub family: c_int,
    pub socktype: c_int,
    pub protocol: c_int,
    pub address_length: u32,
    pub address: *mut c_void,
    pub canonical: *mut c_char,
    pub next: *mut AddrInfo,
}
const _: () = {
    assert!(core::mem::size_of::<AddrInfo>() == 48);
    assert!(core::mem::align_of::<AddrInfo>() == 8);
    assert!(core::mem::offset_of!(AddrInfo, address_length) == 16);
    assert!(core::mem::offset_of!(AddrInfo, address) == 24);
    assert!(core::mem::offset_of!(AddrInfo, canonical) == 32);
    assert!(core::mem::offset_of!(AddrInfo, next) == 40);
};
fn system(errno: c_int) -> Error {
    Error::System(mochios_posix_client::newlib_errno::to_status(errno))
}
fn integer(bytes: &[u8], offset: usize) -> c_int {
    c_int::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn word(bytes: &[u8], offset: usize) -> usize {
    usize::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub(super) fn hints(source: *const AddrInfo) -> Result<Hints, Error> {
    if source.is_null() {
        return Ok(Hints::default());
    }
    let mut bytes = [0; 48];
    user_copy::read(source.cast(), &mut bytes).map_err(system)?;
    // Padding is indeterminate C storage, not a reserved protocol field.
    if integer(&bytes, 16) != 0
        || word(&bytes, 24) != 0
        || word(&bytes, 32) != 0
        || word(&bytes, 40) != 0
    {
        return Err(Error::BadFlags);
    }
    Ok(Hints {
        flags: integer(&bytes, 0),
        family: integer(&bytes, 4),
        socktype: integer(&bytes, 8),
        protocol: integer(&bytes, 12),
    })
}
pub(super) struct Inputs {
    node: [u8; policy::NI_MAXHOST - 1],
    service: [u8; policy::NI_MAXHOST - 1],
    node_length: Option<usize>,
    service_length: Option<usize>,
    pub hints: Hints,
}
impl Inputs {
    pub const fn new() -> Self {
        Self {
            node: [0; policy::NI_MAXHOST - 1],
            service: [0; policy::NI_MAXHOST - 1],
            node_length: None,
            service_length: None,
            hints: Hints {
                flags: 0,
                family: 0,
                socktype: 0,
                protocol: 0,
            },
        }
    }
    /// Initialize the result to null before allocation, lookup or publication.
    /// The snapshots remain owned even if a returning handler changes the C inputs.
    pub fn capture(
        &mut self,
        node: *const c_char,
        service: *const c_char,
        source: *const AddrInfo,
        result: *mut *mut AddrInfo,
    ) -> Result<(), Error> {
        user_copy::write(result.cast(), &0usize.to_ne_bytes()).map_err(system)?;
        self.node_length = None;
        self.service_length = None;
        self.hints = hints(source)?;
        if !node.is_null() {
            self.node_length = Some(
                user_copy::capture_text(node, &mut self.node, ENAMETOOLONG).map_err(|e| {
                    if e == ENAMETOOLONG {
                        Error::NoName
                    } else {
                        system(e)
                    }
                })?,
            );
        }
        if !service.is_null() {
            self.service_length = Some(
                user_copy::capture_text(service, &mut self.service, ENAMETOOLONG).map_err(|e| {
                    if e == ENAMETOOLONG {
                        Error::Service
                    } else {
                        system(e)
                    }
                })?,
            );
        }
        Ok(())
    }
    pub fn node(&self) -> Option<&[u8]> {
        self.node_length.map(|n| &self.node[..n])
    }
    pub fn service(&self) -> Option<&[u8]> {
        self.service_length.map(|n| &self.service[..n])
    }
}

pub(super) fn sockaddr(source: *const c_void, length: u32) -> Result<(ScopedAddress, u16), Error> {
    if length < 2 {
        return Err(Error::Family);
    }
    let mut prefix = [0; 2];
    user_copy::read(source.cast(), &mut prefix).map_err(system)?;
    let family = i32::from(u16::from_ne_bytes(prefix));
    let needed = match family {
        AF_INET => 16,
        AF_INET6 => 28,
        _ => return Err(Error::Family),
    };
    if (length as usize) < needed {
        return Err(Error::Family);
    }
    let mut bytes = [0; 28];
    user_copy::read(source.cast(), &mut bytes[..needed]).map_err(system)?;
    if bytes[..2] != prefix {
        return Err(Error::Family);
    }
    let port = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
    let address = match family {
        AF_INET => Address::V4(bytes[4..8].try_into().unwrap()).into(),
        AF_INET6 => ScopedAddress {
            address: Address::V6(bytes[8..24].try_into().unwrap()),
            scope: u32::from_ne_bytes(bytes[24..28].try_into().unwrap()),
        },
        _ => return Err(Error::Family),
    };
    Ok((address, port))
}

/// Each allocation begins with one addrinfo and contains that node's sockaddr
/// and optional canonical name. Every valid sublist can be released on its own.
pub(super) struct List {
    head: *mut AddrInfo,
    tail: *mut AddrInfo,
}
impl List {
    pub const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        }
    }
    pub fn append(&mut self, entry: Entry<'_>) -> Result<(), Error> {
        let canonical = entry.canonical;
        if canonical.is_some_and(|name| {
            name.is_empty() || name.contains(&0) || name.len() >= policy::NI_MAXHOST
        }) {
            return Err(Error::Fail);
        }
        if entry.address.family() != AF_INET6 && entry.address.scope != 0 {
            return Err(Error::Family);
        }
        let length = 76usize
            .checked_add(canonical.map_or(0, |n| n.len() + 1))
            .ok_or(Error::Memory)?;
        // Append is atomic with respect to asynchronous callbacks: ownership is
        // linked into the registered List before native delivery reopens.
        let _native = defer_native_delivery();
        let allocation = unsafe { malloc(length) }.cast::<u8>();
        if allocation.is_null() {
            return Err(Error::Memory);
        }
        // SAFETY: malloc returned a unique, sufficiently aligned allocation.
        // It is private until publish succeeds; initialize padding as well.
        unsafe { ptr::write_bytes(allocation, 0, length) };
        let bytes = unsafe { core::slice::from_raw_parts_mut(allocation, length) };
        for (offset, value) in [
            (0, 0),
            (4, entry.address.family()),
            (8, entry.transport.socktype()),
            (12, entry.transport.protocol()),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        let address_length: u32 = if entry.address.family() == AF_INET {
            16
        } else {
            28
        };
        bytes[16..20].copy_from_slice(&address_length.to_ne_bytes());
        bytes[24..32].copy_from_slice(&(allocation as usize + 48).to_ne_bytes());
        bytes[48..50].copy_from_slice(&(entry.address.family() as u16).to_ne_bytes());
        bytes[50..52].copy_from_slice(&entry.port.to_be_bytes());
        match entry.address.address {
            Address::V4(v4) => bytes[52..56].copy_from_slice(&v4),
            Address::V6(v6) => {
                bytes[56..72].copy_from_slice(&v6);
                bytes[72..76].copy_from_slice(&entry.address.scope.to_ne_bytes());
            }
        }
        if let Some(name) = canonical {
            bytes[32..40].copy_from_slice(&(allocation as usize + 76).to_ne_bytes());
            bytes[76..76 + name.len()].copy_from_slice(name);
        }
        let node = allocation.cast::<AddrInfo>();
        if self.head.is_null() {
            self.head = node;
        } else {
            // SAFETY: tail is an initialized node owned exclusively by this
            // unpublished list. No application memory is borrowed here.
            unsafe { (*self.tail).next = node };
        }
        self.tail = node;
        Ok(())
    }
    /// The outer owner must be registered in an io_resources scope. Publication
    /// and disarming cleanup share one native-delivery guard.
    pub fn publish(&mut self, result: *mut *mut AddrInfo) -> Result<(), Error> {
        if self.head.is_null() {
            return Err(Error::NoName);
        }
        let _native = defer_native_delivery();
        user_copy::write(result.cast(), &(self.head as usize).to_ne_bytes()).map_err(system)?;
        self.head = ptr::null_mut();
        self.tail = ptr::null_mut();
        Ok(())
    }
}
impl Drop for List {
    fn drop(&mut self) {
        let _native = defer_native_delivery();
        while !self.head.is_null() {
            let node = self.head;
            // SAFETY: unpublished nodes remain private to the tracked owner.
            self.head = unsafe { (*node).next };
            unsafe { free(node.cast()) };
        }
        self.tail = ptr::null_mut();
    }
}
/// # Safety
/// `head` must be null or a still-owned, valid list/sublist returned by this
/// resolver. As with C free, arbitrary or already freed pointers are invalid.
pub(super) unsafe fn release(mut head: *mut AddrInfo) -> Result<(), Error> {
    let _native = defer_native_delivery();
    while !head.is_null() {
        let address = (head as usize)
            .checked_add(40)
            .ok_or_else(|| system(EFAULT))?;
        let mut next = [0; 8];
        user_copy::read(address as *const u8, &mut next).map_err(system)?;
        let pointer = usize::from_ne_bytes(next) as *mut AddrInfo;
        // Reading public links is faultable; no Rust reference to the caller's
        // potentially modified struct is formed. Allocation validity is the C
        // ownership precondition, just as it is for free().
        unsafe { free(head.cast()) };
        head = pointer;
    }
    Ok(())
}

pub(super) struct NameOutputs {
    host: *mut c_char,
    host_capacity: usize,
    service: *mut c_char,
    service_capacity: usize,
}
impl NameOutputs {
    pub fn new(
        host: *mut c_char,
        host_capacity: u32,
        service: *mut c_char,
        service_capacity: u32,
    ) -> Result<Self, Error> {
        let out = Self {
            host,
            host_capacity: host_capacity as usize,
            service,
            service_capacity: service_capacity as usize,
        };
        if !out.wants_host() && !out.wants_service() {
            return Err(Error::NoName);
        }
        Ok(out)
    }
    pub fn wants_host(&self) -> bool {
        !self.host.is_null() && self.host_capacity != 0
    }
    pub fn wants_service(&self) -> bool {
        !self.service.is_null() && self.service_capacity != 0
    }
    /// Both private strings must include one terminal NUL, without embedded
    /// NULs. Check all capacities before the first application write.
    pub fn publish(&self, host: &[u8], service: &[u8]) -> Result<(), Error> {
        for (wanted, pointer, capacity, bytes) in [
            (self.wants_host(), self.host, self.host_capacity, host),
            (
                self.wants_service(),
                self.service,
                self.service_capacity,
                service,
            ),
        ] {
            if !wanted {
                continue;
            }
            if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
                return Err(Error::Fail);
            }
            if bytes.len() > capacity {
                return Err(Error::Overflow);
            }
            (pointer as usize)
                .checked_add(bytes.len())
                .ok_or_else(|| system(EFAULT))?;
        }
        if self.wants_host() {
            user_copy::write(self.host.cast(), host).map_err(system)?;
        }
        if self.wants_service() {
            user_copy::write(self.service.cast(), service).map_err(system)?;
        }
        Ok(())
    }
}

pub(super) fn error_text(code: c_int) -> &'static [u8] {
    match code {
        0 => b"Success\0",
        -1 => b"Invalid name resolution flags\0",
        -2 => b"Name or service not known\0",
        -3 => b"Temporary failure in name resolution\0",
        -4 => b"Name resolution failed\0",
        -6 => b"Address family not supported\0",
        -7 => b"Socket type not supported\0",
        -8 => b"Service not supported for socket type\0",
        -10 => b"Memory allocation failed\0",
        -11 => b"System error\0",
        -12 => b"Name resolution buffer is too small\0",
        _ => b"Unknown name resolution error\0",
    }
}
