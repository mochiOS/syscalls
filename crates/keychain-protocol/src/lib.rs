//! Bounded keychain IPC. User IDs and caller application identities are never request fields.
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;
use alloc::{string::String, vec::Vec};
use core::fmt;
use zeroize::Zeroizing;
// mochiOS' native inline IPC capacity is 8 KiB. Linux must enforce it too.
pub const MAX_FRAME: usize = 8 * 1024;
pub const MAX_SECRET: usize = 4096;
pub const MAX_PASSWORD: usize = 1024;
pub const MAX_ITEMS: usize = 256;
// Two worst-case items (including all grants) fit in native IPC.
pub const PAGE_SIZE: usize = 2;
pub const APPLICATION_PAGE_SIZE: usize = 32;
pub const MAX_APPLICATIONS: usize = MAX_ITEMS * (MAX_GRANTS + 2);
pub const MAX_GRANTS: usize = 16;
pub const SERVICE_NAME: &str = "keychain.service";
pub const ACCESS: &str = "keychain.access";
pub const MANAGE: &str = "keychain.manage";
pub const SESSION: &str = "keychain.session";
const MAGIC: &[u8; 8] = b"MKCHN002";
const HEADER: usize = 24;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Error {
    Invalid = 1,
    Denied,
    Locked,
    Missing,
    Exists,
    Authentication,
    Corrupt,
    Limit,
    Storage,
    Conflict,
    Unavailable,
    Busy,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid keychain request",
            Self::Denied => "keychain access denied",
            Self::Locked => "keychain is locked",
            Self::Missing => "keychain item not found",
            Self::Exists => "keychain already exists",
            Self::Authentication => "password is incorrect or vault authentication failed",
            Self::Corrupt => "keychain data is damaged",
            Self::Limit => "keychain capacity exceeded",
            Self::Storage => "keychain storage failed",
            Self::Conflict => "keychain changed; refresh required",
            Self::Unavailable => "keychain service is unavailable",
            Self::Busy => "keychain service is busy",
        })
    }
}
#[cfg(feature = "std")]
impl std::error::Error for Error {}
impl Error {
    fn decode(n: u16) -> Result<Self> {
        Ok(match n {
            1 => Self::Invalid,
            2 => Self::Denied,
            3 => Self::Locked,
            4 => Self::Missing,
            5 => Self::Exists,
            6 => Self::Authentication,
            7 => Self::Corrupt,
            8 => Self::Limit,
            9 => Self::Storage,
            10 => Self::Conflict,
            11 => Self::Unavailable,
            12 => Self::Busy,
            _ => return Err(Self::Invalid),
        })
    }
}
pub type Result<T> = core::result::Result<T, Error>;
/// Owning secret buffer; debug output never contains its bytes.
pub struct Secret(Zeroizing<Vec<u8>>);
impl Secret {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl Clone for Secret {
    fn clone(&self) -> Self {
        Self::new(self.expose().to_vec())
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Application {
    pub package: String,
    pub signer: [u8; 32],
    pub provenance: u8,
}
impl Application {
    pub fn validate(&self) -> Result<()> {
        if self.package.is_empty()
            || self.package.len() > 128
            || !self
                .package
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            || !(1..=3).contains(&self.provenance)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
pub type ItemId = [u8; 16];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub id: ItemId,
    pub owner: Application,
    pub service: String,
    pub account: String,
    pub label: String,
    pub grants: Vec<Application>,
}
impl Item {
    pub fn validate(&self) -> Result<()> {
        self.owner.validate()?;
        valid_text(&self.service, 128, false)?;
        valid_text(&self.account, 256, true)?;
        valid_text(&self.label, 128, false)?;
        if self.id == [0; 16] || self.grants.len() > MAX_GRANTS {
            return Err(Error::Invalid);
        }
        for (i, g) in self.grants.iter().enumerate() {
            g.validate()?;
            if *g == self.owner || self.grants[..i].contains(g) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}
pub fn valid_text(text: &str, max: usize, empty: bool) -> Result<()> {
    if (!empty && text.is_empty()) || text.len() > max || text.chars().any(char::is_control) {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
pub enum Request {
    Status,
    Initialize {
        password: Secret,
    },
    Unlock {
        password: Secret,
    },
    Lock,
    Put {
        service: String,
        account: String,
        label: String,
        secret: Secret,
    },
    Get {
        id: ItemId,
    },
    Delete {
        id: ItemId,
    },
    List {
        manager: bool,
        offset: u16,
        generation: u64,
    },
    Reveal {
        id: ItemId,
        password: Secret,
    },
    ManageDelete {
        id: ItemId,
        password: Secret,
    },
    Grant {
        id: ItemId,
        target: Application,
        revoke: bool,
        password: Secret,
    },
    ChangePassword {
        old: Secret,
        new: Secret,
    },
    Applications {
        offset: u16,
        generation: u64,
    },
    LockAll,
}
impl Request {
    pub fn opcode(&self) -> u16 {
        match self {
            Self::Status => 1,
            Self::Initialize { .. } => 2,
            Self::Unlock { .. } => 3,
            Self::Lock => 4,
            Self::Put { .. } => 5,
            Self::Get { .. } => 6,
            Self::Delete { .. } => 7,
            Self::List { .. } => 8,
            Self::Reveal { .. } => 9,
            Self::ManageDelete { .. } => 10,
            Self::Grant { .. } => 11,
            Self::ChangePassword { .. } => 12,
            Self::Applications { .. } => 13,
            Self::LockAll => 14,
        }
    }
    pub fn manager(&self) -> bool {
        matches!(
            self,
            Self::Initialize { .. }
                | Self::Unlock { .. }
                | Self::Lock
                | Self::List { manager: true, .. }
                | Self::Reveal { .. }
                | Self::ManageDelete { .. }
                | Self::Grant { .. }
                | Self::ChangePassword { .. }
                | Self::Applications { .. }
        )
    }
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>> {
        let mut w = Writer::new();
        match self {
            Self::Status | Self::Lock | Self::LockAll => {}
            Self::Applications { offset, generation } => {
                w.u16(*offset);
                w.u64(*generation);
            }
            Self::Initialize { password } | Self::Unlock { password } => {
                w.bytes(password.expose(), MAX_PASSWORD)?
            }
            Self::Put {
                service,
                account,
                label,
                secret,
            } => {
                valid_text(service, 128, false)?;
                valid_text(account, 256, true)?;
                valid_text(label, 128, false)?;
                w.text(service, 128)?;
                w.text(account, 256)?;
                w.text(label, 128)?;
                w.bytes(secret.expose(), MAX_SECRET)?;
            }
            Self::Get { id } | Self::Delete { id } => w.raw(id),
            Self::List {
                manager,
                offset,
                generation,
            } => {
                w.u8(u8::from(*manager));
                w.u16(*offset);
                w.u64(*generation);
            }
            Self::Reveal { id, password } | Self::ManageDelete { id, password } => {
                w.raw(id);
                w.bytes(password.expose(), MAX_PASSWORD)?;
            }
            Self::Grant {
                id,
                target,
                revoke,
                password,
            } => {
                w.raw(id);
                w.application(target)?;
                w.u8(u8::from(*revoke));
                w.bytes(password.expose(), MAX_PASSWORD)?;
            }
            Self::ChangePassword { old, new } => {
                w.bytes(old.expose(), MAX_PASSWORD)?;
                w.bytes(new.expose(), MAX_PASSWORD)?;
            }
        };
        frame(self.opcode(), 0, id, &w.finish())
    }
    pub fn decode(bytes: &[u8]) -> Result<(u64, Self)> {
        let (op, status, id, payload) = unframe(bytes)?;
        if status != 0 {
            return Err(Error::Invalid);
        }
        let mut r = Reader::new(payload);
        let req = match op {
            1 => Self::Status,
            2 => Self::Initialize {
                password: r.secret(MAX_PASSWORD)?,
            },
            3 => Self::Unlock {
                password: r.secret(MAX_PASSWORD)?,
            },
            4 => Self::Lock,
            5 => {
                let service = r.text(128)?;
                let account = r.text(256)?;
                let label = r.text(128)?;
                valid_text(&service, 128, false)?;
                valid_text(&account, 256, true)?;
                valid_text(&label, 128, false)?;
                Self::Put {
                    service,
                    account,
                    label,
                    secret: r.secret(MAX_SECRET)?,
                }
            }
            6 => Self::Get { id: r.array()? },
            7 => Self::Delete { id: r.array()? },
            8 => Self::List {
                manager: r.boolean()?,
                offset: r.u16()?,
                generation: r.u64()?,
            },
            9 => Self::Reveal {
                id: r.array()?,
                password: r.secret(MAX_PASSWORD)?,
            },
            10 => Self::ManageDelete {
                id: r.array()?,
                password: r.secret(MAX_PASSWORD)?,
            },
            11 => Self::Grant {
                id: r.array()?,
                target: r.application()?,
                revoke: r.boolean()?,
                password: r.secret(MAX_PASSWORD)?,
            },
            12 => Self::ChangePassword {
                old: r.secret(MAX_PASSWORD)?,
                new: r.secret(MAX_PASSWORD)?,
            },
            13 => Self::Applications {
                offset: r.u16()?,
                generation: r.u64()?,
            },
            14 => Self::LockAll,
            _ => return Err(Error::Invalid),
        };
        r.end()?;
        Ok((id, req))
    }
}
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeychainRequest(op={})", self.opcode())
    }
}
pub enum Reply {
    Ok,
    Status {
        initialized: bool,
        unlocked: bool,
    },
    Id(ItemId),
    Secret(Secret),
    Items {
        generation: u64,
        total: u16,
        items: Vec<Item>,
    },
    Applications {
        generation: u64,
        total: u16,
        applications: Vec<Application>,
    },
}
impl Reply {
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>> {
        let mut w = Writer::new();
        let op = match self {
            Self::Ok => 0,
            Self::Status {
                initialized,
                unlocked,
            } => {
                w.u8(u8::from(*initialized));
                w.u8(u8::from(*unlocked));
                1
            }
            Self::Id(id) => {
                w.raw(id);
                2
            }
            Self::Secret(secret) => {
                w.bytes(secret.expose(), MAX_SECRET)?;
                3
            }
            Self::Items {
                generation,
                total,
                items,
            } => {
                if *generation == 0
                    || items.len() > PAGE_SIZE
                    || usize::from(*total) > MAX_ITEMS
                    || items.len() > usize::from(*total)
                {
                    return Err(Error::Invalid);
                }
                w.u64(*generation);
                w.u16(*total);
                w.u16(items.len() as u16);
                for i in items {
                    w.item(i)?;
                }
                4
            }
            Self::Applications {
                generation,
                total,
                applications: apps,
            } => {
                if *generation == 0
                    || usize::from(*total) > MAX_APPLICATIONS
                    || apps.len() > APPLICATION_PAGE_SIZE
                    || apps.len() > usize::from(*total)
                {
                    return Err(Error::Invalid);
                }
                w.u64(*generation);
                w.u16(*total);
                w.u16(apps.len() as u16);
                for a in apps {
                    w.application(a)?;
                }
                5
            }
        };
        frame(op, 0, id, &w.finish())
    }
    pub fn error(id: u64, error: Error) -> Zeroizing<Vec<u8>> {
        frame(0, error as u16, id, &[]).unwrap_or_default()
    }
    pub fn decode(bytes: &[u8], expected: u64) -> Result<Self> {
        let (op, status, id, payload) = unframe(bytes)?;
        if id != expected {
            return Err(Error::Invalid);
        }
        if status != 0 {
            if !payload.is_empty() {
                return Err(Error::Invalid);
            }
            return Err(Error::decode(status)?);
        }
        let mut r = Reader::new(payload);
        let out = match op {
            0 => Self::Ok,
            1 => Self::Status {
                initialized: r.boolean()?,
                unlocked: r.boolean()?,
            },
            2 => Self::Id(r.array()?),
            3 => Self::Secret(r.secret(MAX_SECRET)?),
            4 => {
                let generation = r.u64()?;
                let total = r.u16()?;
                let n = r.u16()? as usize;
                if generation == 0
                    || n > PAGE_SIZE
                    || usize::from(total) > MAX_ITEMS
                    || n > total as usize
                {
                    return Err(Error::Invalid);
                }
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(r.item()?);
                }
                Self::Items {
                    generation,
                    total,
                    items,
                }
            }
            5 => {
                let generation = r.u64()?;
                let total = r.u16()?;
                let n = r.u16()? as usize;
                if generation == 0
                    || usize::from(total) > MAX_APPLICATIONS
                    || n > APPLICATION_PAGE_SIZE
                    || n > usize::from(total)
                {
                    return Err(Error::Invalid);
                }
                let mut apps = Vec::with_capacity(n);
                for _ in 0..n {
                    apps.push(r.application()?);
                }
                Self::Applications {
                    generation,
                    total,
                    applications: apps,
                }
            }
            _ => return Err(Error::Invalid),
        };
        r.end()?;
        Ok(out)
    }
}
fn frame(op: u16, status: u16, id: u64, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() > MAX_FRAME - HEADER {
        return Err(Error::Limit);
    }
    let mut b = Zeroizing::new(Vec::with_capacity(HEADER + payload.len()));
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&op.to_le_bytes());
    b.extend_from_slice(&status.to_le_bytes());
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(&id.to_le_bytes());
    b.extend_from_slice(payload);
    Ok(b)
}
fn unframe(b: &[u8]) -> Result<(u16, u16, u64, &[u8])> {
    if b.len() < HEADER || b.len() > MAX_FRAME || &b[..8] != MAGIC {
        return Err(Error::Invalid);
    }
    let n = u32::from_le_bytes(b[12..16].try_into().unwrap()) as usize;
    if n != b.len() - HEADER {
        return Err(Error::Invalid);
    }
    Ok((
        u16::from_le_bytes(b[8..10].try_into().unwrap()),
        u16::from_le_bytes(b[10..12].try_into().unwrap()),
        u64::from_le_bytes(b[16..24].try_into().unwrap()),
        &b[24..],
    ))
}
/// Shared bounded encoding for the encrypted vault records; never use for log output.
pub struct Writer {
    bytes: Zeroizing<Vec<u8>>,
}
impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}
impl Writer {
    pub fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }
    pub fn raw(&mut self, b: &[u8]) {
        let required = self
            .bytes
            .len()
            .checked_add(b.len())
            .expect("encoder size overflow");
        if required > self.bytes.capacity() {
            // Vec::reserve/realloc would release the previous secret allocation
            // without zeroizing it. Allocate separately and let Zeroizing erase
            // the old allocation (including spare capacity) before releasing it.
            let capacity = required.max(self.bytes.capacity().saturating_mul(2));
            let mut next = Zeroizing::new(Vec::with_capacity(capacity));
            next.extend_from_slice(&self.bytes);
            self.bytes = next;
        }
        self.bytes.extend_from_slice(b)
    }
    pub fn u8(&mut self, n: u8) {
        self.raw(&[n]);
    }
    pub fn u16(&mut self, n: u16) {
        self.raw(&n.to_le_bytes());
    }
    pub fn u64(&mut self, n: u64) {
        self.raw(&n.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8], max: usize) -> Result<()> {
        if b.len() > max || b.len() > u16::MAX as usize {
            return Err(Error::Limit);
        }
        self.u16(b.len() as u16);
        self.raw(b);
        Ok(())
    }
    pub fn text(&mut self, s: &str, max: usize) -> Result<()> {
        self.bytes(s.as_bytes(), max)
    }
    pub fn application(&mut self, a: &Application) -> Result<()> {
        a.validate()?;
        self.text(&a.package, 128)?;
        self.raw(&a.signer);
        self.u8(a.provenance);
        Ok(())
    }
    pub fn item(&mut self, i: &Item) -> Result<()> {
        i.validate()?;
        self.raw(&i.id);
        self.application(&i.owner)?;
        self.text(&i.service, 128)?;
        self.text(&i.account, 256)?;
        self.text(&i.label, 128)?;
        self.u8(i.grants.len() as u8);
        for g in &i.grants {
            self.application(g)?;
        }
        Ok(())
    }
    pub fn finish(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(Error::Invalid)?;
        let out = self.bytes.get(self.at..end).ok_or(Error::Invalid)?;
        self.at = end;
        Ok(out)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn boolean(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Invalid),
        }
    }
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(Error::Limit);
        }
        self.take(n)
    }
    pub fn secret(&mut self, max: usize) -> Result<Secret> {
        Ok(Secret::new(self.bytes(max)?.to_vec()))
    }
    pub fn text(&mut self, max: usize) -> Result<String> {
        let s = core::str::from_utf8(self.bytes(max)?).map_err(|_| Error::Invalid)?;
        Ok(s.into())
    }
    pub fn application(&mut self) -> Result<Application> {
        let a = Application {
            package: self.text(128)?,
            signer: self.array()?,
            provenance: self.u8()?,
        };
        a.validate()?;
        Ok(a)
    }
    pub fn item(&mut self) -> Result<Item> {
        let id = self.array()?;
        let owner = self.application()?;
        let service = self.text(128)?;
        let account = self.text(256)?;
        let label = self.text(128)?;
        let n = self.u8()? as usize;
        if n > MAX_GRANTS {
            return Err(Error::Limit);
        }
        let mut grants = Vec::with_capacity(n);
        for _ in 0..n {
            grants.push(self.application()?);
        }
        let i = Item {
            id,
            owner,
            service,
            account,
            label,
            grants,
        };
        i.validate()?;
        Ok(i)
    }
    pub fn end(&self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::alloc::{GlobalAlloc, Layout, System};

    struct AuditAllocator;
    static WATCHED: AtomicUsize = AtomicUsize::new(0);
    static RELEASED: AtomicBool = AtomicBool::new(false);
    static UNWIPED: AtomicBool = AtomicBool::new(false);
    // Inspect only an explicitly watched, still-live allocation immediately before
    // handing it back to System. Never inspect memory after free/realloc.
    fn inspect_release(ptr: *mut u8, layout: Layout) {
        if WATCHED
            .compare_exchange(ptr as usize, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let bytes = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            UNWIPED.store(bytes.iter().any(|&b| b != 0), Ordering::SeqCst);
            RELEASED.store(true, Ordering::SeqCst);
        }
    }
    unsafe impl GlobalAlloc for AuditAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            inspect_release(ptr, layout);
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            inspect_release(ptr, layout);
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
    #[global_allocator]
    static ALLOCATOR: AuditAllocator = AuditAllocator;

    #[test]
    fn growing_writer_wipes_old_allocation_before_release() {
        let mut writer = Writer::new();
        writer.raw(&[0xa5; 64]);
        WATCHED.store(writer.bytes.as_ptr() as usize, Ordering::SeqCst);
        writer.raw(&[0x5a; 8192]);
        assert!(RELEASED.load(Ordering::SeqCst));
        assert!(
            !UNWIPED.load(Ordering::SeqCst),
            "secret bytes were released without erasure"
        );
        assert_eq!(&writer.bytes[..64], &[0xa5; 64]);
        assert_eq!(&writer.bytes[64..], &[0x5a; 8192]);
    }
    #[test]
    fn frames_are_bounded_and_secrets_redacted() {
        let r = Request::Initialize {
            password: Secret::new(b"never-log-me".to_vec()),
        };
        assert!(!alloc::format!("{r:?}").contains("never-log-me"));
        assert!(!alloc::format!("{:?}", Secret::new(b"secret".to_vec())).contains("secret"));
        let frame = r.encode(42).unwrap();
        assert!(matches!(
            Request::decode(&frame),
            Ok((42, Request::Initialize { .. }))
        ));
        for n in 0..frame.len() {
            assert!(Request::decode(&frame[..n]).is_err());
        }
        let mut extra = frame.to_vec();
        extra.push(0);
        assert!(Request::decode(&extra).is_err());
        assert!(Reply::decode(&Reply::Ok.encode(42).unwrap(), 41).is_err());
    }
    #[test]
    fn malformed_native_frames_never_panic_or_accept_trailing_data() {
        let mut rng = 0x9e3779b97f4a7c15u64;
        for i in 0..4096 {
            let n = i % (MAX_FRAME + 1);
            let mut bytes = alloc::vec![0; HEADER + n];
            for b in &mut bytes {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                *b = rng as u8;
            }
            bytes[..8].copy_from_slice(MAGIC);
            bytes[8..10].copy_from_slice(&((i % 15) as u16).to_le_bytes());
            bytes[10..12].copy_from_slice(&0u16.to_le_bytes());
            bytes[12..16].copy_from_slice(&(n as u32).to_le_bytes());
            bytes[16..24].copy_from_slice(&42u64.to_le_bytes());
            let _ = Request::decode(&bytes);
            let _ = Reply::decode(&bytes, 42);
            // Truncation of a declared frame must never expose partial results.
            assert!(Request::decode(&bytes[..bytes.len() - 1]).is_err());
            assert!(Reply::decode(&bytes[..bytes.len() - 1], 42).is_err());
        }
    }
    #[test]
    fn request_limits_reject_control_characters_and_large_secrets() {
        assert!(
            Request::Put {
                service: "bad\nname".into(),
                account: String::new(),
                label: "label".into(),
                secret: Secret::new(Vec::new())
            }
            .encode(1)
            .is_err()
        );
        assert!(
            Request::Initialize {
                password: Secret::new(alloc::vec![1;MAX_PASSWORD+1])
            }
            .encode(1)
            .is_err()
        );
    }
}
