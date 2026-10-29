//! Per-call name-service state. Native resource acquisition is published under
//! the delivery guard; file/DNS data I/O and waits run with callbacks enabled.
use super::*;
use mochios_posix_client::{
    interfaces,
    internet::Address,
    netdb::{
        self as policy, Backend as Policy, Error, Host, Reverse, ScopedAddress, Transport,
        database, dns,
    },
    resolver,
};

#[cfg(target_os = "mochios")]
#[path = "netdb_native.rs"]
pub(super) mod native;

/// Owned Handle numbers here are private process-local labels. Implementations
/// must not recover them from a PID, FD or a sender-supplied wire identifier.
pub(super) trait Io {
    fn endpoint(&mut self) -> Result<u32, Error>;
    fn factory(&mut self, endpoint: u32) -> Result<u32, Error>;
    /// None is the explicit pre-creation quota result, safe to retry. Other
    /// errors must not replay an operation whose outcome is unknown.
    fn start(
        &mut self,
        endpoint: u32,
        factory: u32,
        kind: resolver::Kind,
        name: resolver::Name<'_>,
        timeout: u32,
    ) -> Result<Option<u32>, Error>;
    fn observe(&mut self, job: u32) -> Result<resolver::Observation, Error>;
    fn snapshot<'a>(
        &mut self,
        job: u32,
        kind: resolver::Kind,
        name: resolver::Name<'_>,
        out: &'a mut [u8],
    ) -> Result<resolver::ResultView<'a>, Error>;
    fn wait(&mut self, job: u32, deadline: u64) -> Result<(), Error>;
    fn now(&mut self) -> Result<u64, Error>;
    fn retry(&mut self) -> Result<(), Error>;
    fn interfaces<'a>(
        &mut self,
        endpoint: u32,
        out: &'a mut [u8],
    ) -> Result<interfaces::Snapshot<'a>, Error>;
    fn open(&mut self, path: &[u8]) -> Result<u32, Error>;
    fn read(&mut self, file: u32, offset: u64, out: &mut [u8]) -> Result<usize, Error>;
    fn close(&mut self, handle: u32);
}
struct Data {
    done: bool,
    error: Option<Error>,
    buffer: Option<VectorBuffer>,
    length: usize,
}
impl Data {
    const fn new() -> Self {
        Self {
            done: false,
            error: None,
            buffer: None,
            length: 0,
        }
    }
}
#[derive(Clone, Copy)]
enum File {
    Hosts,
    Services,
}
pub(super) struct Backend<I: Io> {
    io: I,
    endpoint: Option<u32>,
    factory: Option<u32>,
    job: Option<u32>,
    file: Option<u32>,
    hosts: Data,
    services: Data,
    metadata: Option<VectorBuffer>,
    answer: Option<VectorBuffer>,
    deadline: Option<u64>,
}
impl<I: Io> Backend<I> {
    pub fn new(io: I) -> Self {
        Self {
            io,
            endpoint: None,
            factory: None,
            job: None,
            file: None,
            hosts: Data::new(),
            services: Data::new(),
            metadata: None,
            answer: None,
            deadline: None,
        }
    }
    fn endpoint(&mut self) -> Result<u32, Error> {
        if let Some(h) = self.endpoint {
            return Ok(h);
        }
        let _native = defer_native_delivery();
        let h = self.io.endpoint()?;
        if h == 0 {
            return Err(Error::Fail);
        }
        self.endpoint = Some(h);
        Ok(h)
    }
    fn metadata(&mut self) -> Result<interfaces::Snapshot<'_>, Error> {
        let endpoint = self.endpoint()?;
        if self.metadata.is_none() {
            let _native = defer_native_delivery();
            self.metadata = Some(VectorBuffer::new(interfaces::MAX_REPLY).map_err(memory_error)?);
        }
        self.io
            .interfaces(endpoint, self.metadata.as_mut().unwrap().bytes())
    }
    fn local(&mut self, address: ScopedAddress) -> bool {
        match address.address {
            Address::V4(v4) if v4[0] == 127 => return true,
            Address::V6(v6) if v6 == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] => {
                return true;
            }
            _ => {}
        }
        // Locality is advisory for NI_NOFQDN. If it cannot be established,
        // preserve the complete name rather than stripping a remote suffix.
        self.metadata().ok().is_some_and(|snapshot| {
            snapshot.records().any(|r| {
                r.addresses().any(|a| match (a, address.address) {
                    (interfaces::Address::V4 { bytes, .. }, Address::V4(v4)) => bytes == v4,
                    (interfaces::Address::V6 { bytes, .. }, Address::V6(v6)) => bytes == v6,
                    _ => false,
                })
            })
        })
    }
    fn file_data(&mut self, which: File) -> Result<Option<&[u8]>, Error> {
        let data = match which {
            File::Hosts => &mut self.hosts,
            File::Services => &mut self.services,
        };
        if !data.done {
            data.done = true;
            let path = match which {
                File::Hosts => b"/etc/hosts".as_slice(),
                File::Services => b"/etc/services".as_slice(),
            };
            let opened = {
                let _native = defer_native_delivery();
                match self.io.open(path) {
                    Ok(h) if h != 0 => {
                        self.file = Some(h);
                        Ok(h)
                    }
                    Ok(_) => Err(Error::Fail),
                    Err(e) => Err(e),
                }
            };
            match opened {
                Err(e) => data.error = Some(e),
                Ok(file) => {
                    let outcome = (|| {
                        loop {
                            if data.buffer.as_ref().is_none_or(|b| data.length == b.length) {
                                let _native = defer_native_delivery();
                                let size = data
                                    .buffer
                                    .as_ref()
                                    .map_or(Some(4096), |b| b.length.checked_mul(2))
                                    .ok_or(Error::Memory)?;
                                let mut next = VectorBuffer::new(size).map_err(memory_error)?;
                                if next.length != size {
                                    return Err(Error::Memory);
                                }
                                if let Some(old) = data.buffer.as_mut() {
                                    next.bytes()[..data.length]
                                        .copy_from_slice(&old.bytes()[..data.length]);
                                }
                                data.buffer = Some(next);
                            }
                            let buffer = data.buffer.as_mut().unwrap();
                            let available = (buffer.length - data.length).min(4096);
                            let n = self.io.read(
                                file,
                                data.length as u64,
                                &mut buffer.bytes()[data.length..data.length + available],
                            )?;
                            if n > available {
                                return Err(Error::Fail);
                            }
                            if n == 0 {
                                return Ok(());
                            }
                            data.length = data.length.checked_add(n).ok_or(Error::Memory)?;
                        }
                    })();
                    {
                        let _native = defer_native_delivery();
                        self.io.close(self.file.take().unwrap());
                    }
                    if let Err(e) = outcome {
                        data.error = Some(e);
                    }
                }
            }
        }
        if let Some(error) = data.error {
            return Err(error);
        }
        Ok(data.buffer.as_mut().map(|b| &b.bytes()[..data.length]))
    }
    fn dns(
        &mut self,
        kind: resolver::Kind,
        name: resolver::Name<'_>,
    ) -> Result<resolver::ResultView<'_>, Error> {
        // A failed family may be followed by a lookup of the other family.
        // Retire its unfinished query before spending the shared deadline.
        if let Some(job) = self.job.take() {
            let _native = defer_native_delivery();
            self.io.close(job);
        }
        let endpoint = self.endpoint()?;
        if self.factory.is_none() {
            let _native = defer_native_delivery();
            let h = self.io.factory(endpoint)?;
            if h == 0 {
                return Err(Error::Fail);
            }
            self.factory = Some(h);
        }
        let deadline = match self.deadline {
            Some(d) => d,
            None => {
                let d = self
                    .io
                    .now()?
                    .checked_add(u64::from(resolver::MAX_TIMEOUT) * 1_000_000)
                    .ok_or(Error::System(-75))?;
                self.deadline = Some(d);
                d
            }
        };
        loop {
            let now = self.io.now()?;
            if now >= deadline {
                return Err(Error::Again);
            }
            let timeout = (deadline - now)
                .div_ceil(1_000_000)
                .min(u64::from(resolver::MAX_TIMEOUT)) as u32;
            {
                let _native = defer_native_delivery();
                if let Some(h) =
                    self.io
                        .start(endpoint, self.factory.unwrap(), kind, name, timeout)?
                {
                    if h == 0 {
                        return Err(Error::Fail);
                    }
                    self.job = Some(h);
                }
            }
            if self.job.is_some() {
                break;
            }
            self.io.retry()?;
        }
        let job = self.job.unwrap();
        let observed = loop {
            let observed = self.io.observe(job)?;
            if observed.kind != kind {
                return Err(Error::Fail);
            }
            if observed.ready {
                break observed;
            }
            self.io.wait(job, deadline)?;
            if self.io.now()? >= deadline {
                // Completion may win the deadline race. Inspect the owner once
                // before closing/cancelling a query that became ready.
                let observed = self.io.observe(job)?;
                if observed.kind != kind {
                    return Err(Error::Fail);
                }
                if observed.ready {
                    break observed;
                }
                return Err(Error::Again);
            }
        };
        let length = usize::try_from(observed.length).map_err(|_| Error::Fail)?;
        if length == 0 || length > resolver::MAX_RESULT_LEN {
            return Err(Error::Fail);
        }
        if self.answer.as_ref().is_none_or(|b| b.length < length) {
            let _native = defer_native_delivery();
            self.answer = Some(VectorBuffer::new(length).map_err(memory_error)?);
        }
        let outcome = self
            .io
            .snapshot(job, kind, name, self.answer.as_mut().unwrap().bytes());
        {
            let _native = defer_native_delivery();
            self.io.close(self.job.take().unwrap());
        }
        outcome
    }
}
fn unavailable(error: Error) -> bool {
    matches!(
        error,
        Error::NoName | Error::System(-2 | -20 | -13 | -1 | -5)
    )
}
fn memory_error(errno: c_int) -> Error {
    if errno == ENOMEM {
        Error::Memory
    } else {
        Error::System(mochios_posix_client::newlib_errno::to_status(errno))
    }
}
impl<I: Io> Policy for Backend<I> {
    fn configuration(&mut self) -> Result<policy::Configuration, Error> {
        Ok(interfaces::configuration(self.metadata()?))
    }
    fn scope(&mut self, name: &[u8]) -> Result<Option<u32>, Error> {
        let name = core::str::from_utf8(name).map_err(|_| Error::NoName)?;
        Ok(self.metadata()?.index(name))
    }
    fn host(
        &mut self,
        name: &[u8],
        family: i32,
        emit: &mut dyn FnMut(Host<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut known = false;
        match self.file_data(File::Hosts) {
            Ok(Some(data)) => {
                for row in database::hosts(data) {
                    let address: ScopedAddress = row.address.into();
                    if row.matches(name) {
                        known = true;
                        if address.family() == family {
                            emit(Host {
                                address,
                                canonical: Some(row.canonical),
                            })?;
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(e) if unavailable(e) => {}
            Err(e) => return Err(e),
        }
        // The local name database owns all of a matching name's families.
        // An IPv4-only local entry must not require DNS authority merely
        // because AF_UNSPEC checks IPv6 first.
        if known {
            return Ok(());
        }
        let kind = match family {
            2 => resolver::Kind::A,
            10 => resolver::Kind::Aaaa,
            _ => return Err(Error::Family),
        };
        let mut wire = [0; 255];
        let question = dns::question(name, &mut wire)?;
        dns::forward(&self.dns(kind, question)?, emit)?;
        Ok(())
    }
    fn service(&mut self, name: &[u8], transport: Transport) -> Result<Option<u16>, Error> {
        match self.file_data(File::Services) {
            Ok(Some(data)) => Ok(database::services(data)
                .find(|r| r.transport == transport && r.matches(name))
                .map(|r| r.port)),
            Ok(None) | Err(Error::System(-2 | -20)) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn reverse(
        &mut self,
        address: ScopedAddress,
        out: &mut [u8],
    ) -> Result<Option<Reverse>, Error> {
        let local_name = match self.file_data(File::Hosts) {
            Ok(Some(data)) => {
                let row = database::hosts(data).find(|r| r.address == address.address);
                if let Some(row) = row {
                    let n = row.canonical.len();
                    out.get_mut(..n)
                        .ok_or(Error::Overflow)?
                        .copy_from_slice(row.canonical);
                    Some(n)
                } else {
                    None
                }
            }
            Ok(None) => None,
            Err(e) if unavailable(e) => None,
            Err(e) => return Err(e),
        };
        if let Some(length) = local_name {
            // A hosts file can contain remote names. Do not treat every file
            // entry as local merely to strip its DNS suffix.
            return Ok(Some(Reverse {
                length,
                local: self.local(address),
            }));
        }
        let mut wire = [0; 255];
        let question = dns::reverse(address, &mut wire)?;
        let found = dns::ptr(&self.dns(resolver::Kind::Ptr, question)?, out)?;
        Ok(found.map(|length| Reverse {
            length,
            local: self.local(address),
        }))
    }
    fn service_name(
        &mut self,
        port: u16,
        transport: Transport,
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let data = match self.file_data(File::Services) {
            Ok(data) => data,
            Err(e) if unavailable(e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let Some(row) = data.and_then(|data| {
            database::services(data).find(|r| r.port == port && r.transport == transport)
        }) else {
            return Ok(None);
        };
        out.get_mut(..row.name.len())
            .ok_or(Error::Overflow)?
            .copy_from_slice(row.name);
        Ok(Some(row.name.len()))
    }
}
impl<I: Io> Drop for Backend<I> {
    fn drop(&mut self) {
        let _native = defer_native_delivery();
        for h in [
            self.job.take(),
            self.file.take(),
            self.factory.take(),
            self.endpoint.take(),
        ]
        .into_iter()
        .flatten()
        {
            self.io.close(h);
        }
        // Buffer destruction is also guarded when native delivery reopens.
        self.hosts.buffer = None;
        self.services.buffer = None;
        self.metadata = None;
        self.answer = None;
    }
}
