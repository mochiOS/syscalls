//! Retain all acquisition/capture/work buffers in the callback resource owner.
//! Raw typed workspaces contain only borrowed ELF views, never resource owners.
use super::*;
use mochios_posix_client::pie::{
    Pie,
    link_scope::{Object, Scope},
};

#[derive(Default)]
struct Node {
    name: Buffer,
    source: Buffer,
    handle: u32,
}
impl Drop for Node {
    fn drop(&mut self) {
        if self.handle != 0 {
            let _delivery = defer_native_delivery();
            close_object_handle(self.handle);
        }
    }
}
#[derive(Default)]
pub(super) struct Dependencies {
    nodes: Buffer,
    images: Buffer,
    objects: Buffer,
    order: Buffer,
}
impl Drop for Dependencies {
    fn drop(&mut self) {
        // The initialized prefix owns each Node. Buffer growth moves its bits
        // without dropping the old allocation; no pointer to a Node escapes.
        for index in 0..self.count() {
            unsafe { ptr::drop_in_place(self.nodes.pointer.cast::<Node>().add(index)) };
        }
    }
}
impl Dependencies {
    fn count(&self) -> usize {
        self.nodes.length / core::mem::size_of::<Node>()
    }
    fn node(&self, index: usize) -> &Node {
        assert!(index < self.count());
        unsafe { &*self.nodes.pointer.cast::<Node>().add(index) }
    }
    fn node_mut(&mut self, index: usize) -> &mut Node {
        assert!(index < self.count());
        unsafe { &mut *self.nodes.pointer.cast::<Node>().add(index) }
    }
    fn append(&mut self, name: &[u8]) -> Result<usize, c_int> {
        let _delivery = defer_native_delivery();
        let index = self.count();
        let length = self
            .nodes
            .length
            .checked_add(core::mem::size_of::<Node>())
            .ok_or(ENOMEM)?;
        self.nodes.reserve(length)?;
        unsafe {
            self.nodes
                .pointer
                .cast::<Node>()
                .add(index)
                .write(Node::default())
        };
        self.nodes.length = length; // Publish ownership before any further allocation/RPC.
        let node = self.node_mut(index);
        node.name.reserve(name.len())?;
        unsafe { ptr::copy_nonoverlapping(name.as_ptr(), node.name.pointer, name.len()) };
        node.name.length = name.len();
        Ok(index)
    }
    fn open_path(&mut self, index: usize, path: &[u8]) -> Result<(), c_int> {
        let client = posix_client().map_err(map_posix_client_error)?;
        // DSOs require read permissions, not a POSIX executable mode bit.
        // Nonblocking open prevents a FIFO from hanging before fstat.
        let _delivery = defer_native_delivery();
        let file = client
            .open_at(
                if path.first() == Some(&b'/') {
                    OpenAtBase::ProcessRoot
                } else {
                    OpenAtBase::ProcessCwd
                },
                posix_protocol::OPEN_READ | posix_protocol::OPEN_NONBLOCK,
                0,
                path,
            )
            .map_err(map_posix_client_error)?;
        self.node_mut(index).handle = file.handle;
        if file.rights & posix_protocol::CHECK_EXECUTABLE_RIGHTS
            != posix_protocol::CHECK_EXECUTABLE_RIGHTS
        {
            return Err(EACCES);
        }
        let status = client.fstat(file).map_err(map_posix_client_error)?;
        if status.mode & 0o170000 != 0o100000 {
            return Err(ENOEXEC);
        }
        Ok(())
    }
    fn open(&mut self, index: usize) -> Result<(), c_int> {
        let name = self.node(index).name.bytes();
        if name.len() > posix_protocol::MAX_PATH_LEN {
            return Err(ENAMETOOLONG);
        }
        // Changing a Handle field does not move or mutate this owned name.
        let name = unsafe { core::slice::from_raw_parts(name.as_ptr(), name.len()) };
        if name.contains(&b'/') {
            return self.open_path(index, name);
        }
        let mut path = [0; posix_protocol::MAX_PATH_LEN];
        let mut permission_denied = false;
        for directory in mochios_posix_client::configuration::DEFAULT_SHARED_LIBRARY_PATH
            .split(|byte| *byte == b':')
        {
            let length = directory
                .len()
                .checked_add(1)
                .and_then(|n| n.checked_add(name.len()))
                .filter(|n| *n <= path.len())
                .ok_or(ENAMETOOLONG)?;
            path[..directory.len()].copy_from_slice(directory);
            path[directory.len()] = b'/';
            path[directory.len() + 1..length].copy_from_slice(name);
            match self.open_path(index, &path[..length]) {
                Ok(()) => return Ok(()),
                Err(ENOENT | ENOTDIR) if self.node(index).handle == 0 => {}
                Err(EACCES) if self.node(index).handle == 0 => permission_denied = true,
                Err(error) => return Err(error),
            }
        }
        Err(if permission_denied { EACCES } else { ENOENT })
    }
    fn capture(&mut self, index: usize, total: &mut usize) -> Result<(), c_int> {
        let mut chunk = [0; mnu_abi::provider::MAX_DATA_LEN];
        loop {
            let node = self.node_mut(index);
            let n = read_at(node.handle, &mut chunk, node.source.length)?;
            if n == 0 {
                break;
            }
            *total = total
                .checked_add(n)
                .filter(|total| *total <= MAX_IMAGE)
                .ok_or(EFBIG)?;
            let length = node.source.length.checked_add(n).ok_or(EFBIG)?;
            node.source.reserve(length)?;
            unsafe {
                ptr::copy_nonoverlapping(
                    chunk.as_ptr(),
                    node.source.pointer.add(node.source.length),
                    n,
                )
            };
            node.source.length = length;
        }
        let _delivery = defer_native_delivery();
        let node = self.node_mut(index);
        close_object_handle(node.handle);
        node.handle = 0;
        Ok(())
    }
    pub(super) fn build(
        &mut self,
        root: &[u8],
        output: &mut Buffer,
    ) -> Result<mochios_posix_client::process_image::Executable, c_int> {
        let mut total = root.len();
        let mut cursor = 0;
        loop {
            // Captured buffers never grow after parsing. Adding Nodes may move
            // Node records, but their independent source/name allocations stay
            // stable. All of them remain owned by the enclosing Preparation.
            let source = if cursor == 0 {
                root
            } else {
                self.node(cursor - 1).source.bytes()
            };
            let source = unsafe { core::slice::from_raw_parts(source.as_ptr(), source.len()) };
            let image = Pie::parse_object(source).map_err(|_| ENOEXEC)?;
            image.validate_direct_scope_startup().map_err(|_| ENOEXEC)?;
            let mut discovery_error = ENOEXEC;
            image
                .dependencies(|name| {
                    if !(0..self.count()).any(|i| self.node(i).name.bytes() == name) {
                        self.append(name).map_err(|error| {
                            discovery_error = error;
                            mochios_posix_client::pie::Error::Invalid
                        })?;
                    }
                    Ok(())
                })
                .map_err(|_| discovery_error)?;
            if cursor == self.count() {
                break;
            }
            self.open(cursor)?;
            self.capture(cursor, &mut total)?;
            cursor += 1;
        }
        let count = self.count().checked_add(1).ok_or(ENOMEM)?;
        // malloc provides alignment for these pointer/integer-only view types.
        // No view owns a resource or has Drop; the callback owner reclaims the
        // backing buffers even when a C handler abandons this frame.
        let images = self
            .images
            .slots::<core::mem::MaybeUninit<Pie<'_>>>(count)?;
        for index in 0..count {
            let bytes = if index == 0 {
                root
            } else {
                self.node(index - 1).source.bytes()
            };
            let image = Pie::parse_object(bytes).map_err(|_| ENOEXEC)?;
            unsafe { images.add(index).write(core::mem::MaybeUninit::new(image)) };
        }
        let images = unsafe { core::slice::from_raw_parts(images.cast::<Pie<'_>>(), count) };
        let objects = self
            .objects
            .slots::<core::mem::MaybeUninit<Object<'_, '_>>>(count)?;
        let mut entropy = [0u8; 8];
        if syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::RandomFill,
            entropy.as_mut_ptr() as u64,
            8,
        ))? != 8
        {
            return Err(EIO);
        }
        let mut address = 0x20000000
            + (u64::from_le_bytes(entropy) % (64 * 1024 * 1024 / PAGE_SIZE as u64))
                * PAGE_SIZE as u64;
        for (index, image) in images.iter().enumerate() {
            let (bias, end) = image.placement(address).map_err(|_| ENOEXEC)?;
            address = end;
            let name = if index == 0 {
                &[][..]
            } else {
                self.node(index - 1).name.bytes()
            };
            unsafe {
                objects
                    .add(index)
                    .write(core::mem::MaybeUninit::new(Object { name, image, bias }))
            };
        }
        let objects =
            unsafe { core::slice::from_raw_parts(objects.cast::<Object<'_, '_>>(), count) };
        let order = self.order.slots::<usize>(count)?;
        let order = unsafe { core::slice::from_raw_parts_mut(order, count) };
        let scope = Scope::new(objects, order).map_err(|_| ENOEXEC)?;
        let length = scope.bundle_length().map_err(|_| ENOEXEC)?;
        output.reserve(length)?;
        output.length = length;
        let bytes = unsafe { core::slice::from_raw_parts_mut(output.pointer, length) };
        if scope.write_bundle(bytes).map_err(|_| ENOEXEC)? != length {
            return Err(EIO);
        }
        images[0].executable(objects[0].bias).map_err(|_| ENOEXEC)
    }
}
