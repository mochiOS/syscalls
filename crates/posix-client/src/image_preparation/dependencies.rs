//! Retain all acquisition/capture/work buffers in the callback resource owner.
//! Raw typed workspaces contain only borrowed ELF views, never resource owners.
use super::*;
use mochios_posix_client::pie::{
    Pie,
    link_scope::{Object, Scope, Step},
};

#[derive(Clone, Copy, Default)]
struct Paths {
    rpath: Option<(usize, usize)>,
    runpath: Option<(usize, usize)>,
    no_default: bool,
}
impl Paths {
    fn capture(
        source: &[u8],
        paths: mochios_posix_client::pie::SearchPaths<'_>,
    ) -> Result<Self, c_int> {
        let span = |text: Option<&[u8]>| -> Result<Option<(usize, usize)>, c_int> {
            text.map(|text| {
                let offset = (text.as_ptr() as usize)
                    .checked_sub(source.as_ptr() as usize)
                    .ok_or(ENOEXEC)?;
                offset
                    .checked_add(text.len())
                    .filter(|end| *end <= source.len())
                    .ok_or(ENOEXEC)?;
                Ok((offset, text.len()))
            })
            .transpose()
        };
        Ok(Self {
            rpath: span(paths.rpath)?,
            runpath: span(paths.runpath)?,
            no_default: paths.no_default_library_path,
        })
    }
    fn view(self, source: &[u8]) -> Result<mochios_posix_client::pie::SearchPaths<'_>, c_int> {
        let text = |span: Option<(usize, usize)>| -> Result<Option<&[u8]>, c_int> {
            span.map(|(start, length)| {
                source
                    .get(start..start.checked_add(length).ok_or(ENOEXEC)?)
                    .ok_or(ENOEXEC)
            })
            .transpose()
        };
        Ok(mochios_posix_client::pie::SearchPaths {
            rpath: text(self.rpath)?,
            runpath: text(self.runpath)?,
            no_default_library_path: self.no_default,
        })
    }
}

struct Node<B: Backend> {
    name: Buffer<B>,
    path: Buffer<B>,
    source: Buffer<B>,
    handle: u32,
    parent: usize,
    paths: Paths,
}
impl<B: Backend> Default for Node<B> {
    fn default() -> Self {
        Self {
            name: Buffer::default(),
            path: Buffer::default(),
            source: Buffer::default(),
            handle: 0,
            parent: 0,
            paths: Paths::default(),
        }
    }
}
impl<B: Backend> Drop for Node<B> {
    fn drop(&mut self) {
        if self.handle != 0 {
            B::critical(|| B::close(self.handle));
        }
    }
}
pub(super) struct Dependencies<B: Backend> {
    nodes: Buffer<B>,
    images: Buffer<B>,
    objects: Buffer<B>,
    order: Buffer<B>,
    lifecycle_order: Buffer<B>,
    tls_templates: Buffer<B>,
    indirect_regions: Buffer<B>,
    indirect_fixups: Buffer<B>,
}
impl<B: Backend> Default for Dependencies<B> {
    fn default() -> Self {
        Self {
            nodes: Buffer::default(),
            images: Buffer::default(),
            objects: Buffer::default(),
            order: Buffer::default(),
            lifecycle_order: Buffer::default(),
            tls_templates: Buffer::default(),
            indirect_regions: Buffer::default(),
            indirect_fixups: Buffer::default(),
        }
    }
}
impl<B: Backend> Drop for Dependencies<B> {
    fn drop(&mut self) {
        // The initialized prefix owns each Node. Buffer growth moves its bits
        // without dropping the old allocation; no pointer to a Node escapes.
        for index in 0..self.count() {
            unsafe { ptr::drop_in_place(self.nodes.pointer.cast::<Node<B>>().add(index)) };
        }
    }
}
impl<B: Backend> Dependencies<B> {
    fn count(&self) -> usize {
        self.nodes.length / core::mem::size_of::<Node<B>>()
    }
    fn node(&self, index: usize) -> &Node<B> {
        assert!(index < self.count());
        unsafe { &*self.nodes.pointer.cast::<Node<B>>().add(index) }
    }
    fn node_mut(&mut self, index: usize) -> &mut Node<B> {
        assert!(index < self.count());
        unsafe { &mut *self.nodes.pointer.cast::<Node<B>>().add(index) }
    }
    fn append(&mut self, name: &[u8], parent: usize) -> Result<usize, c_int> {
        B::critical(|| {
            let index = self.count();
            let length = self
                .nodes
                .length
                .checked_add(core::mem::size_of::<Node<B>>())
                .ok_or(ENOMEM)?;
            self.nodes.reserve(length)?;
            unsafe {
                self.nodes
                    .pointer
                    .cast::<Node<B>>()
                    .add(index)
                    .write(Node::default())
            };
            self.nodes.length = length; // Publish ownership before any further allocation/RPC.
            let node = self.node_mut(index);
            node.parent = parent;
            node.name.reserve(name.len())?;
            unsafe { ptr::copy_nonoverlapping(name.as_ptr(), node.name.pointer, name.len()) };
            node.name.length = name.len();
            Ok(index)
        })
    }
    fn open_path(&mut self, backend: &B, index: usize, path: &[u8]) -> Result<(), c_int> {
        B::critical(|| {
            self.node_mut(index).path.reserve(path.len())?;
            let file = backend.open_library(path)?;
            self.node_mut(index).handle = file.handle;
            if file.handle == 0
                || file.rights & posix_protocol::CHECK_EXECUTABLE_RIGHTS
                    != posix_protocol::CHECK_EXECUTABLE_RIGHTS
            {
                return Err(EACCES);
            }
            backend.validate_library(file)?;
            let selected = &mut self.node_mut(index).path;
            unsafe { ptr::copy_nonoverlapping(path.as_ptr(), selected.pointer, path.len()) };
            selected.length = path.len();
            Ok(())
        })
    }
    fn source<'a>(&'a self, root: &'a [u8], index: usize) -> &'a [u8] {
        if index == 0 {
            root
        } else {
            self.node(index - 1).source.bytes()
        }
    }
    fn search_list(
        &mut self,
        backend: &B,
        index: usize,
        list: &[u8],
        environment: bool,
        denied: &mut bool,
    ) -> Result<bool, c_int> {
        if list.is_empty() {
            return Ok(false);
        }
        // Tokens require origin/platform metadata. Never interpret an unsupported
        // expansion as a literal path or substitute the caller's pathname.
        if list.contains(&b'$') {
            return Err(ENOEXEC);
        }
        let name = self.node(index).name.bytes();
        // This immutable allocation stays stable as Handle fields change.
        let name = unsafe { core::slice::from_raw_parts(name.as_ptr(), name.len()) };
        let mut candidate = [0; posix_protocol::MAX_PATH_LEN];
        for directory in list.split(|byte| *byte == b':' || (environment && *byte == b';')) {
            let prefix = if directory.is_empty() {
                0
            } else {
                directory.len().checked_add(1).ok_or(ENAMETOOLONG)?
            };
            let length = prefix
                .checked_add(name.len())
                .filter(|length| *length <= candidate.len())
                .ok_or(ENAMETOOLONG)?;
            if prefix != 0 {
                candidate[..directory.len()].copy_from_slice(directory);
                candidate[directory.len()] = b'/';
            }
            candidate[prefix..length].copy_from_slice(name);
            match self.open_path(backend, index, &candidate[..length]) {
                Ok(()) => return Ok(true),
                Err(ENOENT | ENOTDIR) if self.node(index).handle == 0 => {}
                Err(EACCES) if self.node(index).handle == 0 => *denied = true,
                Err(error) => return Err(error),
            }
        }
        Ok(false)
    }
    fn open(
        &mut self,
        backend: &B,
        index: usize,
        root: &[u8],
        environment: Option<&[u8]>,
        root_paths: Paths,
    ) -> Result<(), c_int> {
        let name = self.node(index).name.bytes();
        if name.len() > posix_protocol::MAX_PATH_LEN {
            return Err(ENAMETOOLONG);
        }
        if name.contains(&b'$') {
            return Err(ENOEXEC);
        }
        let name = unsafe { core::slice::from_raw_parts(name.as_ptr(), name.len()) };
        if name.contains(&b'/') {
            return self.open_path(backend, index, name);
        }
        let requester = self.node(index).parent;
        let bytes = self.source(root, requester);
        // Captured source allocations are immutable. Only the unopened node's
        // Handle changes during search; no source buffer grows here.
        let bytes = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), bytes.len()) };
        let fields = if requester == 0 {
            root_paths
        } else {
            self.node(requester - 1).paths
        };
        let paths = fields.view(bytes)?;
        let mut denied = false;
        if paths.runpath.is_none() {
            let mut parent = requester;
            loop {
                let bytes = self.source(root, parent);
                let bytes = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), bytes.len()) };
                let fields = if parent == 0 {
                    root_paths
                } else {
                    self.node(parent - 1).paths
                };
                let paths = fields.view(bytes)?;
                if paths.runpath.is_none() {
                    if let Some(list) = paths.rpath {
                        if self.search_list(backend, index, list, false, &mut denied)? {
                            return Ok(());
                        }
                    }
                }
                if parent == 0 {
                    break;
                }
                let next = self.node(parent - 1).parent;
                if next >= parent {
                    return Err(ENOEXEC);
                }
                parent = next;
            }
        }
        if let Some(list) = environment {
            if self.search_list(backend, index, list, true, &mut denied)? {
                return Ok(());
            }
        }
        if let Some(list) = paths.runpath {
            if self.search_list(backend, index, list, false, &mut denied)? {
                return Ok(());
            }
        }
        if !paths.no_default_library_path
            && self.search_list(
                backend,
                index,
                mochios_posix_client::configuration::DEFAULT_SHARED_LIBRARY_PATH,
                false,
                &mut denied,
            )?
        {
            return Ok(());
        }
        Err(if denied { EACCES } else { ENOENT })
    }
    fn capture(&mut self, backend: &B, index: usize, total: &mut usize) -> Result<(), c_int> {
        let mut chunk = [0; mnu_abi::provider::MAX_DATA_LEN];
        loop {
            let node = self.node_mut(index);
            let n = read_at(backend, node.handle, &mut chunk, node.source.length)?;
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
        let node = self.node(index);
        backend.validate_captured(
            Source::Dependency {
                needed: node.name.bytes(),
                path: node.path.bytes(),
            },
            node.source.bytes(),
        )?;
        B::critical(|| {
            let node = self.node_mut(index);
            B::close(node.handle);
            node.handle = 0;
        });
        Ok(())
    }
    pub(super) fn build(
        &mut self,
        root: &[u8],
        output: &mut Buffer<B>,
        lifecycle: &mut Buffer<B>,
        tls: &mut Buffer<B>,
        indirect: &mut Buffer<B>,
        backend: &B,
        variables: Environment<'_>,
        identity: mochios_posix_client::process_image::Identity,
        runtime: bool,
    ) -> Result<mochios_posix_client::process_image::Executable, c_int> {
        let path = variables.library_path.filter(|value| !value.is_empty());
        let preload = variables.preload.filter(|value| !value.is_empty());
        let audit = variables.audit.filter(|value| !value.is_empty());
        let environment = if identity.is_secure() {
            None
        } else {
            if preload.is_some() || audit.is_some() {
                return Err(ENOEXEC);
            }
            path
        };
        let mut total = root.len();
        let mut cursor = 0;
        let mut root_paths = Paths::default();
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
            if !runtime {
                image.validate_direct_scope_startup().map_err(|_| ENOEXEC)?;
            }
            let paths = Paths::capture(source, image.search_paths().map_err(|_| ENOEXEC)?)?;
            if cursor == 0 {
                root_paths = paths;
            } else {
                self.node_mut(cursor - 1).paths = paths;
            }
            let mut discovery_error = ENOEXEC;
            image
                .dependencies(|name| {
                    if !(0..self.count()).any(|i| self.node(i).name.bytes() == name) {
                        self.append(name, cursor).map_err(|error| {
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
            self.open(backend, cursor, root, environment, root_paths)?;
            self.capture(backend, cursor, &mut total)?;
            cursor += 1;
        }
        let count = self.count().checked_add(1).ok_or(ENOMEM)?;
        // Backend storage provides alignment for these pointer/integer views.
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
        backend.entropy(&mut entropy)?;
        let mut address = 0x20000000
            + (u64::from_le_bytes(entropy) % (64 * 1024 * 1024 / PAGE_SIZE as u64))
                * PAGE_SIZE as u64;
        for (index, image) in images.iter().enumerate() {
            let (bias, end) = image.placement(address).map_err(|_| ENOEXEC)?;
            address = address.max(end);
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
        let (region_count, fixup_count) = scope.deferred_counts().map_err(|_| ENOEXEC)?;
        if fixup_count != 0 && !images[0].has_indirect_runtime().map_err(|_| ENOEXEC)? {
            return Err(ENOEXEC);
        }
        let indirect_length = if fixup_count != 0 {
            let size = crate::indirect_image::encoded_length(region_count, fixup_count)
                .map_err(|_| E2BIG)?;
            if size > mnu_abi::process_image::MAX_STACK_BYTES {
                return Err(E2BIG);
            }
            size
        } else {
            0
        };
        let templates = self
            .tls_templates
            .slots::<Option<mochios_posix_client::static_tls::Template>>(count)?;
        for (index, object) in objects.iter().enumerate() {
            let template = object
                .image
                .tls_template(object.bias)
                .map_err(|_| ENOEXEC)?;
            unsafe { templates.add(index).write(template) };
        }
        let templates = unsafe { core::slice::from_raw_parts(templates, count) };
        let tls_runtime = images[0].has_static_tls_runtime().map_err(|_| ENOEXEC)?;
        if templates[1..].iter().any(Option::is_some) && !tls_runtime {
            return Err(ENOEXEC);
        }
        if tls_runtime && templates.iter().any(Option::is_some) {
            use mochios_posix_client::static_tls::image;
            let length = image::encoded_length(count).ok_or(E2BIG)?;
            if length > mnu_abi::process_image::MAX_STACK_BYTES {
                return Err(E2BIG);
            }
            tls.reserve(length)?;
            let payload = unsafe { core::slice::from_raw_parts_mut(tls.pointer, length) };
            image::encode(templates, payload).map_err(|_| ENOEXEC)?;
            tls.length = length;
        }
        let length = scope.bundle_length().map_err(|_| ENOEXEC)?;
        output.reserve(length)?;
        output.length = length;
        let bytes = unsafe { core::slice::from_raw_parts_mut(output.pointer, length) };
        let words = scope.lifecycle_scratch_len().map_err(|_| ENOEXEC)?;
        let scratch = self.lifecycle_order.slots::<usize>(words)?;
        let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, words) };
        let written = if fixup_count != 0 {
            use crate::indirect_image::{Fixup, Region};
            let regions = self.indirect_regions.slots::<Region>(region_count)?;
            let fixups = self.indirect_fixups.slots::<Fixup>(fixup_count)?;
            for i in 0..region_count {
                unsafe { regions.add(i).write(Region::EMPTY) };
            }
            for i in 0..fixup_count {
                unsafe { fixups.add(i).write(Fixup::EMPTY) };
            }
            let regions = unsafe { core::slice::from_raw_parts_mut(regions, region_count) };
            let fixups = unsafe { core::slice::from_raw_parts_mut(fixups, fixup_count) };
            let mut pending = scope.deferred(regions, fixups, scratch).map_err(|_| ENOEXEC)?;
            let size = pending.encoded_length().map_err(|_| ENOEXEC)?;
            if size != indirect_length {
                return Err(EIO);
            }
            indirect.reserve(size)?;
            let payload = unsafe { core::slice::from_raw_parts_mut(indirect.pointer, size) };
            if pending.encode(payload).map_err(|_| ENOEXEC)? != size {
                return Err(EIO);
            }
            indirect.length = size;
            pending.write_bundle(bytes).map_err(|_| ENOEXEC)?
        } else {
            scope.write_bundle(bytes).map_err(|_| ENOEXEC)?
        };
        if written != length {
            return Err(EIO);
        }
        let plan = scope.lifecycle(scratch).map_err(|_| ENOEXEC)?;
        if fixup_count != 0 {
            // This initialized workspace was just validated by pending.encode.
            // Never flatten an array element whose future value is deferred,
            // even if its original bytes happen to name valid executable code.
            let fixups = unsafe {
                core::slice::from_raw_parts(
                    self.indirect_fixups
                        .pointer
                        .cast::<crate::indirect_image::Fixup>(),
                    fixup_count,
                )
            };
            let mut late = false;
            let mut inspect = |step| {
                if let Step::Array { address, count, .. } = step {
                    match count
                        .checked_mul(8)
                        .and_then(|size| address.checked_add(size))
                    {
                        Some(end) => {
                            late |= fixups
                                .iter()
                                .any(|f| f.target() < end && address < f.target() + 8)
                        }
                        None => late = true,
                    }
                }
            };
            plan.initializers(&mut inspect).map_err(|_| ENOEXEC)?;
            plan.finalizers(&mut inspect).map_err(|_| ENOEXEC)?;
            if late {
                return Err(ENOEXEC);
            }
        }
        let plan_length = plan.encoded_length().map_err(|_| ENOEXEC)?;
        if plan_length > mnu_abi::process_image::MAX_STACK_BYTES {
            return Err(E2BIG);
        }
        if plan_length != 0 {
            if !runtime {
                return Err(ENOEXEC);
            }
            lifecycle.reserve(plan_length)?;
            let payload =
                unsafe { core::slice::from_raw_parts_mut(lifecycle.pointer, plan_length) };
            plan.encode_prepared(bytes, payload).map_err(|_| ENOEXEC)?;
            lifecycle.length = plan_length;
        }
        images[0].executable(objects[0].bias).map_err(|_| ENOEXEC)
    }
}
