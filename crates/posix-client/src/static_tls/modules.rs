//! Initial static TLS modules, in root-first object order. No allocation,
//! path lookup, native VM operations or ELF symbol resolution happens here.
use super::{Layout, Template, distance_after};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module {
    /// Object index, including objects without a TLS segment in the numbering.
    pub index: usize,
    pub template: Template,
    /// Positive distance from the thread pointer to this module's first byte.
    pub distance: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitializeError<E> {
    InvalidMapping,
    Read(E),
    Write(E),
}

pub struct Plan<'a> {
    templates: &'a [Option<Template>],
    layout: Layout,
}

impl<'a> Plan<'a> {
    /// Absent TLS segments retain their object index without consuming space.
    /// The root must precede dependencies so local-exec offsets stay unchanged.
    pub fn new(templates: &'a [Option<Template>], page_size: usize) -> Option<Self> {
        let mut distance = 0;
        let mut alignment = 1;
        for template in templates.iter().flatten() {
            template.source.checked_add(template.file_size)?;
            distance = distance_after(distance, *template)?;
            alignment = alignment.max(template.alignment);
        }
        Some(Self {
            templates,
            layout: Layout::from_extent(distance, alignment, page_size)?,
        })
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    pub fn modules(&self) -> impl Iterator<Item = Module> + '_ {
        let mut distance = 0;
        self.templates
            .iter()
            .enumerate()
            .filter_map(move |(index, template)| {
                let template = (*template)?;
                // Plan construction validated the same immutable templates and
                // cumulative arithmetic. A missing segment changes no offsets.
                distance = distance_after(distance, template)?;
                Some(Module {
                    index,
                    template,
                    distance,
                })
            })
    }

    /// Copy templates into a newly allocated, zero-filled private mapping.
    /// The caller owns admission, rollback and publishing the returned TP.
    /// No TCB is installed until every module copy succeeds. .tbss and padding
    /// remain zero, including when the template has no initialized bytes.
    pub fn initialize_zeroed<E>(
        &self,
        base: usize,
        size: usize,
        mut read: impl FnMut(usize, &mut [u8]) -> Result<(), E>,
        mut write: impl FnMut(usize, &[u8]) -> Result<(), E>,
    ) -> Result<usize, InitializeError<E>> {
        if size < self.layout.mapping_size || base.checked_add(size).is_none() {
            return Err(InitializeError::InvalidMapping);
        }
        let placed = self
            .layout
            .place(base)
            .ok_or(InitializeError::InvalidMapping)?;
        let mut bytes = [0u8; 512];
        for module in self.modules() {
            // These subtractions and extents are validated by Plan and place.
            let destination = placed.thread_pointer - module.distance;
            let mut offset = 0;
            while offset < module.template.file_size {
                let size = bytes.len().min(module.template.file_size - offset);
                read(module.template.source + offset, &mut bytes[..size])
                    .map_err(InitializeError::Read)?;
                write(destination + offset, &bytes[..size]).map_err(InitializeError::Write)?;
                offset += size;
            }
        }
        write(placed.thread_pointer, &placed.thread_pointer.to_ne_bytes())
            .map_err(InitializeError::Write)?;
        Ok(placed.thread_pointer)
    }
}
