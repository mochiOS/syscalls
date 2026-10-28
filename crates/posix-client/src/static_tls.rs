//! ELF static TLS policy for x86-64 (Variant II). No kernel TLS ABI is involved.

#[path = "static_tls/modules.rs"]
pub mod modules;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error<E> {
    InvalidImage,
    Read(E),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Template {
    pub source: usize,
    pub file_size: usize,
    pub memory_size: usize,
    pub alignment: usize,
    pub residue: usize,
}

#[derive(Clone, Copy)]
struct Header {
    kind: u32,
    offset: usize,
    address: usize,
    file_size: usize,
    memory_size: usize,
    alignment: usize,
}

impl Header {
    fn read<E>(
        address: usize,
        read: &mut impl FnMut(usize, &mut [u8]) -> Result<(), E>,
    ) -> Result<Self, Error<E>> {
        let mut bytes = [0u8; 56];
        read(address, &mut bytes).map_err(Error::Read)?;
        let word = |offset| {
            usize::try_from(u64::from_le_bytes(
                bytes[offset..offset + 8].try_into().unwrap(),
            ))
            .map_err(|_| Error::InvalidImage)
        };
        Ok(Self {
            kind: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            offset: word(8)?,
            address: word(16)?,
            file_size: word(32)?,
            memory_size: word(40)?,
            alignment: word(48)?,
        })
    }
}

/// Read the ELF64 program header table supplied by the loader. Stride padding
/// is permitted; the entire table and all address arithmetic must be bounded.
/// `bias` is the image relocation bias, zero for an ET_EXEC executable.
pub fn template<E>(
    table: usize,
    stride: usize,
    count: usize,
    bias: usize,
    mut read: impl FnMut(usize, &mut [u8]) -> Result<(), E>,
) -> Result<Option<Template>, Error<E>> {
    if table == 0
        || !(56..=u16::MAX as usize).contains(&stride)
        || count == 0
        || count > u16::MAX as usize
    {
        return Err(Error::InvalidImage);
    }
    table
        .checked_add(stride.checked_mul(count).ok_or(Error::InvalidImage)?)
        .ok_or(Error::InvalidImage)?;
    let mut tls = None;
    for index in 0..count {
        let header = Header::read(table + index * stride, &mut read)?;
        if header.kind != 7 {
            continue;
        }
        if tls.is_some() || header.file_size > header.memory_size {
            return Err(Error::InvalidImage);
        }
        let alignment = header.alignment.max(1);
        if !alignment.is_power_of_two() {
            return Err(Error::InvalidImage);
        }
        header
            .offset
            .checked_add(header.file_size)
            .ok_or(Error::InvalidImage)?;
        header
            .address
            .checked_add(header.memory_size)
            .ok_or(Error::InvalidImage)?;
        let source = header
            .address
            .checked_add(bias)
            .ok_or(Error::InvalidImage)?;
        source
            .checked_add(header.memory_size)
            .ok_or(Error::InvalidImage)?;
        tls = Some((
            header,
            Template {
                source,
                file_size: header.file_size,
                memory_size: header.memory_size,
                alignment,
                residue: header.address & (alignment - 1),
            },
        ));
    }
    let Some((header, result)) = tls else {
        return Ok(None);
    };
    // .tbss is not necessarily part of a PT_LOAD mapping. Only the bytes
    // copied from the file must lie in a matching file-backed LOAD segment.
    if result.file_size != 0 {
        let mut covered = false;
        for index in 0..count {
            let load = Header::read(table + index * stride, &mut read)?;
            if load.kind != 1 || load.file_size > load.memory_size {
                continue;
            }
            let end = load
                .address
                .checked_add(load.file_size)
                .ok_or(Error::InvalidImage)?;
            load.offset
                .checked_add(load.file_size)
                .ok_or(Error::InvalidImage)?;
            if header.address >= load.address
                && header.address + header.file_size <= end
                && load.offset.checked_add(header.address - load.address) == Some(header.offset)
            {
                covered = true;
                break;
            }
        }
        if !covered {
            return Err(Error::InvalidImage);
        }
    }
    Ok(Some(result))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub mapping_size: usize,
    pub alignment: usize,
    pub distance: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub data: usize,
    pub thread_pointer: usize,
}

impl Layout {
    /// The first TCB word is its own address, as expected by x86-64 codegen.
    /// Match lld/ELF/InputSection.cpp:getTlsTpOffset, including p_vaddr residue.
    pub fn new(template: Option<Template>, page_size: usize) -> Option<Self> {
        let (distance, alignment) = match template {
            Some(t) => (distance_after(0, t)?, t.alignment),
            None => (0, 1),
        };
        Self::from_extent(distance, alignment, page_size)
    }

    fn from_extent(distance: usize, alignment: usize, page_size: usize) -> Option<Self> {
        if !page_size.is_power_of_two() || !alignment.is_power_of_two() {
            return None;
        }
        let alignment = alignment.max(core::mem::size_of::<usize>());
        let size = distance
            .checked_add(alignment - 1)?
            .checked_add(core::mem::size_of::<usize>())?;
        let mapping_size = size.checked_add(page_size - 1)? & !(page_size - 1);
        Some(Self {
            mapping_size,
            alignment,
            distance,
        })
    }

    pub fn place(self, base: usize) -> Option<Placement> {
        let end = base.checked_add(self.mapping_size)?;
        let thread_pointer = base
            .checked_add(self.distance)?
            .checked_add(self.alignment - 1)?
            & !(self.alignment - 1);
        if thread_pointer.checked_add(core::mem::size_of::<usize>())? > end {
            return None;
        }
        Some(Placement {
            data: thread_pointer.checked_sub(self.distance)?,
            thread_pointer,
        })
    }
}

// Place the next module before all preceding blocks, preserving the root's
// linker-computed TP offset even when dependencies require stronger alignment.
fn distance_after(preceding: usize, template: Template) -> Option<usize> {
    if !template.alignment.is_power_of_two()
        || template.residue >= template.alignment
        || template.file_size > template.memory_size
    {
        return None;
    }
    let end = preceding.checked_add(template.memory_size)?;
    let padding = template.residue.wrapping_add(end).wrapping_neg() & (template.alignment - 1);
    end.checked_add(padding)
}
