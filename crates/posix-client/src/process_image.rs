use mnu_abi::process_image::{self, Relocation, RelocationKind};

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;
const AUXILIARY_VECTOR_ENTRIES: usize = 18;
pub const AT_RESOURCE_POLICY: u64 = 0x6d00_0001;
pub const AT_UPCALL_STACK: u64 = 0x6d00_0002;
pub const AT_INITIAL_HEAP: u64 = 0x6d00_0003;
/// Bias of the program described by AT_PHDR. AT_BASE remains the interpreter's
/// base. This userspace-owned entry is opaque data to the native kernel.
pub const AT_IMAGE_LOAD_BIAS: u64 = 0x6d00_0004;
/// Userspace lifecycle codec embedded in the initial stack; opaque to mnu.
pub const AT_LIFECYCLE_IMAGE: u64 = 0x6d00_0005;
/// Userspace TLS templates for the complete initial object set; opaque to mnu.
pub const AT_TLS_IMAGE: u64 = 0x6d00_0006;
/// Deferred userspace resolver plan; the native kernel only relocates its
/// stack address and never interprets its ELF-specific contents.
pub const AT_INDIRECT_IMAGE: u64 = 0x6d00_0007;
pub const INITIAL_HEAP_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    EmptyArgumentVector,
    InvalidText,
    ImageTooLarge,
    Codec(process_image::Error),
}

fn checked_text_size(values: &[&[u8]]) -> Result<usize, EncodeError> {
    values.iter().try_fold(0usize, |total, value| {
        if value.contains(&0) {
            return Err(EncodeError::InvalidText);
        }
        total
            .checked_add(value.len())
            .and_then(|size| size.checked_add(1))
            .ok_or(EncodeError::ImageTooLarge)
    })
}

fn put_word(stack: &mut [u8], cursor: &mut usize, value: u64) -> Result<u32, EncodeError> {
    let offset = *cursor;
    let end = offset.checked_add(8).ok_or(EncodeError::ImageTooLarge)?;
    stack
        .get_mut(offset..end)
        .ok_or(EncodeError::ImageTooLarge)?
        .copy_from_slice(&value.to_le_bytes());
    *cursor = end;
    u32::try_from(offset).map_err(|_| EncodeError::ImageTooLarge)
}

fn push_relocation(
    relocations: &mut [Relocation],
    count: &mut usize,
    offset: u32,
    kind: RelocationKind,
) -> Result<(), EncodeError> {
    let destination = relocations
        .get_mut(*count)
        .ok_or(EncodeError::ImageTooLarge)?;
    *destination = Relocation { offset, kind };
    *count += 1;
    Ok(())
}

fn put_relocated_word(
    stack: &mut [u8],
    cursor: &mut usize,
    relocations: &mut [Relocation],
    relocation_count: &mut usize,
    value: u64,
    kind: RelocationKind,
) -> Result<(), EncodeError> {
    let offset = put_word(stack, cursor, value)?;
    push_relocation(relocations, relocation_count, offset, kind)
}

fn copy_text(stack: &mut [u8], cursor: &mut usize, value: &[u8]) -> Result<u64, EncodeError> {
    let offset = *cursor;
    let end = offset
        .checked_add(value.len())
        .and_then(|end| end.checked_add(1))
        .ok_or(EncodeError::ImageTooLarge)?;
    let destination = stack
        .get_mut(offset..end)
        .ok_or(EncodeError::ImageTooLarge)?;
    destination[..value.len()].copy_from_slice(value);
    destination[value.len()] = 0;
    *cursor = end;
    u64::try_from(offset).map_err(|_| EncodeError::ImageTooLarge)
}

/// Encodes a System V process-entry stack as an mnu relocatable startup image.
///
/// All POSIX vector construction happens here in user space. The kernel only
/// receives bytes and generic loader relocations; it never sees argv or envp.
pub fn encode_initial_stack(
    argv: &[&[u8]],
    envp: &[&[u8]],
    execfn: &[u8],
    random: [u8; 16],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    encode_initial_stack_with_aux(argv, envp, execfn, random, &[], output)
}

/// Program metadata selected by a userspace loader. The native ELF container
/// may be a prepared image and need not be the program described to the ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Executable {
    pub entry: u64,
    pub program_headers: u64,
    pub program_header_size: u64,
    pub program_header_count: u64,
    pub interpreter_base: u64,
    pub load_bias: u64,
}

pub fn encode_initial_stack_with_aux(
    argv: &[&[u8]],
    envp: &[&[u8]],
    execfn: &[u8],
    random: [u8; 16],
    auxiliary: &[(u64, u64)],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    encode_initial_stack_for_image(argv, envp, execfn, random, auxiliary, None, output)
}

pub fn encode_initial_stack_for_image(
    argv: &[&[u8]],
    envp: &[&[u8]],
    execfn: &[u8],
    random: [u8; 16],
    auxiliary: &[(u64, u64)],
    image: Option<Executable>,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    encode_initial_stack_for_process(
        argv,
        envp,
        execfn,
        random,
        auxiliary,
        Process {
            image,
            identity: Identity::default(),
            lifecycle: &[],
            tls: &[],
            indirect: &[],
        },
        output,
    )
}

/// POSIX process-entry metadata. This data is opaque to the native kernel and
/// must never be used by a service as a substitute for authenticated identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    pub real_uid: u32,
    pub effective_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
}
impl From<mochios_posix_protocol::SessionInfo> for Identity {
    fn from(session: mochios_posix_protocol::SessionInfo) -> Self {
        Self {
            real_uid: session.real_uid,
            effective_uid: session.effective_uid,
            real_gid: session.real_gid,
            effective_gid: session.effective_gid,
        }
    }
}
impl Identity {
    pub fn is_secure(self) -> bool {
        self.real_uid != self.effective_uid || self.real_gid != self.effective_gid
    }
    /// Remove the environment controls consumed by this loader when identity
    /// differs. Other runtime-specific secure-environment policy is separate.
    pub fn allows_environment(self, entry: &[u8]) -> bool {
        !self.is_secure()
            || ![b"LD_LIBRARY_PATH".as_slice(), b"LD_PRELOAD", b"LD_AUDIT"]
                .iter()
                .any(|name| {
                    entry
                        .strip_prefix(*name)
                        .is_some_and(|tail| tail.starts_with(b"="))
                })
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Process<'a> {
    pub image: Option<Executable>,
    pub identity: Identity,
    pub lifecycle: &'a [u8],
    pub tls: &'a [u8],
    pub indirect: &'a [u8],
}

pub fn encode_initial_stack_for_process(
    argv: &[&[u8]],
    envp: &[&[u8]],
    execfn: &[u8],
    random: [u8; 16],
    auxiliary: &[(u64, u64)],
    process: Process<'_>,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    encode_process(argv, envp, execfn, random, auxiliary, process, None, output)
}

pub fn encode_initial_stack_with_metadata(
    argv: &[&[u8]],
    envp: &[&[u8]],
    execfn: &[u8],
    random: [u8; 16],
    auxiliary: &[(u64, u64)],
    process: Process<'_>,
    mapped: crate::startup_metadata::Layout,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    if !mapped.matches(process) {
        return Err(EncodeError::InvalidText);
    }
    encode_process(
        argv, envp, execfn, random, auxiliary, process, Some(mapped), output,
    )
}

fn encode_process(
    argv: &[&[u8]],
    envp: &[&[u8]],
    execfn: &[u8],
    random: [u8; 16],
    auxiliary: &[(u64, u64)],
    process: Process<'_>,
    mapped: Option<crate::startup_metadata::Layout>,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    let image = process.image;
    for (index, &(key, _)) in auxiliary.iter().enumerate() {
        if key <= AT_EXECFN
            || key == AT_IMAGE_LOAD_BIAS
            || key == AT_LIFECYCLE_IMAGE
            || key == AT_TLS_IMAGE
            || key == AT_INDIRECT_IMAGE
            || auxiliary[..index].iter().any(|&(other, _)| other == key)
        {
            return Err(EncodeError::InvalidText);
        }
    }
    if argv.is_empty() {
        return Err(EncodeError::EmptyArgumentVector);
    }
    if execfn.contains(&0) {
        return Err(EncodeError::InvalidText);
    }
    let argument_bytes = checked_text_size(argv)?;
    let mut environment_count = 0;
    let mut environment_bytes = 0usize;
    for entry in envp {
        if entry.contains(&0) {
            return Err(EncodeError::InvalidText);
        }
        if process.identity.allows_environment(entry) {
            environment_count += 1;
            environment_bytes = environment_bytes
                .checked_add(entry.len())
                .and_then(|bytes| bytes.checked_add(1))
                .ok_or(EncodeError::ImageTooLarge)?;
        }
    }
    let pointer_words = 1usize
        .checked_add(argv.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(environment_count))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| {
            auxiliary
                .len()
                .checked_add(AUXILIARY_VECTOR_ENTRIES)
                .and_then(|count| count.checked_add(usize::from(!process.lifecycle.is_empty())))
                .and_then(|count| count.checked_add(usize::from(!process.tls.is_empty())))
                .and_then(|count| count.checked_add(usize::from(!process.indirect.is_empty())))
                .and_then(|count| count.checked_mul(2))
                .and_then(|count| value.checked_add(count))
        })
        .ok_or(EncodeError::ImageTooLarge)?;
    let pointer_bytes = pointer_words
        .checked_mul(8)
        .ok_or(EncodeError::ImageTooLarge)?;
    let unaligned_length = pointer_bytes
        .checked_add(argument_bytes)
        .and_then(|value| value.checked_add(environment_bytes))
        .and_then(|value| value.checked_add(random.len()))
        .and_then(|value| value.checked_add(execfn.len()))
        .and_then(|value| value.checked_add(1))
        .ok_or(EncodeError::ImageTooLarge)?;
    let lifecycle_offset = unaligned_length
        .checked_add(7)
        .map(|value| value & !7)
        .ok_or(EncodeError::ImageTooLarge)?;
    let lifecycle_end = if process.lifecycle.is_empty() || mapped.is_some() {
        unaligned_length
    } else {
        lifecycle_offset
            .checked_add(process.lifecycle.len())
            .ok_or(EncodeError::ImageTooLarge)?
    };
    let tls_offset = lifecycle_end
        .checked_add(7)
        .map(|value| value & !7)
        .ok_or(EncodeError::ImageTooLarge)?;
    let tls_end = if process.tls.is_empty() || mapped.is_some() {
        lifecycle_end
    } else {
        tls_offset
            .checked_add(process.tls.len())
            .ok_or(EncodeError::ImageTooLarge)?
    };
    let indirect_offset = tls_end
        .checked_add(7)
        .map(|value| value & !7)
        .ok_or(EncodeError::ImageTooLarge)?;
    let payload_length = if process.indirect.is_empty() || mapped.is_some() {
        tls_end
    } else {
        indirect_offset
            .checked_add(process.indirect.len())
            .ok_or(EncodeError::ImageTooLarge)?
    };
    let stack_length = payload_length
        .checked_add(15)
        .map(|value| value & !15)
        .ok_or(EncodeError::ImageTooLarge)?;
    if stack_length > process_image::MAX_STACK_BYTES {
        return Err(EncodeError::ImageTooLarge);
    }

    let mut stack = [0u8; process_image::MAX_STACK_BYTES];
    let mut relocations = [Relocation {
        offset: 0,
        kind: RelocationKind::StackAddress,
    }; process_image::MAX_RELOCATIONS];
    let mut relocation_count = 0usize;
    let mut cursor = 0usize;
    put_word(&mut stack, &mut cursor, argv.len() as u64)?;

    let mut text_cursor = pointer_bytes;
    for argument in argv {
        let offset = copy_text(&mut stack, &mut text_cursor, argument)?;
        put_relocated_word(
            &mut stack,
            &mut cursor,
            &mut relocations,
            &mut relocation_count,
            offset,
            RelocationKind::StackAddress,
        )?;
    }
    put_word(&mut stack, &mut cursor, 0)?;
    for environment in envp
        .iter()
        .filter(|entry| process.identity.allows_environment(entry))
    {
        let offset = copy_text(&mut stack, &mut text_cursor, environment)?;
        put_relocated_word(
            &mut stack,
            &mut cursor,
            &mut relocations,
            &mut relocation_count,
            offset,
            RelocationKind::StackAddress,
        )?;
    }
    put_word(&mut stack, &mut cursor, 0)?;

    let random_offset = text_cursor;
    stack[random_offset..random_offset + random.len()].copy_from_slice(&random);
    text_cursor += random.len();
    let execfn_offset = copy_text(&mut stack, &mut text_cursor, execfn)?;
    if !process.lifecycle.is_empty() && mapped.is_none() {
        stack[lifecycle_offset..lifecycle_offset + process.lifecycle.len()]
            .copy_from_slice(process.lifecycle);
    }
    if !process.tls.is_empty() && mapped.is_none() {
        stack[tls_offset..tls_offset + process.tls.len()].copy_from_slice(process.tls);
    }
    if !process.indirect.is_empty() && mapped.is_none() {
        stack[indirect_offset..indirect_offset + process.indirect.len()]
            .copy_from_slice(process.indirect);
    }

    for (key, value, relocation) in [
        (AT_PHDR, 0, Some(RelocationKind::ElfProgramHeaders)),
        (AT_PHENT, 0, Some(RelocationKind::ElfProgramHeaderSize)),
        (AT_PHNUM, 0, Some(RelocationKind::ElfProgramHeaderCount)),
        (AT_PAGESZ, 0, Some(RelocationKind::PageSize)),
        (AT_BASE, 0, None),
        (AT_FLAGS, 0, None),
        (AT_ENTRY, 0, Some(RelocationKind::ElfEntry)),
        (AT_UID, u64::from(process.identity.real_uid), None),
        (AT_EUID, u64::from(process.identity.effective_uid), None),
        (AT_GID, u64::from(process.identity.real_gid), None),
        (AT_EGID, u64::from(process.identity.effective_gid), None),
        (AT_HWCAP, 0, None),
        (AT_CLKTCK, crate::accounting::CLOCK_TICKS_PER_SECOND, None),
        (AT_SECURE, u64::from(process.identity.is_secure()), None),
        (
            AT_RANDOM,
            random_offset as u64,
            Some(RelocationKind::StackAddress),
        ),
        (AT_EXECFN, execfn_offset, Some(RelocationKind::StackAddress)),
        (AT_IMAGE_LOAD_BIAS, 0, None),
        (AT_NULL, 0, None),
    ]
    .into_iter()
    .filter(|&(key, _, _)| key != AT_NULL)
    .chain((!process.lifecycle.is_empty()).then_some((
        AT_LIFECYCLE_IMAGE,
        mapped
            .and_then(|m| m.address(0))
            .unwrap_or(lifecycle_offset as u64),
        mapped.is_none().then_some(RelocationKind::StackAddress),
    )))
    .chain((!process.tls.is_empty()).then_some((
        AT_TLS_IMAGE,
        mapped.and_then(|m| m.address(1)).unwrap_or(tls_offset as u64),
        mapped.is_none().then_some(RelocationKind::StackAddress),
    )))
    .chain((!process.indirect.is_empty()).then_some((
        AT_INDIRECT_IMAGE,
        mapped
            .and_then(|m| m.address(2))
            .unwrap_or(indirect_offset as u64),
        mapped.is_none().then_some(RelocationKind::StackAddress),
    )))
    .chain(auxiliary.iter().map(|&(key, value)| (key, value, None)))
    .chain(core::iter::once((AT_NULL, 0, None)))
    {
        let (value, relocation) = match image
            .map(|image| match key {
                AT_PHDR => Some(image.program_headers),
                AT_PHENT => Some(image.program_header_size),
                AT_PHNUM => Some(image.program_header_count),
                AT_ENTRY => Some(image.entry),
                AT_BASE => Some(image.interpreter_base),
                AT_IMAGE_LOAD_BIAS => Some(image.load_bias),
                _ => None,
            })
            .flatten()
        {
            Some(value) => (value, None),
            None => (value, relocation),
        };
        put_word(&mut stack, &mut cursor, key)?;
        match relocation {
            Some(kind) => put_relocated_word(
                &mut stack,
                &mut cursor,
                &mut relocations,
                &mut relocation_count,
                value,
                kind,
            )?,
            None => {
                put_word(&mut stack, &mut cursor, value)?;
            }
        }
    }
    if cursor != pointer_bytes || text_cursor > stack_length {
        return Err(EncodeError::ImageTooLarge);
    }

    process_image::encode(
        0,
        &stack[..stack_length],
        &relocations[..relocation_count],
        output,
    )
    .map_err(EncodeError::Codec)
}
