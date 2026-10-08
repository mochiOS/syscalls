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
const AUXILIARY_VECTOR_ENTRIES: usize = 17;

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
    if argv.is_empty() {
        return Err(EncodeError::EmptyArgumentVector);
    }
    if execfn.contains(&0) {
        return Err(EncodeError::InvalidText);
    }
    let argument_bytes = checked_text_size(argv)?;
    let environment_bytes = checked_text_size(envp)?;
    let pointer_words = 1usize
        .checked_add(argv.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(envp.len()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(AUXILIARY_VECTOR_ENTRIES * 2))
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
    let stack_length = unaligned_length
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
    for environment in envp {
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

    for (key, value, relocation) in [
        (AT_PHDR, 0, Some(RelocationKind::ElfProgramHeaders)),
        (AT_PHENT, 0, Some(RelocationKind::ElfProgramHeaderSize)),
        (AT_PHNUM, 0, Some(RelocationKind::ElfProgramHeaderCount)),
        (AT_PAGESZ, 0, Some(RelocationKind::PageSize)),
        (AT_BASE, 0, None),
        (AT_FLAGS, 0, None),
        (AT_ENTRY, 0, Some(RelocationKind::ElfEntry)),
        (AT_UID, 0, None),
        (AT_EUID, 0, None),
        (AT_GID, 0, None),
        (AT_EGID, 0, None),
        (AT_HWCAP, 0, None),
        (AT_CLKTCK, 100, None),
        (AT_SECURE, 0, None),
        (
            AT_RANDOM,
            random_offset as u64,
            Some(RelocationKind::StackAddress),
        ),
        (
            AT_EXECFN,
            execfn_offset,
            Some(RelocationKind::StackAddress),
        ),
        (AT_NULL, 0, None),
    ] {
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
