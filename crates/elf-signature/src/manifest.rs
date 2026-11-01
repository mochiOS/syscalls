//! Signature-covered declarations, separate from signer trust or grant policy.
use super::*;

const SECTION: &[u8] = b".mochios.manifest";
const MAGIC: &[u8; 8] = b"MOELFMAN";
const HEADER_LEN: usize = 16;
const SHT_PROGBITS: u32 = 1;
pub const MAX_MANIFEST_LEN: usize = 64 * 1024;

fn text(bytes: &[u8]) -> Result<&str> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_LEN || bytes.contains(&0) {
        bail!("invalid embedded ELF manifest length or NUL byte");
    }
    core::str::from_utf8(bytes).context("embedded ELF manifest is not UTF-8")
}

/// Embed the exact manifest.toml bytes before signing. Parsing the declaration
/// and deciding capabilities belong to the common userspace manifest policy.
/// Existing signatures or manifests are never overwritten or silently reused.
pub fn embed_manifest(unsigned: &[u8], declaration: &str) -> Result<Vec<u8>> {
    text(declaration.as_bytes())?;
    let elf = parse_elf(unsigned)?;
    if locate_record_in(&elf)?.is_some() {
        bail!("cannot embed a manifest after ELF signing");
    }
    if locate(&elf)?.is_some() {
        bail!("ELF already contains an embedded manifest");
    }
    let mut data = Vec::new();
    data.try_reserve_exact(HEADER_LEN + declaration.len())
        .context("unable to allocate embedded ELF manifest")?;
    data.extend_from_slice(MAGIC);
    data.extend_from_slice(&1u16.to_le_bytes()); // envelope version
    data.extend_from_slice(&1u16.to_le_bytes()); // UTF-8 manifest.toml
    data.extend_from_slice(&0u32.to_le_bytes()); // reserved
    data.extend_from_slice(declaration.as_bytes());
    let output = append_section(&elf, SECTION, SHT_PROGBITS, &data)?;
    locate(&parse_elf(&output)?)?.context("generated ELF manifest is not discoverable")?;
    Ok(output)
}

pub(super) fn locate<'a>(elf: &Elf<'a>) -> Result<Option<&'a str>> {
    let mut found = None;
    for (index, section) in elf.sections.iter().enumerate() {
        if section_name(elf, *section)? != SECTION {
            continue;
        }
        if found.is_some() {
            bail!("duplicate embedded ELF manifest sections");
        }
        let raw = section.raw_offset;
        if section.section_type != SHT_PROGBITS
            || section.align != 4
            || section.entry_size != 0
            || read_u64(elf.bytes, raw + 8)? != 0 // flags
            || read_u64(elf.bytes, raw + 16)? != 0 // address
            || read_u64(elf.bytes, raw + 40)? != 0 // link / info
            || section.offset % 4 != 0
            || section.size <= HEADER_LEN
            || section.size > HEADER_LEN + MAX_MANIFEST_LEN
        {
            bail!("invalid embedded ELF manifest section");
        }
        let range = (section.offset, section.offset + section.size);
        if overlaps(range, (0, ELF64_HEADER_LEN))
            || elf.program_header_table.is_some_and(|r| overlaps(range, r))
            || elf.section_header_table.is_some_and(|r| overlaps(range, r))
            || elf
                .load_segments
                .iter()
                .copied()
                .any(|r| overlaps(range, r))
            || elf
                .program_notes
                .iter()
                .any(|r| overlaps(range, (r.offset, r.offset + r.size)))
            || elf.sections.iter().enumerate().any(|(other, s)| {
                other != index
                    && s.section_type != 8
                    && s.size != 0
                    && overlaps(range, (s.offset, s.offset + s.size))
            })
        {
            bail!("embedded ELF manifest overlaps another file region");
        }
        let bytes = &elf.bytes[range.0..range.1];
        if &bytes[..8] != MAGIC
            || read_u16(bytes, 8)? != 1
            || read_u16(bytes, 10)? != 1
            || read_u32(bytes, 12)? != 0
        {
            bail!("unsupported embedded ELF manifest header");
        }
        found = Some(text(&bytes[HEADER_LEN..])?);
    }
    Ok(found)
}
