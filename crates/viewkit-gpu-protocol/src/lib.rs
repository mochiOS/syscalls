#![no_std]

pub const MAGIC: u32 = u32::from_le_bytes(*b"VKGS");
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 52;
pub const VERTEX_STRIDE: usize = 36;
pub const CLEAR_VERTEX_COUNT: u32 = 6;
pub const MAX_VERTICES: u32 = 65_536;
pub const MAX_ATLAS_EXTENT: u32 = 2_048;
pub const ATLAS_WIDTH: u32 = 1_024;
pub const ATLAS_HEIGHT: u32 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    BadMagic,
    BadVersion,
    BadHeaderLength,
    BadVertexStride,
    TooManyVertices,
    BadDimensions,
    BadOffsets,
    LengthMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scene<'a> {
    pub width: u32,
    pub height: u32,
    pub vertices: &'a [u8],
    pub atlas_width: u32,
    pub atlas_height: u32,
    pub atlas_data_y: u32,
    pub atlas_data_height: u32,
    pub atlas: &'a [u8],
}

impl Scene<'_> {
    pub fn vertex_count(&self) -> u32 {
        (self.vertices.len() / VERTEX_STRIDE) as u32
    }
}

pub fn encode_header(
    output: &mut [u8],
    width: u32,
    height: u32,
    vertex_count: u32,
    atlas_width: u32,
    atlas_height: u32,
    atlas_data_y: u32,
    atlas_data_height: u32,
) -> Result<usize, DecodeError> {
    if output.len() < HEADER_LEN {
        return Err(DecodeError::TooShort);
    }
    validate_dimensions(
        width,
        height,
        vertex_count,
        atlas_width,
        atlas_height,
        atlas_data_y,
        atlas_data_height,
    )?;
    let vertex_bytes = usize::try_from(vertex_count)
        .ok()
        .and_then(|count| count.checked_mul(VERTEX_STRIDE))
        .ok_or(DecodeError::BadOffsets)?;
    let atlas_bytes = usize::try_from(atlas_width)
        .ok()
        .and_then(|width| {
            usize::try_from(atlas_data_height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(DecodeError::BadOffsets)?;
    let atlas_offset = HEADER_LEN
        .checked_add(vertex_bytes)
        .ok_or(DecodeError::BadOffsets)?;
    let total_len = atlas_offset
        .checked_add(atlas_bytes)
        .ok_or(DecodeError::BadOffsets)?;
    output[..HEADER_LEN].fill(0);
    put_u32(output, 0, MAGIC)?;
    put_u16(output, 4, VERSION)?;
    put_u16(output, 6, HEADER_LEN as u16)?;
    put_u32(
        output,
        8,
        u32::try_from(total_len).map_err(|_| DecodeError::BadOffsets)?,
    )?;
    put_u32(output, 12, width)?;
    put_u32(output, 16, height)?;
    put_u32(output, 20, vertex_count)?;
    put_u32(output, 24, VERTEX_STRIDE as u32)?;
    put_u32(output, 28, HEADER_LEN as u32)?;
    put_u32(
        output,
        32,
        u32::try_from(atlas_offset).map_err(|_| DecodeError::BadOffsets)?,
    )?;
    put_u32(output, 36, atlas_width)?;
    put_u32(output, 40, atlas_height)?;
    put_u32(output, 44, atlas_data_y)?;
    put_u32(output, 48, atlas_data_height)?;
    Ok(total_len)
}

pub fn decode(bytes: &[u8]) -> Result<Scene<'_>, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::TooShort);
    }
    if read_u32(bytes, 0)? != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if read_u16(bytes, 4)? != VERSION {
        return Err(DecodeError::BadVersion);
    }
    if usize::from(read_u16(bytes, 6)?) != HEADER_LEN {
        return Err(DecodeError::BadHeaderLength);
    }
    let total_len = read_usize(bytes, 8)?;
    if total_len != bytes.len() {
        return Err(DecodeError::LengthMismatch);
    }
    let width = read_u32(bytes, 12)?;
    let height = read_u32(bytes, 16)?;
    let vertex_count = read_u32(bytes, 20)?;
    if read_usize(bytes, 24)? != VERTEX_STRIDE {
        return Err(DecodeError::BadVertexStride);
    }
    let vertices_offset = read_usize(bytes, 28)?;
    let atlas_offset = read_usize(bytes, 32)?;
    let atlas_width = read_u32(bytes, 36)?;
    let atlas_height = read_u32(bytes, 40)?;
    let atlas_data_y = read_u32(bytes, 44)?;
    let atlas_data_height = read_u32(bytes, 48)?;
    validate_dimensions(
        width,
        height,
        vertex_count,
        atlas_width,
        atlas_height,
        atlas_data_y,
        atlas_data_height,
    )?;
    let vertex_bytes = usize::try_from(vertex_count)
        .ok()
        .and_then(|count| count.checked_mul(VERTEX_STRIDE))
        .ok_or(DecodeError::BadOffsets)?;
    let expected_atlas = vertices_offset
        .checked_add(vertex_bytes)
        .ok_or(DecodeError::BadOffsets)?;
    let atlas_bytes = usize::try_from(atlas_width)
        .ok()
        .and_then(|width| {
            usize::try_from(atlas_data_height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(DecodeError::BadOffsets)?;
    if vertices_offset != HEADER_LEN
        || atlas_offset != expected_atlas
        || atlas_offset.checked_add(atlas_bytes) != Some(total_len)
    {
        return Err(DecodeError::BadOffsets);
    }
    Ok(Scene {
        width,
        height,
        vertices: &bytes[vertices_offset..atlas_offset],
        atlas_width,
        atlas_height,
        atlas_data_y,
        atlas_data_height,
        atlas: &bytes[atlas_offset..total_len],
    })
}

pub fn decode_prefix(bytes: &[u8]) -> Result<(Scene<'_>, usize), DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::TooShort);
    }
    let total_len = read_usize(bytes, 8)?;
    let message = bytes.get(..total_len).ok_or(DecodeError::TooShort)?;
    Ok((decode(message)?, total_len))
}

fn validate_dimensions(
    width: u32,
    height: u32,
    vertices: u32,
    atlas_width: u32,
    atlas_height: u32,
    atlas_data_y: u32,
    atlas_data_height: u32,
) -> Result<(), DecodeError> {
    if width == 0
        || height == 0
        || atlas_width == 0
        || atlas_height == 0
        || atlas_data_y > atlas_height
        || atlas_data_y
            .checked_add(atlas_data_height)
            .is_none_or(|end| end > atlas_height)
        || (atlas_data_height == 0 && atlas_data_y != 0)
        || atlas_width > MAX_ATLAS_EXTENT
        || atlas_height > MAX_ATLAS_EXTENT
    {
        return Err(DecodeError::BadDimensions);
    }
    if vertices < CLEAR_VERTEX_COUNT || vertices > MAX_VERTICES || vertices % 3 != 0 {
        return Err(DecodeError::TooManyVertices);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DecodeError> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or(DecodeError::TooShort)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DecodeError> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(DecodeError::TooShort)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_usize(bytes: &[u8], offset: usize) -> Result<usize, DecodeError> {
    usize::try_from(read_u32(bytes, offset)?).map_err(|_| DecodeError::BadOffsets)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), DecodeError> {
    bytes
        .get_mut(offset..offset.saturating_add(2))
        .ok_or(DecodeError::TooShort)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), DecodeError> {
    bytes
        .get_mut(offset..offset.saturating_add(4))
        .ok_or(DecodeError::TooShort)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_exact_length() {
        let mut bytes = [0u8; HEADER_LEN + VERTEX_STRIDE * 6 + 16];
        assert_eq!(
            encode_header(&mut bytes, 640, 480, 6, 2, 2, 0, 2),
            Ok(bytes.len())
        );
        let scene = decode(&bytes).unwrap();
        assert_eq!((scene.width, scene.height), (640, 480));
        assert_eq!(scene.vertex_count(), 6);
        assert_eq!(scene.atlas.len(), 16);
        assert_eq!(
            decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_header_corruption() {
        let mut bytes = [0u8; HEADER_LEN + VERTEX_STRIDE * 6 + 4];
        encode_header(&mut bytes, 1, 1, 6, 1, 1, 0, 1).unwrap();
        bytes[0] = 0;
        assert_eq!(decode(&bytes), Err(DecodeError::BadMagic));
    }

    #[test]
    fn prefix_decode_keeps_transport_padding_outside_message() {
        let message_len = HEADER_LEN + VERTEX_STRIDE * 6 + 4;
        let mut bytes = [0u8; HEADER_LEN + VERTEX_STRIDE * 6 + 12];
        encode_header(&mut bytes, 1, 1, 6, 1, 1, 0, 1).unwrap();
        bytes[8..12].copy_from_slice(&(message_len as u32).to_le_bytes());
        let (_, decoded_len) = decode_prefix(&bytes).unwrap();
        assert_eq!(decoded_len, message_len);
        assert_eq!(decode(&bytes), Err(DecodeError::LengthMismatch));
    }

    #[test]
    fn accepts_empty_and_offset_atlas_updates() {
        let mut vertices_only = [0u8; HEADER_LEN + VERTEX_STRIDE * 6];
        encode_header(&mut vertices_only, 1, 1, 6, 2, 4, 0, 0).unwrap();
        let scene = decode(&vertices_only).unwrap();
        assert_eq!((scene.atlas_data_y, scene.atlas_data_height), (0, 0));
        assert!(scene.atlas.is_empty());

        let mut partial = [0u8; HEADER_LEN + VERTEX_STRIDE * 6 + 16];
        encode_header(&mut partial, 1, 1, 6, 2, 4, 2, 2).unwrap();
        let scene = decode(&partial).unwrap();
        assert_eq!((scene.atlas_data_y, scene.atlas_data_height), (2, 2));
        assert_eq!(scene.atlas.len(), 16);
    }
}
