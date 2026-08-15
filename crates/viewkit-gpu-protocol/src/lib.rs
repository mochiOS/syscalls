#![no_std]

#[cfg(test)]
extern crate std;

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

pub mod compositor {
    use super::{DecodeError, MAX_VERTICES, VERTEX_STRIDE, put_u16, put_u32, read_u16, read_u32};

    pub const MAGIC: u32 = u32::from_le_bytes(*b"VKGC");
    pub const VERSION: u16 = 1;
    pub const HEADER_LEN: usize = 64;
    pub const TEXTURE_DESC_LEN: usize = 40;
    pub const BATCH_DESC_LEN: usize = 16;
    pub const MAX_TEXTURES: u32 = 64;
    pub const MAX_BATCHES: u32 = 128;
    pub const MAX_TEXTURE_EXTENT: u32 = 8_192;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Texture<'a> {
        pub key: u64,
        pub width: u32,
        pub height: u32,
        pub data_y: u32,
        pub data_height: u32,
        pub generation: u64,
        pub data: &'a [u8],
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Batch {
        pub texture_key: u64,
        pub first_vertex: u32,
        pub vertex_count: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Scene<'a> {
        pub width: u32,
        pub height: u32,
        pub vertices: &'a [u8],
        bytes: &'a [u8],
        texture_count: u32,
        batch_count: u32,
        texture_offset: usize,
        batch_offset: usize,
        data_offset: usize,
    }

    impl Scene<'_> {
        pub fn vertex_count(&self) -> u32 {
            (self.vertices.len() / VERTEX_STRIDE) as u32
        }

        pub const fn texture_count(&self) -> u32 {
            self.texture_count
        }

        pub const fn batch_count(&self) -> u32 {
            self.batch_count
        }

        pub fn texture(&self, index: u32) -> Option<Texture<'_>> {
            if index >= self.texture_count {
                return None;
            }
            let offset = self
                .texture_offset
                .checked_add(index as usize * TEXTURE_DESC_LEN)?;
            let data_offset = read_u32(self.bytes, offset + 24).ok()? as usize;
            let data_len = read_u32(self.bytes, offset + 28).ok()? as usize;
            Some(Texture {
                key: read_u64(self.bytes, offset).ok()?,
                width: read_u32(self.bytes, offset + 8).ok()?,
                height: read_u32(self.bytes, offset + 12).ok()?,
                data_y: read_u32(self.bytes, offset + 16).ok()?,
                data_height: read_u32(self.bytes, offset + 20).ok()?,
                generation: read_u64(self.bytes, offset + 32).ok()?,
                data: if data_len == 0 {
                    &[]
                } else {
                    self.bytes
                        .get(data_offset..data_offset.checked_add(data_len)?)?
                },
            })
        }

        pub fn batch(&self, index: u32) -> Option<Batch> {
            if index >= self.batch_count {
                return None;
            }
            let offset = self
                .batch_offset
                .checked_add(index as usize * BATCH_DESC_LEN)?;
            Some(Batch {
                texture_key: read_u64(self.bytes, offset).ok()?,
                first_vertex: read_u32(self.bytes, offset + 8).ok()?,
                vertex_count: read_u32(self.bytes, offset + 12).ok()?,
            })
        }
    }

    pub fn encoded_len(
        vertex_count: u32,
        texture_count: u32,
        batch_count: u32,
        texture_data_len: usize,
    ) -> Result<usize, DecodeError> {
        validate_counts(vertex_count, texture_count, batch_count)?;
        HEADER_LEN
            .checked_add(texture_count as usize * TEXTURE_DESC_LEN)
            .and_then(|length| length.checked_add(batch_count as usize * BATCH_DESC_LEN))
            .and_then(|length| length.checked_add(vertex_count as usize * VERTEX_STRIDE))
            .and_then(|length| length.checked_add(texture_data_len))
            .ok_or(DecodeError::BadOffsets)
    }

    pub fn encode_header(
        output: &mut [u8],
        width: u32,
        height: u32,
        vertex_count: u32,
        texture_count: u32,
        batch_count: u32,
        texture_data_len: usize,
    ) -> Result<usize, DecodeError> {
        if width == 0 || height == 0 {
            return Err(DecodeError::BadDimensions);
        }
        let total = encoded_len(vertex_count, texture_count, batch_count, texture_data_len)?;
        if output.len() < total {
            return Err(DecodeError::TooShort);
        }
        let texture_offset = HEADER_LEN;
        let batch_offset = texture_offset + texture_count as usize * TEXTURE_DESC_LEN;
        let vertex_offset = batch_offset + batch_count as usize * BATCH_DESC_LEN;
        let data_offset = vertex_offset + vertex_count as usize * VERTEX_STRIDE;
        output[..HEADER_LEN].fill(0);
        put_u32(output, 0, MAGIC)?;
        put_u16(output, 4, VERSION)?;
        put_u16(output, 6, HEADER_LEN as u16)?;
        put_u32(output, 8, total as u32)?;
        put_u32(output, 12, width)?;
        put_u32(output, 16, height)?;
        put_u32(output, 20, vertex_count)?;
        put_u32(output, 24, VERTEX_STRIDE as u32)?;
        put_u32(output, 28, texture_count)?;
        put_u32(output, 32, batch_count)?;
        put_u32(output, 36, texture_offset as u32)?;
        put_u32(output, 40, batch_offset as u32)?;
        put_u32(output, 44, vertex_offset as u32)?;
        put_u32(output, 48, data_offset as u32)?;
        Ok(total)
    }

    pub fn encode_texture(
        output: &mut [u8],
        index: u32,
        key: u64,
        width: u32,
        height: u32,
        data_y: u32,
        data_height: u32,
        data_offset: usize,
        data_len: usize,
        generation: u64,
    ) -> Result<(), DecodeError> {
        validate_texture(width, height, data_y, data_height, data_len)?;
        let offset = HEADER_LEN
            .checked_add(index as usize * TEXTURE_DESC_LEN)
            .ok_or(DecodeError::BadOffsets)?;
        put_u64(output, offset, key)?;
        put_u32(output, offset + 8, width)?;
        put_u32(output, offset + 12, height)?;
        put_u32(output, offset + 16, data_y)?;
        put_u32(output, offset + 20, data_height)?;
        put_u32(output, offset + 24, data_offset as u32)?;
        put_u32(output, offset + 28, data_len as u32)?;
        put_u64(output, offset + 32, generation)
    }

    pub fn encode_batch(
        output: &mut [u8],
        batch_offset: usize,
        index: u32,
        batch: Batch,
    ) -> Result<(), DecodeError> {
        let offset = batch_offset
            .checked_add(index as usize * BATCH_DESC_LEN)
            .ok_or(DecodeError::BadOffsets)?;
        put_u64(output, offset, batch.texture_key)?;
        put_u32(output, offset + 8, batch.first_vertex)?;
        put_u32(output, offset + 12, batch.vertex_count)
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
        if read_u16(bytes, 6)? as usize != HEADER_LEN {
            return Err(DecodeError::BadHeaderLength);
        }
        if read_u32(bytes, 8)? as usize != bytes.len() {
            return Err(DecodeError::LengthMismatch);
        }
        let width = read_u32(bytes, 12)?;
        let height = read_u32(bytes, 16)?;
        let vertex_count = read_u32(bytes, 20)?;
        if width == 0 || height == 0 || read_u32(bytes, 24)? as usize != VERTEX_STRIDE {
            return Err(DecodeError::BadDimensions);
        }
        let texture_count = read_u32(bytes, 28)?;
        let batch_count = read_u32(bytes, 32)?;
        validate_counts(vertex_count, texture_count, batch_count)?;
        let texture_offset = read_u32(bytes, 36)? as usize;
        let batch_offset = read_u32(bytes, 40)? as usize;
        let vertex_offset = read_u32(bytes, 44)? as usize;
        let data_offset = read_u32(bytes, 48)? as usize;
        let expected_batch = HEADER_LEN + texture_count as usize * TEXTURE_DESC_LEN;
        let expected_vertex = expected_batch + batch_count as usize * BATCH_DESC_LEN;
        let expected_data = expected_vertex + vertex_count as usize * VERTEX_STRIDE;
        if texture_offset != HEADER_LEN
            || batch_offset != expected_batch
            || vertex_offset != expected_vertex
            || data_offset != expected_data
            || data_offset > bytes.len()
            || bytes[52..HEADER_LEN].iter().any(|byte| *byte != 0)
        {
            return Err(DecodeError::BadOffsets);
        }
        let scene = Scene {
            width,
            height,
            vertices: &bytes[vertex_offset..data_offset],
            bytes,
            texture_count,
            batch_count,
            texture_offset,
            batch_offset,
            data_offset,
        };
        let mut next_data = data_offset;
        for index in 0..texture_count {
            let texture = scene.texture(index).ok_or(DecodeError::BadOffsets)?;
            validate_texture(
                texture.width,
                texture.height,
                texture.data_y,
                texture.data_height,
                texture.data.len(),
            )?;
            let offset = texture_offset + index as usize * TEXTURE_DESC_LEN;
            let encoded_offset = read_u32(bytes, offset + 24)? as usize;
            if texture.data.is_empty() {
                if encoded_offset != 0 {
                    return Err(DecodeError::BadOffsets);
                }
            } else {
                if encoded_offset != next_data {
                    return Err(DecodeError::BadOffsets);
                }
                next_data = next_data
                    .checked_add(texture.data.len())
                    .ok_or(DecodeError::BadOffsets)?;
            }
        }
        if next_data != bytes.len() {
            return Err(DecodeError::BadOffsets);
        }
        for index in 0..batch_count {
            let batch = scene.batch(index).ok_or(DecodeError::BadOffsets)?;
            if batch.vertex_count == 0
                || batch.vertex_count % 3 != 0
                || batch
                    .first_vertex
                    .checked_add(batch.vertex_count)
                    .is_none_or(|end| end > vertex_count)
                || !(0..texture_count).any(|texture| {
                    scene
                        .texture(texture)
                        .is_some_and(|item| item.key == batch.texture_key)
                })
            {
                return Err(DecodeError::BadOffsets);
            }
        }
        Ok(scene)
    }

    fn validate_counts(vertices: u32, textures: u32, batches: u32) -> Result<(), DecodeError> {
        if vertices == 0 || vertices > MAX_VERTICES || vertices % 3 != 0 {
            return Err(DecodeError::TooManyVertices);
        }
        if textures == 0 || textures > MAX_TEXTURES || batches == 0 || batches > MAX_BATCHES {
            return Err(DecodeError::BadOffsets);
        }
        Ok(())
    }

    fn validate_texture(
        width: u32,
        height: u32,
        data_y: u32,
        data_height: u32,
        data_len: usize,
    ) -> Result<(), DecodeError> {
        if width == 0
            || height == 0
            || width > MAX_TEXTURE_EXTENT
            || height > MAX_TEXTURE_EXTENT
            || data_y
                .checked_add(data_height)
                .is_none_or(|end| end > height)
            || (data_height == 0) != (data_len == 0)
            || data_len != width as usize * data_height as usize * 4
        {
            return Err(DecodeError::BadDimensions);
        }
        Ok(())
    }

    fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DecodeError> {
        let value = bytes
            .get(offset..offset.saturating_add(8))
            .ok_or(DecodeError::TooShort)?;
        Ok(u64::from_le_bytes([
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
        ]))
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), DecodeError> {
        bytes
            .get_mut(offset..offset.saturating_add(8))
            .ok_or(DecodeError::TooShort)?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
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

    #[test]
    fn compositor_scene_round_trip() {
        use compositor::{
            BATCH_DESC_LEN, Batch, HEADER_LEN as COMPOSITOR_HEADER_LEN, TEXTURE_DESC_LEN,
        };
        let vertex_count = 6;
        let data_len = 8;
        let total = compositor::encoded_len(vertex_count, 1, 1, data_len).unwrap();
        let mut bytes = std::vec![0u8; total];
        compositor::encode_header(&mut bytes, 1920, 1080, vertex_count, 1, 1, data_len).unwrap();
        let batch_offset = COMPOSITOR_HEADER_LEN + TEXTURE_DESC_LEN;
        let vertex_offset = batch_offset + BATCH_DESC_LEN;
        let data_offset = vertex_offset + vertex_count as usize * VERTEX_STRIDE;
        compositor::encode_texture(&mut bytes, 0, 42, 2, 1, 0, 1, data_offset, data_len, 7)
            .unwrap();
        compositor::encode_batch(
            &mut bytes,
            batch_offset,
            0,
            Batch {
                texture_key: 42,
                first_vertex: 0,
                vertex_count,
            },
        )
        .unwrap();
        bytes[data_offset..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let scene = compositor::decode(&bytes).unwrap();
        assert_eq!(
            (
                scene.width,
                scene.height,
                scene.texture_count(),
                scene.batch_count()
            ),
            (1920, 1080, 1, 1)
        );
        assert_eq!(scene.texture(0).unwrap().generation, 7);
        assert_eq!(scene.texture(0).unwrap().data, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(scene.batch(0).unwrap().texture_key, 42);
    }
}
