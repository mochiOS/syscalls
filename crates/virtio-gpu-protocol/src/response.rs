use crate::codec::{
    read_u8, read_u32, read_u64, require_decode, require_encode, write_u8, write_u32, write_u64,
};
use crate::{
    DecodeError, EncodeError, Rect, TYPE_RESP_ERR_INVALID_CONTEXT_ID,
    TYPE_RESP_ERR_INVALID_PARAMETER, TYPE_RESP_ERR_INVALID_RESOURCE_ID,
    TYPE_RESP_ERR_INVALID_SCANOUT_ID, TYPE_RESP_ERR_OUT_OF_MEMORY, TYPE_RESP_ERR_UNSPEC,
    TYPE_RESP_OK_CAPSET, TYPE_RESP_OK_CAPSET_INFO, TYPE_RESP_OK_DISPLAY_INFO, TYPE_RESP_OK_NODATA,
};

pub const DISPLAY_MODE_COUNT: usize = 16;
pub const DISPLAY_INFO_LEN: usize = 24 + DISPLAY_MODE_COUNT * DisplayInfo::ENCODED_LEN;
const RESPONSE_HEADER_LEN: usize = 24;
pub const CAPSET_INFO_LEN: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapsetInfo {
    pub id: u32,
    pub maximum_version: u32,
    pub maximum_size: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayInfo {
    pub rect: Rect,
    pub enabled: bool,
}

impl DisplayInfo {
    pub const ENCODED_LEN: usize = 24;

    fn encode_at(self, buffer: &mut [u8], offset: usize) -> Result<(), EncodeError> {
        if self.enabled {
            self.rect.validate_nonempty()?;
        } else if self.rect != Rect::default() {
            return Err(EncodeError::InvalidValue);
        }
        self.rect.encode_at(buffer, offset);
        write_u32(buffer, offset + 16, u32::from(self.enabled));
        write_u32(buffer, offset + 20, 0);
        Ok(())
    }

    fn decode_at(buffer: &[u8], offset: usize) -> Result<Self, DecodeError> {
        let rect = Rect::decode_at(buffer, offset)?;
        let enabled = read_u32(buffer, offset + 16)?;
        let flags = read_u32(buffer, offset + 20)?;
        if flags != 0 {
            return Err(DecodeError::NonZeroReserved {
                offset: offset + 20,
                actual: u64::from(flags),
            });
        }
        match enabled {
            0 if rect == Rect::default() => Ok(Self {
                rect,
                enabled: false,
            }),
            1 => {
                if !rect.is_nonempty()
                    || rect.x.checked_add(rect.width).is_none()
                    || rect.y.checked_add(rect.height).is_none()
                {
                    return Err(DecodeError::InvalidValue { offset, actual: 0 });
                }
                Ok(Self {
                    rect,
                    enabled: true,
                })
            }
            _ => Err(DecodeError::InvalidValue {
                offset: offset + 16,
                actual: u64::from(enabled),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayInfoView<'a> {
    bytes: &'a [u8],
}

impl<'a> DisplayInfoView<'a> {
    pub fn mode(self, index: usize) -> Result<Option<DisplayInfo>, DecodeError> {
        if index >= DISPLAY_MODE_COUNT {
            return Ok(None);
        }
        DisplayInfo::decode_at(self.bytes, index * DisplayInfo::ENCODED_LEN).map(Some)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseError {
    Unspecified,
    OutOfMemory,
    InvalidScanoutId,
    InvalidResourceId,
    InvalidContextId,
    InvalidParameter,
}

impl ResponseError {
    const fn wire_value(self) -> u32 {
        match self {
            Self::Unspecified => TYPE_RESP_ERR_UNSPEC,
            Self::OutOfMemory => TYPE_RESP_ERR_OUT_OF_MEMORY,
            Self::InvalidScanoutId => TYPE_RESP_ERR_INVALID_SCANOUT_ID,
            Self::InvalidResourceId => TYPE_RESP_ERR_INVALID_RESOURCE_ID,
            Self::InvalidContextId => TYPE_RESP_ERR_INVALID_CONTEXT_ID,
            Self::InvalidParameter => TYPE_RESP_ERR_INVALID_PARAMETER,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ResponseMessage<'a> {
    NoData,
    DisplayInfo(&'a [DisplayInfo; DISPLAY_MODE_COUNT]),
    CapsetInfo(CapsetInfo),
    Capset(&'a [u8]),
    Error(ResponseError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response<'a> {
    NoData,
    DisplayInfo(DisplayInfoView<'a>),
    CapsetInfo(CapsetInfo),
    Capset(&'a [u8]),
    Error(ResponseError),
}

fn encode_header(buffer: &mut [u8], response_type: u32) {
    write_u32(buffer, 0, response_type);
    write_u32(buffer, 4, 0);
    write_u64(buffer, 8, 0);
    write_u32(buffer, 16, 0);
    write_u8(buffer, 20, 0);
    buffer[21..24].fill(0);
}

fn decode_header(buffer: &[u8]) -> Result<u32, DecodeError> {
    let response_type = read_u32(buffer, 0)?;
    for (offset, value) in [
        (4, u64::from(read_u32(buffer, 4)?)),
        (8, read_u64(buffer, 8)?),
        (16, u64::from(read_u32(buffer, 16)?)),
        (20, u64::from(read_u8(buffer, 20)?)),
        (
            21,
            u64::from(read_u8(buffer, 21)?)
                | (u64::from(read_u8(buffer, 22)?) << 8)
                | (u64::from(read_u8(buffer, 23)?) << 16),
        ),
    ] {
        if value != 0 {
            return Err(DecodeError::NonZeroReserved {
                offset,
                actual: value,
            });
        }
    }
    Ok(response_type)
}

impl ResponseMessage<'_> {
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::DisplayInfo(_) => DISPLAY_INFO_LEN,
            Self::CapsetInfo(_) => CAPSET_INFO_LEN,
            Self::Capset(data) => RESPONSE_HEADER_LEN.saturating_add(data.len()),
            Self::NoData | Self::Error(_) => RESPONSE_HEADER_LEN,
        }
    }

    pub fn encode(self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let length = self.encoded_len();
        require_encode(buffer, length)?;
        let buffer = &mut buffer[..length];
        buffer.fill(0);
        match self {
            Self::NoData => encode_header(buffer, TYPE_RESP_OK_NODATA),
            Self::Error(error) => encode_header(buffer, error.wire_value()),
            Self::DisplayInfo(modes) => {
                encode_header(buffer, TYPE_RESP_OK_DISPLAY_INFO);
                for (index, mode) in modes.iter().enumerate() {
                    mode.encode_at(
                        buffer,
                        RESPONSE_HEADER_LEN + index * DisplayInfo::ENCODED_LEN,
                    )?;
                }
            }
            Self::CapsetInfo(info) => {
                if info.id == 0 || info.maximum_size == 0 {
                    return Err(EncodeError::InvalidValue);
                }
                encode_header(buffer, TYPE_RESP_OK_CAPSET_INFO);
                write_u32(buffer, 24, info.id);
                write_u32(buffer, 28, info.maximum_version);
                write_u32(buffer, 32, info.maximum_size);
                write_u32(buffer, 36, 0);
            }
            Self::Capset(data) => {
                if data.is_empty() {
                    return Err(EncodeError::InvalidValue);
                }
                encode_header(buffer, TYPE_RESP_OK_CAPSET);
                buffer[RESPONSE_HEADER_LEN..].copy_from_slice(data);
            }
        }
        Ok(length)
    }
}

impl<'a> Response<'a> {
    pub fn decode(buffer: &'a [u8]) -> Result<Self, DecodeError> {
        if buffer.len() < RESPONSE_HEADER_LEN {
            return Err(DecodeError::InvalidLength {
                expected: RESPONSE_HEADER_LEN,
                actual: buffer.len(),
            });
        }
        let response_type = decode_header(buffer)?;
        match response_type {
            TYPE_RESP_OK_NODATA => {
                require_decode(buffer, RESPONSE_HEADER_LEN)?;
                Ok(Self::NoData)
            }
            TYPE_RESP_OK_DISPLAY_INFO => {
                require_decode(buffer, DISPLAY_INFO_LEN)?;
                let bytes = &buffer[RESPONSE_HEADER_LEN..];
                let view = DisplayInfoView { bytes };
                for index in 0..DISPLAY_MODE_COUNT {
                    let _ = view.mode(index)?;
                }
                Ok(Self::DisplayInfo(view))
            }
            TYPE_RESP_OK_CAPSET_INFO => {
                require_decode(buffer, CAPSET_INFO_LEN)?;
                let id = read_u32(buffer, 24)?;
                let maximum_version = read_u32(buffer, 28)?;
                let maximum_size = read_u32(buffer, 32)?;
                let reserved = read_u32(buffer, 36)?;
                if reserved != 0 {
                    return Err(DecodeError::NonZeroReserved {
                        offset: 36,
                        actual: u64::from(reserved),
                    });
                }
                if id == 0 || maximum_size == 0 {
                    return Err(DecodeError::InvalidValue {
                        offset: 24,
                        actual: u64::from(id) << 32 | u64::from(maximum_size),
                    });
                }
                Ok(Self::CapsetInfo(CapsetInfo {
                    id,
                    maximum_version,
                    maximum_size,
                }))
            }
            TYPE_RESP_OK_CAPSET => {
                if buffer.len() == RESPONSE_HEADER_LEN {
                    return Err(DecodeError::InvalidLength {
                        expected: RESPONSE_HEADER_LEN + 1,
                        actual: buffer.len(),
                    });
                }
                Ok(Self::Capset(&buffer[RESPONSE_HEADER_LEN..]))
            }
            TYPE_RESP_ERR_UNSPEC
            | TYPE_RESP_ERR_OUT_OF_MEMORY
            | TYPE_RESP_ERR_INVALID_SCANOUT_ID
            | TYPE_RESP_ERR_INVALID_RESOURCE_ID
            | TYPE_RESP_ERR_INVALID_CONTEXT_ID
            | TYPE_RESP_ERR_INVALID_PARAMETER => {
                require_decode(buffer, RESPONSE_HEADER_LEN)?;
                let error = match response_type {
                    TYPE_RESP_ERR_UNSPEC => ResponseError::Unspecified,
                    TYPE_RESP_ERR_OUT_OF_MEMORY => ResponseError::OutOfMemory,
                    TYPE_RESP_ERR_INVALID_SCANOUT_ID => ResponseError::InvalidScanoutId,
                    TYPE_RESP_ERR_INVALID_RESOURCE_ID => ResponseError::InvalidResourceId,
                    TYPE_RESP_ERR_INVALID_CONTEXT_ID => ResponseError::InvalidContextId,
                    _ => ResponseError::InvalidParameter,
                };
                Ok(Self::Error(error))
            }
            _ => Err(DecodeError::UnknownResponse {
                actual: response_type,
            }),
        }
    }

    pub fn require_no_data(buffer: &'a [u8]) -> Result<(), DecodeError> {
        match Self::decode(buffer)? {
            Self::NoData => Ok(()),
            Self::Error(_) => Err(DecodeError::UnexpectedResponse {
                expected: TYPE_RESP_OK_NODATA,
                actual: read_u32(buffer, 0)?,
            }),
            Self::DisplayInfo(_) | Self::CapsetInfo(_) | Self::Capset(_) => {
                Err(DecodeError::UnexpectedResponse {
                    expected: TYPE_RESP_OK_NODATA,
                    actual: TYPE_RESP_OK_DISPLAY_INFO,
                })
            }
        }
    }
}
