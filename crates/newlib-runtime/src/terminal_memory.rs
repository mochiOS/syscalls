//! Copy C terminal structures without borrowing faultable application memory.
use super::*;

macro_rules! scalar {
    ($bytes:ident, $structure:ty, $field:ident, $value:expr) => {{
        let value = $value.to_ne_bytes();
        let offset = core::mem::offset_of!($structure, $field);
        $bytes[offset..offset + value.len()].copy_from_slice(&value);
    }};
    ($bytes:ident, $structure:ty, $field:ident, $integer:ty, read) => {{
        let offset = core::mem::offset_of!($structure, $field);
        <$integer>::from_ne_bytes(
            $bytes[offset..offset + core::mem::size_of::<$integer>()]
                .try_into()
                .expect("C field fits its structure"),
        )
    }};
}

pub(super) fn read_attributes(source: *const NewlibTermios) -> Result<NewlibTermios, c_int> {
    let mut bytes = [0; core::mem::size_of::<NewlibTermios>()];
    user_copy::read(source.cast(), &mut bytes)?;
    let mut characters = [0; posix_protocol::TERMINAL_CONTROL_CHARACTERS];
    let offset = core::mem::offset_of!(NewlibTermios, c_cc);
    let count = characters.len();
    characters.copy_from_slice(&bytes[offset..offset + count]);
    Ok(NewlibTermios {
        c_iflag: scalar!(bytes, NewlibTermios, c_iflag, u32, read),
        c_oflag: scalar!(bytes, NewlibTermios, c_oflag, u32, read),
        c_cflag: scalar!(bytes, NewlibTermios, c_cflag, u32, read),
        c_lflag: scalar!(bytes, NewlibTermios, c_lflag, u32, read),
        c_cc: characters,
        c_ispeed: scalar!(bytes, NewlibTermios, c_ispeed, u32, read),
        c_ospeed: scalar!(bytes, NewlibTermios, c_ospeed, u32, read),
    })
}

pub(super) fn write_attributes(
    destination: *mut NewlibTermios,
    value: NewlibTermios,
) -> Result<(), c_int> {
    let mut bytes = [0; core::mem::size_of::<NewlibTermios>()];
    scalar!(bytes, NewlibTermios, c_iflag, value.c_iflag);
    scalar!(bytes, NewlibTermios, c_oflag, value.c_oflag);
    scalar!(bytes, NewlibTermios, c_cflag, value.c_cflag);
    scalar!(bytes, NewlibTermios, c_lflag, value.c_lflag);
    let offset = core::mem::offset_of!(NewlibTermios, c_cc);
    bytes[offset..offset + value.c_cc.len()].copy_from_slice(&value.c_cc);
    scalar!(bytes, NewlibTermios, c_ispeed, value.c_ispeed);
    scalar!(bytes, NewlibTermios, c_ospeed, value.c_ospeed);
    user_copy::write(destination.cast(), &bytes)
}

pub(super) fn read_window(source: *const NewlibWinSize) -> Result<NewlibWinSize, c_int> {
    let mut bytes = [0; core::mem::size_of::<NewlibWinSize>()];
    user_copy::read(source.cast(), &mut bytes)?;
    Ok(NewlibWinSize {
        ws_row: scalar!(bytes, NewlibWinSize, ws_row, u16, read),
        ws_col: scalar!(bytes, NewlibWinSize, ws_col, u16, read),
        ws_xpixel: scalar!(bytes, NewlibWinSize, ws_xpixel, u16, read),
        ws_ypixel: scalar!(bytes, NewlibWinSize, ws_ypixel, u16, read),
    })
}

pub(super) fn write_window(
    destination: *mut NewlibWinSize,
    value: NewlibWinSize,
) -> Result<(), c_int> {
    let mut bytes = [0; core::mem::size_of::<NewlibWinSize>()];
    scalar!(bytes, NewlibWinSize, ws_row, value.ws_row);
    scalar!(bytes, NewlibWinSize, ws_col, value.ws_col);
    scalar!(bytes, NewlibWinSize, ws_xpixel, value.ws_xpixel);
    scalar!(bytes, NewlibWinSize, ws_ypixel, value.ws_ypixel);
    user_copy::write(destination.cast(), &bytes)
}
