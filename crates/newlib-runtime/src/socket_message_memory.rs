//! Import/export C message metadata as bytes, never faultable Rust objects.
use super::*;

macro_rules! read_field {
    ($bytes:ident, $structure:ty, $field:ident, $integer:ty) => {{
        let offset = core::mem::offset_of!($structure, $field);
        <$integer>::from_ne_bytes(
            $bytes[offset..offset + core::mem::size_of::<$integer>()]
                .try_into()
                .expect("C field fits its structure"),
        )
    }};
}

pub(super) fn read_message(source: *const Message) -> Result<Message, c_int> {
    let mut bytes = [0; core::mem::size_of::<Message>()];
    user_copy::read(source.cast(), &mut bytes)?;
    Ok(Message {
        name: read_field!(bytes, Message, name, usize) as *mut c_void,
        name_length: read_field!(bytes, Message, name_length, u32),
        vectors: read_field!(bytes, Message, vectors, usize) as *const IoVecMut,
        vector_count: read_field!(bytes, Message, vector_count, usize),
        control: read_field!(bytes, Message, control, usize) as *mut c_void,
        control_length: read_field!(bytes, Message, control_length, usize),
        flags: read_field!(bytes, Message, flags, c_int),
    })
}

pub(super) fn read_vector(source: *const IoVecMut, index: usize) -> Result<Vector, c_int> {
    let offset = index
        .checked_mul(core::mem::size_of::<IoVecMut>())
        .ok_or(EFAULT)?;
    let address = (source as usize).checked_add(offset).ok_or(EFAULT)?;
    let mut bytes = [0; core::mem::size_of::<IoVecMut>()];
    user_copy::read(address as *const u8, &mut bytes)?;
    Ok(Vector {
        base: read_field!(bytes, IoVecMut, iov_base, usize) as *mut u8,
        length: read_field!(bytes, IoVecMut, iov_len, usize),
    })
}

pub(super) fn write_message(destination: *mut Message, message: Message) -> Result<(), c_int> {
    let mut bytes = [0; core::mem::size_of::<Message>()];
    macro_rules! field {
        ($field:ident, $value:expr) => {{
            let value = $value.to_ne_bytes();
            let offset = core::mem::offset_of!(Message, $field);
            bytes[offset..offset + value.len()].copy_from_slice(&value);
        }};
    }
    field!(name, message.name as usize);
    field!(name_length, message.name_length);
    field!(vectors, message.vectors as usize);
    field!(vector_count, message.vector_count);
    field!(control, message.control as usize);
    field!(control_length, message.control_length);
    field!(flags, message.flags);
    user_copy::write(destination.cast(), &bytes)
}
