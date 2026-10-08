pub const RESET_IDS: i16 = 0x01;
pub const SET_PROCESS_GROUP: i16 = 0x02;
pub const SET_SCHEDULING_PARAMETERS: i16 = 0x04;
pub const SET_SCHEDULER: i16 = 0x08;
pub const SET_SIGNAL_DEFAULTS: i16 = 0x10;
pub const SET_SIGNAL_MASK: i16 = 0x20;

pub const KNOWN_ATTRIBUTE_FLAGS: i16 = RESET_IDS
    | SET_PROCESS_GROUP
    | SET_SCHEDULING_PARAMETERS
    | SET_SCHEDULER
    | SET_SIGNAL_DEFAULTS
    | SET_SIGNAL_MASK;

pub const IMPLEMENTED_ATTRIBUTE_FLAGS: i16 =
    RESET_IDS | SET_PROCESS_GROUP | SET_SIGNAL_DEFAULTS | SET_SIGNAL_MASK;

pub const EXEC_ERROR_PACKET_LEN: usize = core::mem::size_of::<i32>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecStatus {
    Succeeded,
    Failed(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecStatusError {
    Truncated,
    InvalidErrno,
    Oversized,
}

/// Decodes the private parent/child status stream used by `posix_spawn`.
/// An empty stream closed by exec means success; a complete positive errno
/// packet means that setup or image replacement failed in the child.
pub fn decode_exec_status(
    bytes: &[u8],
    end_of_stream: bool,
) -> Result<Option<ExecStatus>, ExecStatusError> {
    if bytes.is_empty() {
        return if end_of_stream {
            Ok(Some(ExecStatus::Succeeded))
        } else {
            Ok(None)
        };
    }
    if bytes.len() > EXEC_ERROR_PACKET_LEN {
        return Err(ExecStatusError::Oversized);
    }
    if bytes.len() < EXEC_ERROR_PACKET_LEN {
        return if end_of_stream {
            Err(ExecStatusError::Truncated)
        } else {
            Ok(None)
        };
    }
    let errno = i32::from_ne_bytes(
        bytes
            .try_into()
            .expect("validated spawn error packet length"),
    );
    if errno <= 0 {
        return Err(ExecStatusError::InvalidErrno);
    }
    Ok(Some(ExecStatus::Failed(errno)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeFlags {
    Supported,
    RequiresScheduler,
    Invalid,
}

pub const fn classify_attribute_flags(flags: i16) -> AttributeFlags {
    if flags & !KNOWN_ATTRIBUTE_FLAGS != 0 {
        AttributeFlags::Invalid
    } else if flags & !IMPLEMENTED_ATTRIBUTE_FLAGS != 0 {
        AttributeFlags::RequiresScheduler
    } else {
        AttributeFlags::Supported
    }
}
