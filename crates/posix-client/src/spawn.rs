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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathCandidateError {
    EmptyFile,
    ContainsNul,
    TooLong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathSearchError {
    Continue,
    ContinueWithAccessDenied,
    Stop(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathSearchFailure {
    Candidate(PathCandidateError),
    Errno(i32),
}

/// Builds one NUL-terminated `PATH` candidate. An empty directory denotes the
/// current directory, and a directory already ending in `/` is not modified.
pub fn build_path_candidate(
    directory: &[u8],
    file: &[u8],
    output: &mut [u8],
) -> Result<usize, PathCandidateError> {
    if file.is_empty() {
        return Err(PathCandidateError::EmptyFile);
    }
    if directory.contains(&0) || file.contains(&0) {
        return Err(PathCandidateError::ContainsNul);
    }
    let separator = usize::from(!directory.is_empty() && !directory.ends_with(b"/"));
    let length = directory
        .len()
        .checked_add(separator)
        .and_then(|length| length.checked_add(file.len()))
        .ok_or(PathCandidateError::TooLong)?;
    if length >= output.len() {
        return Err(PathCandidateError::TooLong);
    }
    output[..directory.len()].copy_from_slice(directory);
    let mut written = directory.len();
    if separator != 0 {
        output[written] = b'/';
        written += 1;
    }
    output[written..length].copy_from_slice(file);
    output[length] = 0;
    Ok(length)
}

/// Classifies errors from one `PATH` candidate according to exec search
/// semantics. Access denial is remembered so it wins over a final ENOENT.
pub const fn classify_path_search_error(errno: i32) -> PathSearchError {
    match errno {
        2 | 20 => PathSearchError::Continue,
        13 => PathSearchError::ContinueWithAccessDenied,
        other => PathSearchError::Stop(other),
    }
}

/// Searches colon-separated directories in order. Each candidate passed to
/// `execute` includes its trailing NUL so runtimes can call a C ABI directly.
pub fn search_path<T>(
    path: &[u8],
    file: &[u8],
    candidate: &mut [u8],
    mut execute: impl FnMut(&[u8]) -> Result<T, i32>,
) -> Result<T, PathSearchFailure> {
    let mut access_denied = false;
    for directory in path.split(|byte| *byte == b':') {
        let length = build_path_candidate(directory, file, candidate)
            .map_err(PathSearchFailure::Candidate)?;
        match execute(&candidate[..=length]) {
            Ok(value) => return Ok(value),
            Err(errno) => match classify_path_search_error(errno) {
                PathSearchError::Continue => {}
                PathSearchError::ContinueWithAccessDenied => access_denied = true,
                PathSearchError::Stop(errno) => return Err(PathSearchFailure::Errno(errno)),
            },
        }
    }
    Err(PathSearchFailure::Errno(if access_denied { 13 } else { 2 }))
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
