//! User-space encoding of launch arguments and explicit native Handle grants.

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};

/// Launcher item containing `NAME=value`, consumed by this userspace encoder
/// when constructing the POSIX startup image, never parsed by the kernel.
pub const ENVIRONMENT_PREFIX: &str = "__MNU_EXEC_ENV=";

/// Launcher item containing decimal `key:source_handle:rights`. This userspace
/// convention becomes a binary native HandleGrant; the kernel then enforces
/// source ownership, TRANSFER authority and rights attenuation on that grant.
pub const INHERITED_HANDLE_PREFIX: &str = "__MNU_EXEC_INHERIT_HANDLE=";

/// Launcher item containing decimal `key:value`. Only the binary opaque pair
/// is supplied to the native creation mechanism.
pub const INHERITED_VALUE_PREFIX: &str = "__MNU_EXEC_INHERIT_VALUE=";

#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError {
    TooLarge,
    InvalidEntry,
    Startup(crate::process_image::EncodeError),
    Creation(mnu_abi::process_create::Error),
}

/// Convert launcher policy into opaque native creation metadata. Authorization
/// identity is supplied separately; untrusted argv cannot set security policy.
/// The kernel checks source ownership, TRANSFER and rights attenuation later.
pub fn encode_native_launch(
    identity: &str,
    argument_zero: &str,
    items: &[String],
    random: [u8; 16],
) -> Result<Vec<u8>, EncodeError> {
    encode_native_launch_for_process(
        identity,
        argument_zero,
        items,
        random,
        crate::process_image::Process::default(),
    )
}

/// Install userspace-prepared entry metadata through the same startup encoder
/// as exec. `process` is trusted local loader output, never launcher argv or
/// authenticated credentials supplied by a remote request.
pub fn encode_native_launch_for_process(
    identity: &str,
    argument_zero: &str,
    items: &[String],
    random: [u8; 16],
    process: crate::process_image::Process<'_>,
) -> Result<Vec<u8>, EncodeError> {
    use mnu_abi::process_create::{self, HandleGrant, Value};

    if argument_zero.is_empty() || argument_zero.as_bytes().contains(&0) {
        return Err(EncodeError::InvalidEntry);
    }
    let mut arguments = vec![argument_zero.as_bytes()];
    let mut environment = Vec::new();
    let mut handles: Vec<HandleGrant> = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    for item in items {
        if item.as_bytes().contains(&0) {
            return Err(EncodeError::InvalidEntry);
        }
        if let Some(entry) = item.strip_prefix(ENVIRONMENT_PREFIX) {
            let (name, _) = entry.split_once('=').ok_or(EncodeError::InvalidEntry)?;
            if name.is_empty() {
                return Err(EncodeError::InvalidEntry);
            }
            environment.push(entry.as_bytes());
        } else if let Some(entry) = item.strip_prefix(INHERITED_HANDLE_PREFIX) {
            let mut fields = entry.split(':');
            let key = decimal(fields.next())?;
            let source =
                u32::try_from(decimal(fields.next())?).map_err(|_| EncodeError::InvalidEntry)?;
            let rights = decimal(fields.next())?;
            if fields.next().is_some()
                || source == 0
                || rights & !mnu_abi::HANDLE_RIGHT_ALL != 0
                || handles.iter().any(|previous| previous.key == key)
            {
                return Err(EncodeError::InvalidEntry);
            }
            if handles.len() >= process_create::MAX_HANDLES {
                return Err(EncodeError::TooLarge);
            }
            handles.push(HandleGrant {
                key,
                source,
                target: 0,
                rights,
            });
        } else if let Some(entry) = item.strip_prefix(INHERITED_VALUE_PREFIX) {
            let mut fields = entry.split(':');
            let key = decimal(fields.next())?;
            let value = decimal(fields.next())?;
            if fields.next().is_some() || values.iter().any(|previous| previous.key == key) {
                return Err(EncodeError::InvalidEntry);
            }
            if values.len() >= process_create::MAX_VALUES {
                return Err(EncodeError::TooLarge);
            }
            values.push(Value { key, value });
        } else if item.starts_with("__MNU_EXEC_") {
            // Legacy identity/digest fields must not become ordinary argv or
            // grant authorization. Native creation consumes a separate permit.
            return Err(EncodeError::InvalidEntry);
        } else {
            // Empty argv entries are legal, unlike legacy metadata delimiters.
            arguments.push(item.as_bytes());
        }
    }
    let mut startup = vec![0; process_create::MAX_REQUEST_BYTES];
    let length = crate::process_image::encode_initial_stack_for_process(
        &arguments,
        &environment,
        identity.as_bytes(),
        random,
        &[],
        process,
        &mut startup,
    )
    .map_err(EncodeError::Startup)?;
    let mut metadata = vec![0; process_create::MAX_REQUEST_BYTES];
    let length = process_create::encode(
        identity,
        argument_zero,
        &startup[..length],
        &handles,
        &values,
        &mut metadata,
    )
    .map_err(EncodeError::Creation)?;
    metadata.truncate(length);
    Ok(metadata)
}

fn decimal(field: Option<&str>) -> Result<u64, EncodeError> {
    let field = field.ok_or(EncodeError::InvalidEntry)?;
    if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(EncodeError::InvalidEntry);
    }
    field.parse().map_err(|_| EncodeError::InvalidEntry)
}
