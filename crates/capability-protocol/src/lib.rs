#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{borrow::ToOwned, string::String, vec, vec::Vec};
use core::convert::TryFrom;
use core::fmt;
use core::mem::{offset_of, size_of};

pub const CAPABILITY_PROMPT_OPCODE: u32 = 0x4350_5251;
pub const CAPABILITY_RESPONSE_OPCODE: u32 = 0x4350_5252;
pub const CAPABILITY_DECISION_OPCODE: u32 = 0x4350_5244;
pub const CAPABILITY_PERSISTENT_QUERY_OPCODE: u32 = 0x4350_5150;
pub const PROTOCOL_VERSION: u32 = 1;

pub const MAX_CAPABILITY_NAME_LEN: usize = 64;
pub const MAX_EXECUTABLE_PATH_LEN: usize = 256;
pub const MAX_RESOURCE_PATH_LEN: usize = 256;
pub const MAX_REASON_LEN: usize = 128;
pub const MAX_PAYLOAD_SIZE: usize = size_of::<CapabilityRequest>();
pub const MAX_DECISION_PAYLOAD_SIZE: usize = size_of::<CapabilityDecisionRequest>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    TooShort,
    InvalidLength,
    UnknownOpcode,
    InvalidUtf8,
    InvalidField,
    UnsupportedVersion,
    TrailingBytes,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TooShort => "payload too short",
            Self::InvalidLength => "invalid payload length",
            Self::UnknownOpcode => "unknown opcode",
            Self::InvalidUtf8 => "invalid utf-8",
            Self::InvalidField => "invalid field",
            Self::UnsupportedVersion => "unsupported version",
            Self::TrailingBytes => "trailing bytes present",
        };
        f.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtocolError {}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapabilityDecision {
    AllowOnce = 1,
    AllowForProcess = 2,
    AllowPersistently = 3,
    AllowAllUserGrantable = 4,
    #[default]
    Deny = 5,
}

impl TryFrom<u32> for CapabilityDecision {
    type Error = ProtocolError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AllowOnce),
            2 => Ok(Self::AllowForProcess),
            3 => Ok(Self::AllowPersistently),
            4 => Ok(Self::AllowAllUserGrantable),
            5 => Ok(Self::Deny),
            _ => Err(ProtocolError::InvalidField),
        }
    }
}

impl From<CapabilityDecision> for u32 {
    fn from(value: CapabilityDecision) -> Self {
        value as u32
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapabilityClass {
    #[default]
    UserGrantable = 1,
    Privileged = 2,
    SystemOnly = 3,
}

impl TryFrom<u32> for CapabilityClass {
    type Error = ProtocolError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::UserGrantable),
            2 => Ok(Self::Privileged),
            3 => Ok(Self::SystemOnly),
            _ => Err(ProtocolError::InvalidField),
        }
    }
}

impl From<CapabilityClass> for u32 {
    fn from(value: CapabilityClass) -> Self {
        value as u32
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutableIdentity {
    pub path_len: u16,
    pub reserved: u16,
    pub digest: [u8; 32],
    pub path: [u8; MAX_EXECUTABLE_PATH_LEN],
}

impl Default for ExecutableIdentity {
    fn default() -> Self {
        Self {
            path_len: 0,
            reserved: 0,
            digest: [0; 32],
            path: [0; MAX_EXECUTABLE_PATH_LEN],
        }
    }
}

impl ExecutableIdentity {
    pub fn set_path(&mut self, path: &str) -> Result<(), ProtocolError> {
        let bytes = path.as_bytes();
        if bytes.len() > self.path.len() || bytes.len() > u16::MAX as usize {
            return Err(ProtocolError::InvalidLength);
        }
        self.path_len = bytes.len() as u16;
        self.path[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn path(&self) -> Result<&str, ProtocolError> {
        field_str(&self.path, self.path_len)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.reserved != 0 {
            return Err(ProtocolError::InvalidField);
        }
        self.path()?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceDescriptor {
    pub kind: u32,
    pub path_len: u16,
    pub reserved: u16,
    pub path: [u8; MAX_RESOURCE_PATH_LEN],
}

impl Default for ResourceDescriptor {
    fn default() -> Self {
        Self {
            kind: 0,
            path_len: 0,
            reserved: 0,
            path: [0; MAX_RESOURCE_PATH_LEN],
        }
    }
}

impl ResourceDescriptor {
    pub fn set_path(&mut self, kind: u32, path: &str) -> Result<(), ProtocolError> {
        let bytes = path.as_bytes();
        if bytes.len() > self.path.len() || bytes.len() > u16::MAX as usize {
            return Err(ProtocolError::InvalidLength);
        }
        self.kind = kind;
        self.path_len = bytes.len() as u16;
        self.path[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn path(&self) -> Result<Option<&str>, ProtocolError> {
        if self.path_len == 0 {
            return Ok(None);
        }
        field_str(&self.path, self.path_len).map(Some)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.reserved != 0 {
            return Err(ProtocolError::InvalidField);
        }
        if self.path_len == 0 {
            return Ok(());
        }
        self.path()?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityRequest {
    pub opcode: u32,
    pub process_id: u64,
    pub executable: ExecutableIdentity,
    pub capability_class: CapabilityClass,
    pub capability_len: u16,
    pub resource: ResourceDescriptor,
    pub reason_len: u16,
    pub interactive: u8,
    pub decision_scope: u8,
    pub reserved0: u16,
    pub capability: [u8; MAX_CAPABILITY_NAME_LEN],
    pub reason: [u8; MAX_REASON_LEN],
}

impl Default for CapabilityRequest {
    fn default() -> Self {
        Self {
            opcode: 0,
            process_id: 0,
            executable: ExecutableIdentity::default(),
            capability_class: CapabilityClass::UserGrantable,
            capability_len: 0,
            resource: ResourceDescriptor::default(),
            reason_len: 0,
            interactive: 0,
            decision_scope: 0,
            reserved0: 0,
            capability: [0; MAX_CAPABILITY_NAME_LEN],
            reason: [0; MAX_REASON_LEN],
        }
    }
}

impl CapabilityRequest {
    pub fn new_prompt(
        process_id: u64,
        executable_path: &str,
        digest: [u8; 32],
        capability: &str,
        resource_path: Option<&str>,
        reason: Option<&str>,
        interactive: bool,
        capability_class: CapabilityClass,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_opcode(
            CAPABILITY_PROMPT_OPCODE,
            process_id,
            executable_path,
            digest,
            capability,
            resource_path,
            reason,
            interactive,
            capability_class,
        )
    }

    pub fn new_persistent_query(
        process_id: u64,
        executable_path: &str,
        digest: [u8; 32],
        capability: &str,
        resource_path: Option<&str>,
        reason: Option<&str>,
        capability_class: CapabilityClass,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_opcode(
            CAPABILITY_PERSISTENT_QUERY_OPCODE,
            process_id,
            executable_path,
            digest,
            capability,
            resource_path,
            reason,
            false,
            capability_class,
        )
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self.opcode {
            CAPABILITY_PROMPT_OPCODE | CAPABILITY_PERSISTENT_QUERY_OPCODE => {}
            _ => return Err(ProtocolError::UnknownOpcode),
        }
        if self.process_id == 0 {
            return Err(ProtocolError::InvalidField);
        }
        if self.reserved0 != 0 || self.executable.reserved != 0 || self.resource.reserved != 0 {
            return Err(ProtocolError::InvalidField);
        }
        self.executable.validate()?;
        self.resource.validate()?;
        field_str(&self.capability, self.capability_len)?;
        field_str(&self.reason, self.reason_len)?;
        Ok(())
    }

    pub fn capability(&self) -> Result<&str, ProtocolError> {
        field_str(&self.capability, self.capability_len)
    }

    pub fn executable_path(&self) -> Result<&str, ProtocolError> {
        self.executable.path()
    }

    pub fn resource_path(&self) -> Result<Option<&str>, ProtocolError> {
        self.resource.path()
    }

    pub fn reason(&self) -> Result<Option<&str>, ProtocolError> {
        if self.reason_len == 0 {
            return Ok(None);
        }
        field_str(&self.reason, self.reason_len).map(Some)
    }

    #[cfg(feature = "alloc")]
    pub fn encode_vec(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = vec![0u8; size_of::<Self>()];
        encode_request(self, &mut bytes)?;
        Ok(bytes)
    }

    #[cfg(feature = "alloc")]
    pub fn capability_string(&self) -> Result<String, ProtocolError> {
        Ok(self.capability()?.to_owned())
    }

    #[cfg(feature = "alloc")]
    pub fn executable_path_string(&self) -> Result<String, ProtocolError> {
        Ok(self.executable_path()?.to_owned())
    }

    fn new_with_opcode(
        opcode: u32,
        process_id: u64,
        executable_path: &str,
        digest: [u8; 32],
        capability: &str,
        resource_path: Option<&str>,
        reason: Option<&str>,
        interactive: bool,
        capability_class: CapabilityClass,
    ) -> Result<Self, ProtocolError> {
        let mut request = Self {
            opcode,
            process_id,
            executable: ExecutableIdentity::default(),
            capability_class,
            capability_len: 0,
            resource: ResourceDescriptor::default(),
            reason_len: 0,
            interactive: interactive as u8,
            decision_scope: 0,
            reserved0: 0,
            capability: [0; MAX_CAPABILITY_NAME_LEN],
            reason: [0; MAX_REASON_LEN],
        };
        request.executable.set_path(executable_path)?;
        request.executable.digest = digest;
        request.set_capability(capability)?;
        if let Some(resource_path) = resource_path {
            request.resource.set_path(1, resource_path)?;
        }
        if let Some(reason) = reason {
            request.set_reason(reason)?;
        }
        Ok(request)
    }

    pub fn set_capability(&mut self, capability: &str) -> Result<(), ProtocolError> {
        let bytes = capability.as_bytes();
        if bytes.len() > self.capability.len() || bytes.len() > u16::MAX as usize {
            return Err(ProtocolError::InvalidLength);
        }
        self.capability_len = bytes.len() as u16;
        self.capability[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn set_reason(&mut self, reason: &str) -> Result<(), ProtocolError> {
        let bytes = reason.as_bytes();
        if bytes.len() > self.reason.len() || bytes.len() > u16::MAX as usize {
            return Err(ProtocolError::InvalidLength);
        }
        self.reason_len = bytes.len() as u16;
        self.reason[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityDecisionRequest {
    pub opcode: u32,
    pub decision: CapabilityDecision,
    pub reserved: u64,
    pub request: CapabilityRequest,
}

pub type CapabilityPromptRequest = CapabilityRequest;
pub type CapabilityExecutableIdentity = ExecutableIdentity;
pub type CapabilityResourceDescriptor = ResourceDescriptor;

impl CapabilityDecisionRequest {
    pub fn new(decision: CapabilityDecision, request: CapabilityRequest) -> Self {
        Self {
            opcode: CAPABILITY_DECISION_OPCODE,
            decision,
            reserved: request.process_id,
            request,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.opcode != CAPABILITY_DECISION_OPCODE {
            return Err(ProtocolError::UnknownOpcode);
        }
        self.request.validate()?;
        Ok(())
    }

    #[cfg(feature = "alloc")]
    pub fn encode_vec(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = vec![0u8; size_of::<Self>()];
        encode_decision_request(self, &mut bytes)?;
        Ok(bytes)
    }
}

pub fn decode_request(bytes: &[u8]) -> Result<CapabilityRequest, ProtocolError> {
    if bytes.len() < size_of::<CapabilityRequest>() {
        return Err(ProtocolError::TooShort);
    }
    if bytes.len() > size_of::<CapabilityRequest>() {
        return Err(ProtocolError::TrailingBytes);
    }
    let opcode = read_u32(bytes, offset_of!(CapabilityRequest, opcode));
    if opcode != CAPABILITY_PROMPT_OPCODE && opcode != CAPABILITY_PERSISTENT_QUERY_OPCODE {
        return Err(ProtocolError::UnknownOpcode);
    }
    let mut request = CapabilityRequest::default();
    request.opcode = opcode;
    request.process_id = read_u64(bytes, offset_of!(CapabilityRequest, process_id));
    request.executable.path_len = read_u16(
        bytes,
        offset_of!(CapabilityRequest, executable) + offset_of!(ExecutableIdentity, path_len),
    );
    request.executable.reserved = read_u16(
        bytes,
        offset_of!(CapabilityRequest, executable) + offset_of!(ExecutableIdentity, reserved),
    );
    copy_array(
        bytes,
        offset_of!(CapabilityRequest, executable) + offset_of!(ExecutableIdentity, digest),
        &mut request.executable.digest,
    );
    copy_array(
        bytes,
        offset_of!(CapabilityRequest, executable) + offset_of!(ExecutableIdentity, path),
        &mut request.executable.path,
    );
    request.capability_class = CapabilityClass::try_from(read_u32(
        bytes,
        offset_of!(CapabilityRequest, capability_class),
    ))?;
    request.capability_len = read_u16(bytes, offset_of!(CapabilityRequest, capability_len));
    request.resource.kind = read_u32(
        bytes,
        offset_of!(CapabilityRequest, resource) + offset_of!(ResourceDescriptor, kind),
    );
    request.resource.path_len = read_u16(
        bytes,
        offset_of!(CapabilityRequest, resource) + offset_of!(ResourceDescriptor, path_len),
    );
    request.resource.reserved = read_u16(
        bytes,
        offset_of!(CapabilityRequest, resource) + offset_of!(ResourceDescriptor, reserved),
    );
    copy_array(
        bytes,
        offset_of!(CapabilityRequest, resource) + offset_of!(ResourceDescriptor, path),
        &mut request.resource.path,
    );
    request.reason_len = read_u16(bytes, offset_of!(CapabilityRequest, reason_len));
    request.interactive = read_u8(bytes, offset_of!(CapabilityRequest, interactive));
    request.decision_scope = read_u8(bytes, offset_of!(CapabilityRequest, decision_scope));
    request.reserved0 = read_u16(bytes, offset_of!(CapabilityRequest, reserved0));
    copy_array(
        bytes,
        offset_of!(CapabilityRequest, capability),
        &mut request.capability,
    );
    copy_array(
        bytes,
        offset_of!(CapabilityRequest, reason),
        &mut request.reason,
    );
    request.validate()?;
    Ok(request)
}

pub fn decode_decision_request(bytes: &[u8]) -> Result<CapabilityDecisionRequest, ProtocolError> {
    if bytes.len() < size_of::<CapabilityDecisionRequest>() {
        return Err(ProtocolError::TooShort);
    }
    if bytes.len() > size_of::<CapabilityDecisionRequest>() {
        return Err(ProtocolError::TrailingBytes);
    }
    let opcode = read_u32(bytes, offset_of!(CapabilityDecisionRequest, opcode));
    if opcode != CAPABILITY_DECISION_OPCODE {
        return Err(ProtocolError::UnknownOpcode);
    }
    let decision = CapabilityDecision::try_from(read_u32(
        bytes,
        offset_of!(CapabilityDecisionRequest, decision),
    ))?;
    let reserved = read_u64(bytes, offset_of!(CapabilityDecisionRequest, reserved));
    let request_offset = offset_of!(CapabilityDecisionRequest, request);
    let request =
        decode_request(&bytes[request_offset..request_offset + size_of::<CapabilityRequest>()])?;
    Ok(CapabilityDecisionRequest {
        opcode,
        decision,
        reserved,
        request,
    })
}

pub fn encode_request(
    request: &CapabilityRequest,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if output.len() < size_of::<CapabilityRequest>() {
        return Err(ProtocolError::TooShort);
    }
    request.validate()?;
    let size = size_of::<CapabilityRequest>();
    output[..size].fill(0);
    write_u32(
        output,
        offset_of!(CapabilityRequest, opcode),
        request.opcode,
    );
    write_u64(
        output,
        offset_of!(CapabilityRequest, process_id),
        request.process_id,
    );
    write_u16(
        output,
        offset_of!(CapabilityRequest, executable) + offset_of!(ExecutableIdentity, path_len),
        request.executable.path_len,
    );
    write_u16(
        output,
        offset_of!(CapabilityRequest, executable) + offset_of!(ExecutableIdentity, reserved),
        request.executable.reserved,
    );
    copy_array_out(
        output,
        offset_of!(CapabilityRequest, executable) + offset_of!(ExecutableIdentity, digest),
        &request.executable.digest,
    );
    copy_array_out(
        output,
        offset_of!(CapabilityRequest, executable) + offset_of!(ExecutableIdentity, path),
        &request.executable.path,
    );
    write_u32(
        output,
        offset_of!(CapabilityRequest, capability_class),
        u32::from(request.capability_class),
    );
    write_u16(
        output,
        offset_of!(CapabilityRequest, capability_len),
        request.capability_len,
    );
    write_u32(
        output,
        offset_of!(CapabilityRequest, resource) + offset_of!(ResourceDescriptor, kind),
        request.resource.kind,
    );
    write_u16(
        output,
        offset_of!(CapabilityRequest, resource) + offset_of!(ResourceDescriptor, path_len),
        request.resource.path_len,
    );
    write_u16(
        output,
        offset_of!(CapabilityRequest, resource) + offset_of!(ResourceDescriptor, reserved),
        request.resource.reserved,
    );
    copy_array_out(
        output,
        offset_of!(CapabilityRequest, resource) + offset_of!(ResourceDescriptor, path),
        &request.resource.path,
    );
    write_u16(
        output,
        offset_of!(CapabilityRequest, reason_len),
        request.reason_len,
    );
    write_u8(
        output,
        offset_of!(CapabilityRequest, interactive),
        request.interactive,
    );
    write_u8(
        output,
        offset_of!(CapabilityRequest, decision_scope),
        request.decision_scope,
    );
    write_u16(
        output,
        offset_of!(CapabilityRequest, reserved0),
        request.reserved0,
    );
    copy_array_out(
        output,
        offset_of!(CapabilityRequest, capability),
        &request.capability,
    );
    copy_array_out(
        output,
        offset_of!(CapabilityRequest, reason),
        &request.reason,
    );
    Ok(size)
}

pub fn encode_decision_request(
    request: &CapabilityDecisionRequest,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if output.len() < size_of::<CapabilityDecisionRequest>() {
        return Err(ProtocolError::TooShort);
    }
    request.validate()?;
    let size = size_of::<CapabilityDecisionRequest>();
    output[..size].fill(0);
    write_u32(
        output,
        offset_of!(CapabilityDecisionRequest, opcode),
        request.opcode,
    );
    write_u32(
        output,
        offset_of!(CapabilityDecisionRequest, decision),
        u32::from(request.decision),
    );
    write_u64(
        output,
        offset_of!(CapabilityDecisionRequest, reserved),
        request.reserved,
    );
    let request_offset = offset_of!(CapabilityDecisionRequest, request);
    encode_request(
        &request.request,
        &mut output[request_offset..request_offset + size_of::<CapabilityRequest>()],
    )?;
    Ok(size)
}

#[cfg(feature = "alloc")]
pub fn encode_request_vec(request: &CapabilityRequest) -> Result<Vec<u8>, ProtocolError> {
    request.encode_vec()
}

#[cfg(feature = "alloc")]
pub fn encode_decision_request_vec(
    request: &CapabilityDecisionRequest,
) -> Result<Vec<u8>, ProtocolError> {
    request.encode_vec()
}

fn field_str<'a, const N: usize>(bytes: &'a [u8; N], len: u16) -> Result<&'a str, ProtocolError> {
    let len = len as usize;
    if len > N {
        return Err(ProtocolError::InvalidLength);
    }
    core::str::from_utf8(&bytes[..len]).map_err(|_| ProtocolError::InvalidUtf8)
}

fn read_u8(bytes: &[u8], offset: usize) -> u8 {
    bytes[offset]
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_ne_bytes(buf)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_ne_bytes(buf)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_ne_bytes(buf)
}

fn copy_array<const N: usize>(bytes: &[u8], offset: usize, output: &mut [u8; N]) {
    output.copy_from_slice(&bytes[offset..offset + N]);
}

fn write_u8(bytes: &mut [u8], offset: usize, value: u8) {
    bytes[offset] = value;
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn copy_array_out<const N: usize>(bytes: &mut [u8], offset: usize, input: &[u8; N]) {
    bytes[offset..offset + N].copy_from_slice(input);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn opcodes_match_expected() {
        assert_eq!(CAPABILITY_PROMPT_OPCODE, 0x4350_5251);
        assert_eq!(CAPABILITY_RESPONSE_OPCODE, 0x4350_5252);
        assert_eq!(CAPABILITY_DECISION_OPCODE, 0x4350_5244);
        assert_eq!(CAPABILITY_PERSISTENT_QUERY_OPCODE, 0x4350_5150);
    }

    #[test]
    fn layout_matches_expected() {
        assert_eq!(MAX_CAPABILITY_NAME_LEN, 64);
        assert_eq!(MAX_EXECUTABLE_PATH_LEN, 256);
        assert_eq!(MAX_RESOURCE_PATH_LEN, 256);
        assert_eq!(MAX_REASON_LEN, 128);

        assert_eq!(size_of::<ExecutableIdentity>(), 292);
        assert_eq!(align_of::<ExecutableIdentity>(), 2);
        assert_eq!(offset_of!(ExecutableIdentity, path_len), 0);
        assert_eq!(offset_of!(ExecutableIdentity, reserved), 2);
        assert_eq!(offset_of!(ExecutableIdentity, digest), 4);
        assert_eq!(offset_of!(ExecutableIdentity, path), 36);
        assert_eq!(ExecutableIdentity::default().digest.len(), 32);
        assert_eq!(ExecutableIdentity::default().path.len(), 256);

        assert_eq!(size_of::<ResourceDescriptor>(), 264);
        assert_eq!(align_of::<ResourceDescriptor>(), 4);
        assert_eq!(offset_of!(ResourceDescriptor, kind), 0);
        assert_eq!(offset_of!(ResourceDescriptor, path_len), 4);
        assert_eq!(offset_of!(ResourceDescriptor, reserved), 6);
        assert_eq!(offset_of!(ResourceDescriptor, path), 8);
        assert_eq!(ResourceDescriptor::default().path.len(), 256);

        assert_eq!(size_of::<CapabilityRequest>(), 784);
        assert_eq!(align_of::<CapabilityRequest>(), 8);
        assert_eq!(offset_of!(CapabilityRequest, opcode), 0);
        assert_eq!(offset_of!(CapabilityRequest, process_id), 8);
        assert_eq!(offset_of!(CapabilityRequest, executable), 16);
        assert_eq!(offset_of!(CapabilityRequest, capability_class), 308);
        assert_eq!(offset_of!(CapabilityRequest, capability_len), 312);
        assert_eq!(offset_of!(CapabilityRequest, resource), 316);
        assert_eq!(offset_of!(CapabilityRequest, reason_len), 580);
        assert_eq!(offset_of!(CapabilityRequest, interactive), 582);
        assert_eq!(offset_of!(CapabilityRequest, decision_scope), 583);
        assert_eq!(offset_of!(CapabilityRequest, reserved0), 584);
        assert_eq!(offset_of!(CapabilityRequest, capability), 586);
        assert_eq!(offset_of!(CapabilityRequest, reason), 650);
        assert_eq!(CapabilityRequest::default().capability.len(), 64);
        assert_eq!(CapabilityRequest::default().reason.len(), 128);

        assert_eq!(size_of::<CapabilityDecisionRequest>(), 800);
        assert_eq!(align_of::<CapabilityDecisionRequest>(), 8);
        assert_eq!(offset_of!(CapabilityDecisionRequest, opcode), 0);
        assert_eq!(offset_of!(CapabilityDecisionRequest, decision), 4);
        assert_eq!(offset_of!(CapabilityDecisionRequest, reserved), 8);
        assert_eq!(offset_of!(CapabilityDecisionRequest, request), 16);
    }

    fn golden_request() -> CapabilityRequest {
        CapabilityRequest::new_prompt(
            0x0102_0304_0506_0708,
            "/x",
            [0xa5; 32],
            "cap",
            Some("/r"),
            Some("why"),
            true,
            CapabilityClass::UserGrantable,
        )
        .unwrap()
    }

    fn golden_request_bytes() -> [u8; 784] {
        let mut expected = [0u8; 784];
        expected[0..4].copy_from_slice(&[0x51, 0x52, 0x50, 0x43]);
        expected[8..16].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        expected[16..18].copy_from_slice(&[2, 0]);
        expected[20..52].fill(0xa5);
        expected[52..54].copy_from_slice(b"/x");
        expected[308..312].copy_from_slice(&[1, 0, 0, 0]);
        expected[312..314].copy_from_slice(&[3, 0]);
        expected[316..320].copy_from_slice(&[1, 0, 0, 0]);
        expected[320..322].copy_from_slice(&[2, 0]);
        expected[324..326].copy_from_slice(b"/r");
        expected[580..582].copy_from_slice(&[3, 0]);
        expected[582] = 1;
        expected[586..589].copy_from_slice(b"cap");
        expected[650..653].copy_from_slice(b"why");
        expected
    }

    #[test]
    fn request_encoding_matches_golden_bytes() {
        let request = golden_request();
        let mut actual = [0u8; 784];
        assert_eq!(encode_request(&request, &mut actual), Ok(784));
        assert_eq!(actual, golden_request_bytes());
    }

    #[test]
    fn decision_encoding_matches_golden_bytes() {
        let decision =
            CapabilityDecisionRequest::new(CapabilityDecision::AllowPersistently, golden_request());
        let mut actual = [0u8; 800];
        assert_eq!(encode_decision_request(&decision, &mut actual), Ok(800));

        let mut expected = [0u8; 800];
        expected[0..4].copy_from_slice(&[0x44, 0x52, 0x50, 0x43]);
        expected[4..8].copy_from_slice(&[3, 0, 0, 0]);
        expected[8..16].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        expected[16..].copy_from_slice(&golden_request_bytes());
        assert_eq!(actual, expected);
    }

    #[test]
    fn encode_decode_request_roundtrip() {
        let request = CapabilityRequest::new_prompt(
            42,
            "/bin/tool",
            [7; 32],
            "fs.read.user",
            Some("/home/user/file.txt"),
            Some("file access"),
            true,
            CapabilityClass::UserGrantable,
        )
        .unwrap();
        let mut bytes = vec![0u8; size_of::<CapabilityRequest>()];
        let len = encode_request(&request, &mut bytes).unwrap();
        assert_eq!(len, size_of::<CapabilityRequest>());
        assert_eq!(decode_request(&bytes).unwrap(), request);
    }

    #[test]
    fn encode_decode_decision_roundtrip() {
        let request = CapabilityRequest::new_persistent_query(
            7,
            "/bin/tool",
            [1; 32],
            "window.overlay",
            None,
            Some("prompt"),
            CapabilityClass::UserGrantable,
        )
        .unwrap();
        let decision = CapabilityDecisionRequest::new(CapabilityDecision::AllowOnce, request);
        let mut bytes = vec![0u8; size_of::<CapabilityDecisionRequest>()];
        let len = encode_decision_request(&decision, &mut bytes).unwrap();
        assert_eq!(len, size_of::<CapabilityDecisionRequest>());
        assert_eq!(decode_decision_request(&bytes).unwrap(), decision);
    }

    #[test]
    fn rejects_invalid_inputs() {
        let short_request = [0u8; 783];
        assert_eq!(decode_request(&short_request), Err(ProtocolError::TooShort));
        let short_decision = [0u8; 799];
        assert_eq!(
            decode_decision_request(&short_decision),
            Err(ProtocolError::TooShort)
        );

        let mut bytes = vec![0u8; size_of::<CapabilityRequest>() + 1];
        assert_eq!(
            decode_request(&bytes).unwrap_err(),
            ProtocolError::TrailingBytes
        );
        bytes.truncate(size_of::<CapabilityRequest>());
        bytes[..4].copy_from_slice(&0xdead_beefu32.to_ne_bytes());
        assert_eq!(
            decode_request(&bytes).unwrap_err(),
            ProtocolError::UnknownOpcode
        );

        let mut decision_bytes = vec![0u8; size_of::<CapabilityDecisionRequest>()];
        decision_bytes[..4].copy_from_slice(&0xdead_beefu32.to_ne_bytes());
        assert_eq!(
            decode_decision_request(&decision_bytes),
            Err(ProtocolError::UnknownOpcode)
        );
    }

    #[test]
    fn decodes_unaligned_input() {
        let request = golden_request();
        let mut request_storage = vec![0u8; size_of::<CapabilityRequest>() + 1];
        encode_request(&request, &mut request_storage[1..]).unwrap();
        assert_eq!(decode_request(&request_storage[1..]), Ok(request));

        let decision =
            CapabilityDecisionRequest::new(CapabilityDecision::AllowPersistently, request);
        let mut decision_storage = vec![0u8; size_of::<CapabilityDecisionRequest>() + 1];
        encode_decision_request(&decision, &mut decision_storage[1..]).unwrap();
        assert_eq!(
            decode_decision_request(&decision_storage[1..]),
            Ok(decision)
        );
    }

    #[test]
    fn string_validation_works() {
        let mut request = CapabilityRequest::new_prompt(
            1,
            "/bin/tool",
            [0; 32],
            "fs.read.user",
            None,
            None,
            false,
            CapabilityClass::UserGrantable,
        )
        .unwrap();
        request.capability[0] = 0xff;
        assert_eq!(request.capability(), Err(ProtocolError::InvalidUtf8));
    }
}
