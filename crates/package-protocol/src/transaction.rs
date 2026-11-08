//! Native package changes use a prepared, immutable transaction object. Neither
//! a pathname nor an integer in a message is an approval or transaction handle.
use super::*;

pub const PREPARE_INSTALL: u16 = 0x10;
pub const PREPARE_UPDATE: u16 = 0x11;
pub const PREPARE_REMOVE: u16 = 0x12;
pub const DESCRIBE: u16 = 0x13;
pub const COMMIT: u16 = 0x14;
pub const CONNECT: u16 = 0x15;
pub const PLAN: u16 = 0x8013;
pub const MAX_PLAN_BYTES: usize = 1024;
pub const PLAN_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
pub const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_PENDING: usize = 8;
pub const MAX_TOTAL_PACKAGE_BYTES: u64 = 1024 * 1024 * 1024;
pub const TIMEOUT_NS: u64 = 120_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Mutation {
    Install = 1,
    Update = 2,
    Remove = 3,
}
impl Mutation {
    pub const fn capability(self) -> &'static str {
        match self {
            Self::Install => "package.install",
            Self::Update => "package.update",
            Self::Remove => "package.remove",
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Install => "Install",
            Self::Update => "Update",
            Self::Remove => "Remove",
        }
    }
}
pub enum Command<'a> {
    Prepare(Mutation, &'a str),
    Describe,
    Commit,
    Connect,
}
pub fn encode_prepare(
    id: u64,
    mutation: Mutation,
    package_id: &str,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let opcode = match mutation {
        Mutation::Install => PREPARE_INSTALL,
        Mutation::Update => PREPARE_UPDATE,
        Mutation::Remove => {
            validate_package_id(package_id)?;
            PREPARE_REMOVE
        }
    };
    if mutation != Mutation::Remove && !package_id.is_empty() {
        return Err(ProtocolError::InvalidField);
    }
    encode_message(opcode, id, 0, package_id.as_bytes(), output)
}
pub fn encode_command(id: u64, commit: bool, output: &mut [u8]) -> Result<usize, ProtocolError> {
    encode_message(if commit { COMMIT } else { DESCRIBE }, id, 0, &[], output)
}
pub fn decode_command(bytes: &[u8]) -> Result<(u64, Command<'_>), ProtocolError> {
    let message = decode_message(bytes)?;
    if message.status != 0 {
        return Err(ProtocolError::InvalidField);
    }
    let command = match message.opcode {
        PREPARE_INSTALL if message.payload.is_empty() => Command::Prepare(Mutation::Install, ""),
        PREPARE_UPDATE if message.payload.is_empty() => Command::Prepare(Mutation::Update, ""),
        PREPARE_REMOVE => {
            let id = decode_text(message.payload)?;
            validate_package_id(id)?;
            Command::Prepare(Mutation::Remove, id)
        }
        DESCRIBE if message.payload.is_empty() => Command::Describe,
        COMMIT if message.payload.is_empty() => Command::Commit,
        CONNECT if message.payload.is_empty() => Command::Connect,
        _ => return Err(ProtocolError::UnexpectedOpcode),
    };
    Ok((message.request_id, command))
}
pub struct Plan<'a> {
    pub mutation: Mutation,
    pub source_digest: [u8; 32],
    pub previous_digest: [u8; 32],
    pub package_id: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub developer: &'a str,
}
pub fn encode_plan(id: u64, plan: Plan<'_>, output: &mut [u8]) -> Result<usize, ProtocolError> {
    validate_package_id(plan.package_id)?;
    let fields = [plan.package_id, plan.name, plan.version, plan.developer];
    for (value, maximum) in fields.iter().zip([
        MAX_PACKAGE_ID_LEN,
        MAX_NAME_LEN,
        MAX_VERSION_LEN,
        MAX_PACKAGE_ID_LEN,
    ]) {
        validate_text(value, maximum, false)?;
    }
    let length = 76 + fields.iter().map(|value| value.len()).sum::<usize>();
    let mut payload = [0; MAX_PLAN_BYTES - HEADER_LEN];
    if length > payload.len() {
        return Err(ProtocolError::InvalidLength);
    }
    payload[..2].copy_from_slice(&(plan.mutation as u16).to_le_bytes());
    payload[4..36].copy_from_slice(&plan.source_digest);
    payload[36..68].copy_from_slice(&plan.previous_digest);
    let mut cursor = 76;
    for (i, value) in fields.iter().enumerate() {
        payload[68 + i * 2..70 + i * 2].copy_from_slice(&(value.len() as u16).to_le_bytes());
        payload[cursor..cursor + value.len()].copy_from_slice(value.as_bytes());
        cursor += value.len();
    }
    encode_message(PLAN, id, 0, &payload[..length], output)
}
pub fn decode_plan(bytes: &[u8], id: u64) -> Result<Plan<'_>, ProtocolError> {
    if bytes.len() > MAX_PLAN_BYTES {
        return Err(ProtocolError::InvalidLength);
    }
    let m = decode_message(bytes)?;
    let p = m.payload;
    if m.opcode != PLAN || m.request_id != id || m.status != 0 || p.len() < 76 || p[2..4] != [0; 2]
    {
        return Err(ProtocolError::InvalidField);
    }
    let mutation = match u16::from_le_bytes(p[..2].try_into().unwrap()) {
        1 => Mutation::Install,
        2 => Mutation::Update,
        3 => Mutation::Remove,
        _ => return Err(ProtocolError::InvalidField),
    };
    let lengths: [usize; 4] = core::array::from_fn(|i| {
        u16::from_le_bytes(p[68 + i * 2..70 + i * 2].try_into().unwrap()) as usize
    });
    if 76 + lengths.iter().sum::<usize>() != p.len() {
        return Err(ProtocolError::InvalidLength);
    }
    let mut cursor = 76;
    let mut fields = [""; 4];
    for (i, maximum) in [
        MAX_PACKAGE_ID_LEN,
        MAX_NAME_LEN,
        MAX_VERSION_LEN,
        MAX_PACKAGE_ID_LEN,
    ]
    .iter()
    .enumerate()
    {
        fields[i] = decode_text(&p[cursor..cursor + lengths[i]])?;
        validate_text(fields[i], *maximum, false)?;
        cursor += lengths[i];
    }
    validate_package_id(fields[0])?;
    Ok(Plan {
        mutation,
        source_digest: p[4..36].try_into().unwrap(),
        previous_digest: p[36..68].try_into().unwrap(),
        package_id: fields[0],
        name: fields[1],
        version: fields[2],
        developer: fields[3],
    })
}

pub fn encode_connect(id: u64, output: &mut [u8]) -> Result<usize, ProtocolError> {
    encode_message(CONNECT, id, 0, &[], output)
}
