pub const MAGIC: u32 = u32::from_le_bytes(*b"SESS");
pub const VERSION: u16 = 1;
pub const REQUEST_LEN: usize = 16;
pub const RESPONSE_LEN: usize = 24;

pub const LOCK: u16 = 1;
pub const LOG_OUT: u16 = 2;
const RESPONSE_BIT: u16 = 0x8000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Lock,
    LogOut,
}

impl Action {
    pub const fn opcode(self) -> u16 {
        match self {
            Self::Lock => LOCK,
            Self::LogOut => LOG_OUT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub action: Action,
    pub session_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub action: Action,
    pub session_id: u64,
    pub status: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    UnknownOpcode,
    InvalidSession,
    InvalidReserved,
}

pub fn encode_request(request: Request) -> [u8; REQUEST_LEN] {
    let mut output = [0u8; REQUEST_LEN];
    encode_header(&mut output, request.action.opcode(), request.session_id);
    output
}

pub fn decode_request(bytes: &[u8]) -> Result<Request, DecodeError> {
    let (opcode, session_id) = decode_header(bytes, REQUEST_LEN)?;
    Ok(Request {
        action: decode_action(opcode)?,
        session_id,
    })
}

pub fn encode_response(response: Response) -> [u8; RESPONSE_LEN] {
    let mut output = [0u8; RESPONSE_LEN];
    encode_header(
        &mut output,
        response.action.opcode() | RESPONSE_BIT,
        response.session_id,
    );
    output[16..20].copy_from_slice(&response.status.to_le_bytes());
    output
}

pub fn decode_response(bytes: &[u8]) -> Result<Response, DecodeError> {
    let (opcode, session_id) = decode_header(bytes, RESPONSE_LEN)?;
    if opcode & RESPONSE_BIT == 0 {
        return Err(DecodeError::UnknownOpcode);
    }
    if bytes[20..24] != [0; 4] {
        return Err(DecodeError::InvalidReserved);
    }
    Ok(Response {
        action: decode_action(opcode & !RESPONSE_BIT)?,
        session_id,
        status: i32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
    })
}

fn encode_header(output: &mut [u8], opcode: u16, session_id: u64) {
    output[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&opcode.to_le_bytes());
    output[8..16].copy_from_slice(&session_id.to_le_bytes());
}

fn decode_header(bytes: &[u8], expected_len: usize) -> Result<(u16, u64), DecodeError> {
    if bytes.len() != expected_len {
        return Err(DecodeError::InvalidLength);
    }
    if u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    if u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION {
        return Err(DecodeError::UnsupportedVersion);
    }
    let opcode = u16::from_le_bytes([bytes[6], bytes[7]]);
    let session_id = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    if session_id == 0 {
        return Err(DecodeError::InvalidSession);
    }
    Ok((opcode, session_id))
}

fn decode_action(opcode: u16) -> Result<Action, DecodeError> {
    match opcode {
        LOCK => Ok(Action::Lock),
        LOG_OUT => Ok(Action::LogOut),
        _ => Err(DecodeError::UnknownOpcode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_and_golden_bytes() {
        let request = Request {
            action: Action::LogOut,
            session_id: 0x100f_0e0d_0c0b_0a09,
        };
        let encoded = encode_request(request);
        assert_eq!(
            encoded,
            [
                b'S', b'E', b'S', b'S', 1, 0, 2, 0, 9, 10, 11, 12, 13, 14, 15, 16,
            ]
        );
        assert_eq!(decode_request(&encoded), Ok(request));
    }

    #[test]
    fn response_round_trip_validates_reserved() {
        let response = Response {
            action: Action::Lock,
            session_id: u64::MAX,
            status: -22,
        };
        let mut encoded = encode_response(response);
        assert_eq!(decode_response(&encoded), Ok(response));
        encoded[20] = 1;
        assert_eq!(decode_response(&encoded), Err(DecodeError::InvalidReserved));
    }

    #[test]
    fn rejects_invalid_headers_and_lengths() {
        let valid = encode_request(Request {
            action: Action::Lock,
            session_id: 1,
        });
        assert_eq!(
            decode_request(&valid[..15]),
            Err(DecodeError::InvalidLength)
        );
        let mut bytes = valid;
        bytes[0] = 0;
        assert_eq!(decode_request(&bytes), Err(DecodeError::InvalidMagic));
        bytes = valid;
        bytes[4] = 2;
        assert_eq!(decode_request(&bytes), Err(DecodeError::UnsupportedVersion));
        bytes = valid;
        bytes[6..8].copy_from_slice(&9u16.to_le_bytes());
        assert_eq!(decode_request(&bytes), Err(DecodeError::UnknownOpcode));
        bytes = valid;
        bytes[8..16].fill(0);
        assert_eq!(decode_request(&bytes), Err(DecodeError::InvalidSession));
    }
}
