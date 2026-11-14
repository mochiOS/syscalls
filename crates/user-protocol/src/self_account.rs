//! Self operations carry no username, UID or authority claims. The service
//! obtains the account from the kernel-authenticated caller and POSIX session.
use super::*;
pub struct Info {
    pub request_id: u64,
}
impl Info {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require_output(output, HEADER_LEN)?;
        write_header(output, Opcode::SelfInfo, self.request_id, 0);
        Ok(HEADER_LEN)
    }
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::SelfInfo)?;
        if header.payload_len != 0 {
            return Err(DecodeError::InvalidLength);
        }
        Ok(Self {
            request_id: header.request_id,
        })
    }
}
pub struct ChangePassword<'a> {
    pub request_id: u64,
    pub current: &'a [u8],
    pub replacement: &'a [u8],
}
impl ChangePassword<'_> {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        if self.current.len() > MAX_PASSWORD_LEN || self.replacement.len() > MAX_PASSWORD_LEN {
            return Err(EncodeError::ValueTooLong);
        }
        let size = HEADER_LEN + 8 + self.current.len() + self.replacement.len();
        require_output(output, size)?;
        write_header(
            output,
            Opcode::ChangeOwnPassword,
            self.request_id,
            (size - HEADER_LEN) as u32,
        );
        output[HEADER_LEN..HEADER_LEN + 8].fill(0);
        output[HEADER_LEN..HEADER_LEN + 2]
            .copy_from_slice(&(self.current.len() as u16).to_le_bytes());
        output[HEADER_LEN + 2..HEADER_LEN + 4]
            .copy_from_slice(&(self.replacement.len() as u16).to_le_bytes());
        output[HEADER_LEN + 8..HEADER_LEN + 8 + self.current.len()].copy_from_slice(self.current);
        output[HEADER_LEN + 8 + self.current.len()..size].copy_from_slice(self.replacement);
        Ok(size)
    }
}
impl<'a> ChangePassword<'a> {
    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::ChangeOwnPassword)?;
        if header.payload_len < 8 || input[HEADER_LEN + 4..HEADER_LEN + 8] != [0; 4] {
            return Err(DecodeError::InvalidLength);
        }
        let old =
            u16::from_le_bytes(input[HEADER_LEN..HEADER_LEN + 2].try_into().unwrap()) as usize;
        let new =
            u16::from_le_bytes(input[HEADER_LEN + 2..HEADER_LEN + 4].try_into().unwrap()) as usize;
        if old > MAX_PASSWORD_LEN
            || new > MAX_PASSWORD_LEN
            || input.len() != HEADER_LEN + 8 + old + new
        {
            return Err(DecodeError::InvalidLength);
        }
        Ok(Self {
            request_id: header.request_id,
            current: &input[HEADER_LEN + 8..HEADER_LEN + 8 + old],
            replacement: &input[HEADER_LEN + 8 + old..],
        })
    }
}
pub fn encode_info(
    id: u64,
    account: public_account::Record<'_>,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    require_output(output, HEADER_LEN + public_account::MAX_RECORD)?;
    let length = public_account::encode_record(account, &mut output[HEADER_LEN..])?;
    write_header(output, Opcode::SelfAccount, id, length as u32);
    Ok(HEADER_LEN + length)
}
pub fn decode_info(id: u64, input: &[u8]) -> Result<public_account::Record<'_>, DecodeError> {
    let header = expected_header(input, Opcode::SelfAccount)?;
    if header.request_id != id {
        return Err(DecodeError::InvalidLength);
    }
    public_account::decode_record(&input[HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_password_has_no_target_and_rejects_truncated_or_extended_frames() {
        let mut bytes = [0; MAX_MESSAGE_LEN];
        let n = ChangePassword {
            request_id: 7,
            current: b"current",
            replacement: b"new",
        }
        .encode(&mut bytes)
        .unwrap();
        let request = ChangePassword::decode(&bytes[..n]).unwrap();
        assert_eq!(
            (request.request_id, request.current, request.replacement),
            (7, b"current".as_slice(), b"new".as_slice())
        );
        for cut in 0..n {
            assert!(ChangePassword::decode(&bytes[..cut]).is_err());
        }
        assert!(ChangePassword::decode(&bytes[..n + 1]).is_err());
        bytes[HEADER_LEN + 4] = 1;
        assert!(ChangePassword::decode(&bytes[..n]).is_err());
    }
}
