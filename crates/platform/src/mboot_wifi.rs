use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

#[cfg(target_os = "mochios")]
use mboot_protocol::{
    Argument, Body, Destination, KnownCommand, MAX_MESSAGE_LEN, Message, MessageType, decode_line,
    encode_to_string,
};

#[cfg(target_os = "mochios")]
const AGENT_NAME: &str = "mboot-agent.service";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WifiStatus {
    pub available: bool,
    pub enabled: bool,
    pub connected: bool,
    pub interface: String,
    pub ssid: String,
    pub address: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WifiNetwork {
    pub ssid: String,
    pub signal: i32,
    pub secured: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiError {
    Unavailable,
    InvalidReply,
    Rejected,
}

impl fmt::Display for WifiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "Wi-Fi service is unavailable",
            Self::InvalidReply => "Wi-Fi service returned an invalid response",
            Self::Rejected => "Wi-Fi operation was rejected",
        })
    }
}

#[cfg(target_os = "mochios")]
pub fn status() -> Result<WifiStatus, WifiError> {
    let response = call(KnownCommand::WifiStatus, Vec::new())?;
    Ok(WifiStatus {
        available: response.argument("available") == Some("1"),
        enabled: response.argument("enabled") == Some("1"),
        connected: response.argument("connected") == Some("1"),
        interface: decode_optional_text(response.argument("interface"))?,
        ssid: decode_optional_hex(response.argument("ssid"), 32)?,
        address: decode_optional_text(response.argument("address"))?,
    })
}

#[cfg(target_os = "mochios")]
pub fn scan() -> Result<Vec<WifiNetwork>, WifiError> {
    let response = call(KnownCommand::WifiScan, Vec::new())?;
    let Some(encoded) = response.argument("networks") else {
        return Err(WifiError::InvalidReply);
    };
    if encoded == "none" {
        return Ok(Vec::new());
    }
    encoded
        .split(',')
        .map(|entry| {
            let mut fields = entry.split(':');
            let ssid = decode_hex_text(fields.next().ok_or(WifiError::InvalidReply)?, 32)?;
            let signal = fields
                .next()
                .ok_or(WifiError::InvalidReply)?
                .parse::<i32>()
                .map_err(|_| WifiError::InvalidReply)?;
            let secured = match fields.next() {
                Some("0") => false,
                Some("1") => true,
                _ => return Err(WifiError::InvalidReply),
            };
            if fields.next().is_some() {
                return Err(WifiError::InvalidReply);
            }
            Ok(WifiNetwork {
                ssid,
                signal,
                secured,
            })
        })
        .collect()
}

#[cfg(target_os = "mochios")]
pub fn set_enabled(enabled: bool) -> Result<(), WifiError> {
    call(
        KnownCommand::WifiSetEnabled,
        alloc::vec![Argument::new("enabled", if enabled { "1" } else { "0" },)],
    )?;
    Ok(())
}

#[cfg(target_os = "mochios")]
pub fn connect(network: &WifiNetwork, password: &str) -> Result<(), WifiError> {
    let mut arguments = alloc::vec![
        Argument::new("ssid", encode_hex(network.ssid.as_bytes())),
        Argument::new("security", if network.secured { "secured" } else { "open" },),
    ];
    if network.secured {
        arguments.push(Argument::new("credential", encode_hex(password.as_bytes())));
    }
    call(KnownCommand::WifiConnect, arguments)?;
    Ok(())
}

#[cfg(target_os = "mochios")]
pub fn disconnect() -> Result<(), WifiError> {
    call(KnownCommand::WifiDisconnect, Vec::new())?;
    Ok(())
}

#[cfg(target_os = "mochios")]
fn call(command: KnownCommand, arguments: Vec<Argument>) -> Result<Message, WifiError> {
    let agent = crate::process::find_by_name(AGENT_NAME).map_err(|_| WifiError::Unavailable)?;
    if agent == 0 {
        return Err(WifiError::Unavailable);
    }
    let request_id = crate::time::ticks().unwrap_or(1).max(1);
    let request = Message::command(
        Destination::Mboot,
        MessageType::Request,
        request_id,
        command,
        arguments,
    );
    let encoded = encode_to_string(&request).map_err(|_| WifiError::InvalidReply)?;
    let mut reply = [0u8; MAX_MESSAGE_LEN];
    let raw = crate::ipc::call(agent, encoded.as_bytes(), &mut reply)
        .map_err(|_| WifiError::Unavailable)?;
    let length = (raw & 0xffff_ffff) as usize;
    let response = decode_line(reply.get(..length).ok_or(WifiError::InvalidReply)?)
        .map_err(|_| WifiError::InvalidReply)?;
    if response.request_id != request_id
        || response.destination != Destination::Mochios
        || response.message_type != MessageType::Response
    {
        return Err(WifiError::InvalidReply);
    }
    match response.body {
        Body::Ok => Ok(response),
        Body::Error(_) => Err(WifiError::Rejected),
        Body::Command(_) => Err(WifiError::InvalidReply),
    }
}

#[cfg(not(target_os = "mochios"))]
pub fn status() -> Result<WifiStatus, WifiError> {
    Err(WifiError::Unavailable)
}

#[cfg(not(target_os = "mochios"))]
pub fn scan() -> Result<Vec<WifiNetwork>, WifiError> {
    Err(WifiError::Unavailable)
}

#[cfg(not(target_os = "mochios"))]
pub fn set_enabled(_enabled: bool) -> Result<(), WifiError> {
    Err(WifiError::Unavailable)
}

#[cfg(not(target_os = "mochios"))]
pub fn connect(_network: &WifiNetwork, _password: &str) -> Result<(), WifiError> {
    Err(WifiError::Unavailable)
}

#[cfg(not(target_os = "mochios"))]
pub fn disconnect() -> Result<(), WifiError> {
    Err(WifiError::Unavailable)
}

fn decode_optional_text(value: Option<&str>) -> Result<String, WifiError> {
    match value {
        Some("none") => Ok(String::new()),
        Some(value) => Ok(value.to_string()),
        None => Err(WifiError::InvalidReply),
    }
}

fn decode_optional_hex(value: Option<&str>, maximum: usize) -> Result<String, WifiError> {
    match value {
        Some("none") => Ok(String::new()),
        Some(value) => decode_hex_text(value, maximum),
        None => Err(WifiError::InvalidReply),
    }
}

fn decode_hex_text(value: &str, maximum: usize) -> Result<String, WifiError> {
    if value.len() % 2 != 0 || value.len() > maximum.saturating_mul(2) {
        return Err(WifiError::InvalidReply);
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex(pair[0]).ok_or(WifiError::InvalidReply)?;
        let low = hex(pair[1]).ok_or(WifiError::InvalidReply)?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|_| WifiError::InvalidReply)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{decode_hex_text, encode_hex};

    #[test]
    fn wifi_text_hex_round_trip() {
        let encoded = encode_hex("mochi Wi-Fi".as_bytes());
        assert_eq!(decode_hex_text(&encoded, 32).as_deref(), Ok("mochi Wi-Fi"));
    }

    #[test]
    fn wifi_text_hex_rejects_invalid_input() {
        assert!(decode_hex_text("0", 32).is_err());
        assert!(decode_hex_text("gg", 32).is_err());
        assert!(decode_hex_text("00", 0).is_err());
    }
}
