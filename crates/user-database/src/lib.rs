#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

pub const DATABASE_PATH: &str = "/system/users/users.db";
pub const DATABASE_VERSION: u16 = 1;
pub const FIRST_REGULAR_UID: u32 = 1000;

const HEADER: &str = "MUSRDB\t1";
const LOCKED_FLAG: u32 = 1;
const KNOWN_FLAGS: u32 = LOCKED_FLAG;
const MAX_DATABASE_BYTES: usize = 1024 * 1024;
const MAX_USERS: usize = 4096;
const MAX_NAME_BYTES: usize = 32;
const MAX_DISPLAY_NAME_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 512;
const MAX_PASSWORD_HASH_BYTES: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub display_name: String,
    pub home: String,
    pub shell: String,
    pub password_hash: String,
    pub locked: bool,
}

impl UserRecord {
    pub fn regular(name: &str, uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            name: name.to_string(),
            display_name: name.to_string(),
            home: alloc::format!("/home/{name}"),
            shell: "/bin/msh".to_string(),
            password_hash: "!".to_string(),
            locked: true,
        }
    }

    pub fn validate(&self) -> Result<(), DatabaseError> {
        validate_name(&self.name)?;
        validate_text(&self.display_name, MAX_DISPLAY_NAME_BYTES, "display name")?;
        validate_absolute_path(&self.home, "home")?;
        validate_absolute_path(&self.shell, "shell")?;
        validate_text(
            &self.password_hash,
            MAX_PASSWORD_HASH_BYTES,
            "password hash",
        )?;
        if self.uid == 0 && self.name != "root" {
            return Err(DatabaseError::InvalidRoot);
        }
        if self.name == "root" && (self.uid != 0 || self.gid != 0) {
            return Err(DatabaseError::InvalidRoot);
        }
        Ok(())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, DatabaseError> {
        let line = core::str::from_utf8(bytes).map_err(|_| DatabaseError::InvalidUtf8)?;
        if line.is_empty() || line.contains('\n') || line.contains('\r') {
            return Err(DatabaseError::InvalidRecord);
        }
        parse_record(line)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DatabaseError> {
        self.validate()?;
        let mut output = String::new();
        encode_record(self, &mut output);
        Ok(output.into_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserDatabase {
    users: Vec<UserRecord>,
}

impl Default for UserDatabase {
    fn default() -> Self {
        Self::with_root()
    }
}

impl UserDatabase {
    pub fn with_root() -> Self {
        Self {
            users: alloc::vec![UserRecord {
                uid: 0,
                gid: 0,
                name: "root".to_string(),
                display_name: "System Administrator".to_string(),
                home: "/home/root".to_string(),
                shell: "/bin/msh".to_string(),
                password_hash: "!".to_string(),
                locked: true,
            }],
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, DatabaseError> {
        if bytes.len() > MAX_DATABASE_BYTES {
            return Err(DatabaseError::DatabaseTooLarge);
        }
        let text = core::str::from_utf8(bytes).map_err(|_| DatabaseError::InvalidUtf8)?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(DatabaseError::InvalidHeader);
        }

        let mut users = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if users.len() >= MAX_USERS {
                return Err(DatabaseError::TooManyUsers);
            }
            users.push(parse_record(line)?);
        }
        let database = Self { users };
        database.validate()?;
        Ok(database)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DatabaseError> {
        self.validate()?;
        let mut output = String::from(HEADER);
        output.push('\n');
        for user in &self.users {
            encode_record(user, &mut output);
            output.push('\n');
        }
        if output.len() > MAX_DATABASE_BYTES {
            return Err(DatabaseError::DatabaseTooLarge);
        }
        Ok(output.into_bytes())
    }

    pub fn users(&self) -> &[UserRecord] {
        &self.users
    }

    pub fn find_name(&self, name: &str) -> Option<&UserRecord> {
        self.users.iter().find(|user| user.name == name)
    }

    pub fn find_name_mut(&mut self, name: &str) -> Option<&mut UserRecord> {
        self.users.iter_mut().find(|user| user.name == name)
    }

    pub fn find_uid(&self, uid: u32) -> Option<&UserRecord> {
        self.users.iter().find(|user| user.uid == uid)
    }

    pub fn next_regular_uid(&self) -> Result<u32, DatabaseError> {
        let mut candidate = FIRST_REGULAR_UID;
        loop {
            if self.find_uid(candidate).is_none() {
                return Ok(candidate);
            }
            candidate = candidate
                .checked_add(1)
                .ok_or(DatabaseError::UidExhausted)?;
        }
    }

    pub fn add(&mut self, user: UserRecord) -> Result<(), DatabaseError> {
        user.validate()?;
        if self.users.len() >= MAX_USERS {
            return Err(DatabaseError::TooManyUsers);
        }
        if self.find_name(&user.name).is_some() {
            return Err(DatabaseError::DuplicateName);
        }
        if self.find_uid(user.uid).is_some() {
            return Err(DatabaseError::DuplicateUid);
        }
        self.users.push(user);
        self.users.sort_by_key(|record| record.uid);
        self.validate()
    }

    pub fn remove(&mut self, name: &str) -> Result<UserRecord, DatabaseError> {
        if name == "root" {
            return Err(DatabaseError::RootRemoval);
        }
        let index = self
            .users
            .iter()
            .position(|user| user.name == name)
            .ok_or(DatabaseError::UserNotFound)?;
        Ok(self.users.remove(index))
    }

    pub fn validate(&self) -> Result<(), DatabaseError> {
        if self.users.len() > MAX_USERS {
            return Err(DatabaseError::TooManyUsers);
        }
        let mut root_count = 0usize;
        for (index, user) in self.users.iter().enumerate() {
            user.validate()?;
            if user.name == "root" {
                root_count += 1;
            }
            for previous in &self.users[..index] {
                if previous.name == user.name {
                    return Err(DatabaseError::DuplicateName);
                }
                if previous.uid == user.uid {
                    return Err(DatabaseError::DuplicateUid);
                }
            }
        }
        if root_count != 1 {
            return Err(DatabaseError::InvalidRoot);
        }
        Ok(())
    }
}

fn encode_record(user: &UserRecord, output: &mut String) {
    let flags = if user.locked { LOCKED_FLAG } else { 0 };
    output.push_str(&user.uid.to_string());
    output.push('\t');
    output.push_str(&user.gid.to_string());
    output.push('\t');
    output.push_str(&flags.to_string());
    for value in [
        &user.name,
        &user.display_name,
        &user.home,
        &user.shell,
        &user.password_hash,
    ] {
        output.push('\t');
        encode_hex(value.as_bytes(), output);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseError {
    DatabaseTooLarge,
    InvalidUtf8,
    InvalidHeader,
    InvalidRecord,
    InvalidNumber,
    InvalidHex,
    InvalidName,
    InvalidText,
    InvalidPath,
    InvalidFlags,
    InvalidRoot,
    DuplicateName,
    DuplicateUid,
    TooManyUsers,
    UidExhausted,
    UserNotFound,
    RootRemoval,
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DatabaseTooLarge => "user database is too large",
            Self::InvalidUtf8 => "user database is not UTF-8",
            Self::InvalidHeader => "user database header is invalid",
            Self::InvalidRecord => "user database record is invalid",
            Self::InvalidNumber => "user database number is invalid",
            Self::InvalidHex => "user database string encoding is invalid",
            Self::InvalidName => "user name is invalid",
            Self::InvalidText => "user record text is invalid",
            Self::InvalidPath => "user record path is invalid",
            Self::InvalidFlags => "user record flags are invalid",
            Self::InvalidRoot => "root user record is invalid",
            Self::DuplicateName => "user name already exists",
            Self::DuplicateUid => "user ID already exists",
            Self::TooManyUsers => "user database contains too many users",
            Self::UidExhausted => "no user ID is available",
            Self::UserNotFound => "user was not found",
            Self::RootRemoval => "root user cannot be removed",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DatabaseError {}

fn parse_record(line: &str) -> Result<UserRecord, DatabaseError> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() != 8 {
        return Err(DatabaseError::InvalidRecord);
    }
    let uid = fields[0]
        .parse::<u32>()
        .map_err(|_| DatabaseError::InvalidNumber)?;
    let gid = fields[1]
        .parse::<u32>()
        .map_err(|_| DatabaseError::InvalidNumber)?;
    let flags = fields[2]
        .parse::<u32>()
        .map_err(|_| DatabaseError::InvalidNumber)?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(DatabaseError::InvalidFlags);
    }
    let user = UserRecord {
        uid,
        gid,
        name: decode_hex_string(fields[3])?,
        display_name: decode_hex_string(fields[4])?,
        home: decode_hex_string(fields[5])?,
        shell: decode_hex_string(fields[6])?,
        password_hash: decode_hex_string(fields[7])?,
        locked: flags & LOCKED_FLAG != 0,
    };
    user.validate()?;
    Ok(user)
}

fn validate_name(name: &str) -> Result<(), DatabaseError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_BYTES {
        return Err(DatabaseError::InvalidName);
    }
    if !matches!(bytes[0], b'a'..=b'z' | b'_') {
        return Err(DatabaseError::InvalidName);
    }
    if !bytes
        .iter()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
    {
        return Err(DatabaseError::InvalidName);
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize, _field: &str) -> Result<(), DatabaseError> {
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(DatabaseError::InvalidText);
    }
    Ok(())
}

fn validate_absolute_path(value: &str, _field: &str) -> Result<(), DatabaseError> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES || !value.starts_with('/') {
        return Err(DatabaseError::InvalidPath);
    }
    if value
        .split('/')
        .any(|component| component == "." || component == "..")
        || value.chars().any(char::is_control)
    {
        return Err(DatabaseError::InvalidPath);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8], output: &mut String) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
}

fn decode_hex_string(value: &str) -> Result<String, DatabaseError> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(DatabaseError::InvalidHex);
    }
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = decode_nibble(pair[0]).ok_or(DatabaseError::InvalidHex)?;
        let low = decode_nibble(pair[1]).ok_or(DatabaseError::InvalidHex)?;
        decoded.push((high << 4) | low);
    }
    String::from_utf8(decoded).map_err(|_| DatabaseError::InvalidUtf8)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_database_round_trips() {
        let database = UserDatabase::with_root();
        let encoded = database.encode().unwrap();
        assert_eq!(UserDatabase::parse(&encoded).unwrap(), database);
    }

    #[test]
    fn regular_user_round_trips_unicode_display_name() {
        let mut database = UserDatabase::with_root();
        let mut user = UserRecord::regular("alice", 1000, 1000);
        user.display_name = "Alice Example".to_string();
        database.add(user).unwrap();
        let decoded = UserDatabase::parse(&database.encode().unwrap()).unwrap();
        assert_eq!(decoded.find_name("alice").unwrap().uid, 1000);
    }

    #[test]
    fn individual_record_round_trips() {
        let mut user = UserRecord::regular("alice", 1000, 1000);
        user.display_name = "Alice Example".to_string();
        assert_eq!(UserRecord::parse(&user.encode().unwrap()).unwrap(), user);
    }

    #[test]
    fn duplicate_name_and_uid_are_rejected() {
        let mut database = UserDatabase::with_root();
        database
            .add(UserRecord::regular("alice", 1000, 1000))
            .unwrap();
        assert_eq!(
            database.add(UserRecord::regular("alice", 1001, 1001)),
            Err(DatabaseError::DuplicateName)
        );
        assert_eq!(
            database.add(UserRecord::regular("bob", 1000, 1000)),
            Err(DatabaseError::DuplicateUid)
        );
    }

    #[test]
    fn invalid_names_and_paths_are_rejected() {
        let mut user = UserRecord::regular("Alice", 1000, 1000);
        assert_eq!(user.validate(), Err(DatabaseError::InvalidName));
        user.name = "alice".to_string();
        user.home = "/home/../root".to_string();
        assert_eq!(user.validate(), Err(DatabaseError::InvalidPath));
    }

    #[test]
    fn root_cannot_be_removed() {
        assert_eq!(
            UserDatabase::with_root().remove("root"),
            Err(DatabaseError::RootRemoval)
        );
    }

    #[test]
    fn next_uid_fills_first_available_slot() {
        let mut database = UserDatabase::with_root();
        database
            .add(UserRecord::regular("alice", 1001, 1001))
            .unwrap();
        assert_eq!(database.next_regular_uid(), Ok(1000));
    }

    #[test]
    fn unknown_flags_and_missing_root_are_rejected() {
        let invalid_flags =
            b"MUSRDB\t1\n0\t0\t2\t726f6f74\t726f6f74\t2f686f6d652f726f6f74\t2f62696e2f6d7368\t21\n";
        assert_eq!(
            UserDatabase::parse(invalid_flags),
            Err(DatabaseError::InvalidFlags)
        );
        assert_eq!(
            UserDatabase::parse(b"MUSRDB\t1\n"),
            Err(DatabaseError::InvalidRoot)
        );
    }
}
