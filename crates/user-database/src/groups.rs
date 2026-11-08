//! Persistent group metadata. Membership never grants kernel authority.
//! user.service evaluates its administrator role in userspace.
use super::{DatabaseError, UserDatabase, validate_name};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

pub const DATABASE_PATH: &str = "/var/lib/accounts/groups.db";
pub const MAX_MEMBERS: usize = 64;
pub const ADMINISTRATOR_GROUP: &str = "admin";
const MAX_BYTES: usize = 1024 * 1024;
const MAX_GROUPS: usize = 4096;
const HEADER: &str = "MGRPDB\t1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub gid: u32,
    pub name: String,
    /// Explicit additional members; a user's primary GID is held in users.db.
    pub members: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    TooLarge,
    Duplicate,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid group database: {self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Group {
    fn validate(&self) -> Result<(), Error> {
        validate_name(&self.name).map_err(|_: DatabaseError| Error::Invalid)?;
        if self.members.len() > MAX_MEMBERS {
            return Err(Error::TooLarge);
        }
        for (index, member) in self.members.iter().enumerate() {
            validate_name(member).map_err(|_| Error::Invalid)?;
            if self.members[..index].contains(member) {
                return Err(Error::Duplicate);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupDatabase {
    groups: Vec<Group>,
}
impl GroupDatabase {
    /// First-time provisioning only. Persist the result before publishing it.
    /// Existing named/shared groups are subsequently read from groups.db.
    pub fn provision(users: &UserDatabase) -> Result<Self, Error> {
        let mut database = Self { groups: Vec::new() };
        for user in users.users().iter().filter(|user| user.uid == user.gid) {
            database.ensure_private(user)?;
        }
        Ok(database)
    }
    pub fn find_gid(&self, gid: u32) -> Option<&Group> {
        self.groups.iter().find(|group| group.gid == gid)
    }
    pub fn find_name(&self, name: &str) -> Option<&Group> {
        self.groups.iter().find(|group| group.name == name)
    }
    pub fn groups(&self) -> &[Group] {
        &self.groups
    }
    pub fn is_administrator(&self, user: &super::UserRecord) -> bool {
        user.uid == 0 || self.find_name(ADMINISTRATOR_GROUP)
            .is_some_and(|group| group.members.iter().any(|name| name == &user.name))
    }
    /// One-time migration for installations created before administrator roles.
    /// An existing empty admin group is deliberate and is never repopulated.
    pub fn provision_administrators(&mut self, users: &UserDatabase) -> Result<bool, Error> {
        if self.find_name(ADMINISTRATOR_GROUP).is_some() { return Ok(false); }
        let gid = (80..super::FIRST_REGULAR_UID).find(|gid| self.find_gid(*gid).is_none()).ok_or(Error::TooLarge)?;
        let first = users.users().iter().filter(|user| user.uid >= super::FIRST_REGULAR_UID).min_by_key(|user| user.uid);
        self.add(Group {
            gid, name: ADMINISTRATOR_GROUP.into(),
            members: first.map(|user| alloc::vec![user.name.clone()]).unwrap_or_default(),
        })?;
        Ok(true)
    }
    pub fn add_administrator(&mut self, name: &str) -> Result<(), Error> {
        validate_name(name).map_err(|_| Error::Invalid)?;
        let group = self.groups.iter_mut().find(|group| group.name == ADMINISTRATOR_GROUP).ok_or(Error::Invalid)?;
        if !group.members.iter().any(|member| member == name) {
            if group.members.len() == MAX_MEMBERS { return Err(Error::TooLarge); }
            group.members.push(name.into());
        }
        Ok(())
    }
    /// Revoke memberships before removing an account so name reuse cannot
    /// inherit a previous account's administrator role.
    pub fn remove_member(&mut self, name: &str) -> bool {
        let mut changed = false;
        for group in &mut self.groups {
            let old = group.members.len();
            group.members.retain(|member| member != name);
            changed |= old != group.members.len();
        }
        changed
    }
    pub fn prune_members(&mut self, users: &UserDatabase) -> bool {
        let mut changed = false;
        for group in &mut self.groups {
            let old = group.members.len();
            group.members.retain(|name| users.find_name(name).is_some());
            changed |= old != group.members.len();
        }
        changed
    }
    pub fn add(&mut self, group: Group) -> Result<(), Error> {
        group.validate()?;
        if self.groups.len() >= MAX_GROUPS {
            return Err(Error::TooLarge);
        }
        if self.find_gid(group.gid).is_some() || self.find_name(&group.name).is_some() {
            return Err(Error::Duplicate);
        }
        self.groups.push(group);
        self.groups.sort_by_key(|group| group.gid);
        Ok(())
    }
    /// Preserve configured shared groups. Allocate a private group only when
    /// the account requests its own UID as GID and neither ID nor name exists.
    pub fn ensure_private(&mut self, user: &super::UserRecord) -> Result<bool, Error> {
        if user.uid != user.gid || self.find_gid(user.gid).is_some() {
            return Ok(false);
        }
        self.add(Group {
            gid: user.gid,
            name: user.name.clone(),
            members: Vec::new(),
        })?;
        Ok(true)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let text = core::str::from_utf8(bytes).map_err(|_| Error::Invalid)?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(Error::Invalid);
        }
        let mut database = Self { groups: Vec::new() };
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split('\t');
            let id = fields.next().ok_or(Error::Invalid)?;
            if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Invalid);
            }
            let gid = id.parse().map_err(|_| Error::Invalid)?;
            let name = fields.next().ok_or(Error::Invalid)?.to_string();
            let members = fields.next().ok_or(Error::Invalid)?;
            if fields.next().is_some() {
                return Err(Error::Invalid);
            }
            let mut names = Vec::new();
            if !members.is_empty() {
                for member in members.split(',') {
                    if names.len() == MAX_MEMBERS {
                        return Err(Error::TooLarge);
                    }
                    validate_name(member).map_err(|_| Error::Invalid)?;
                    names.push(member.to_string());
                }
            }
            let members = names;
            database.add(Group { gid, name, members })?;
        }
        Ok(database)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.groups.len() > MAX_GROUPS {
            return Err(Error::TooLarge);
        }
        let mut output = String::from(HEADER);
        output.push('\n');
        for group in &self.groups {
            group.validate()?;
            use core::fmt::Write;
            write!(&mut output, "{}\t{}\t", group.gid, group.name).map_err(|_| Error::TooLarge)?;
            for (index, member) in group.members.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(member);
            }
            output.push('\n');
            if output.len() > MAX_BYTES {
                return Err(Error::TooLarge);
            }
        }
        Ok(output.into_bytes())
    }
}
