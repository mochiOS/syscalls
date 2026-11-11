//! Shared manifest.toml schema. Parsing declarations establishes no identity,
//! publisher trust, install provenance or authority to grant capabilities.
#![no_std]
extern crate alloc;

mod parser;
pub mod resources;
pub use resources::{ResourceDependency, ResourceExport, ResourceFile};
mod types;
mod validation;
pub use types::*;

pub const MAX_MANIFEST_LEN: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge,
    Syntax,
    Schema,
}

/// Parse the same bounded TOML grammar and typed declarations in tools and
/// services. Duplicate keys, malformed escapes and type mismatches fail closed.
pub fn parse_manifest_checked(text: &str) -> Result<PackageManifest, ParseError> {
    if text.len() > MAX_MANIFEST_LEN {
        return Err(ParseError::TooLarge);
    }
    let table = text
        .parse::<toml::Table>()
        .map_err(|_| ParseError::Syntax)?;
    let (manifest, entry, requires) = parser::manifest(&table).ok_or(ParseError::Schema)?;
    validation::validate(manifest, entry, requires).ok_or(ParseError::Schema)
}

pub fn parse_manifest(text: &str) -> Option<PackageManifest> {
    parse_manifest_checked(text).ok()
}
