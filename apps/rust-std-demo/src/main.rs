use std::fs;
use std::io::{self, Write};

fn main() -> io::Result<()> {
    println!("hello from Rust std");
    fs::write("/rust.txt", b"mochiOS")?;
    io::stdout().write_all(b"done\n")?;
    Ok(())
}
