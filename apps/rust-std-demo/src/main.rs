use std::io::{self, Write};

fn main() -> io::Result<()> {
    println!("hello from Rust std");
    io::stdout().write_all(b"done\n")?;
    Ok(())
}
