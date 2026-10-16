//! Local termios edits; no service state or caller-memory references escape.
use super::*;

pub(super) fn speed(termios: *const NewlibTermios, input: bool) -> Result<u32, c_int> {
    let value = terminal_memory::read_attributes(termios)?;
    Ok(if input {
        value.c_ispeed
    } else {
        value.c_ospeed
    })
}

fn valid_speed(speed: u32) -> bool {
    matches!(
        speed,
        0 | 50
            | 75
            | 110
            | 134
            | 150
            | 200
            | 300
            | 600
            | 1_200
            | 1_800
            | 2_400
            | 4_800
            | 9_600
            | 19_200
            | 38_400
            | 57_600
            | 115_200
    )
}

pub(super) fn set_speed(
    termios: *mut NewlibTermios,
    speed: u32,
    input: bool,
    output: bool,
) -> Result<c_int, c_int> {
    if termios.is_null() {
        return Err(EFAULT);
    }
    if !valid_speed(speed) {
        return Err(EINVAL);
    }
    let mut value = terminal_memory::read_attributes(termios)?;
    if input {
        value.c_ispeed = speed;
    }
    if output {
        value.c_ospeed = speed;
    }
    terminal_memory::write_attributes(termios, value)?;
    Ok(0)
}

pub(super) fn make_raw(termios: *mut NewlibTermios) -> Result<(), c_int> {
    let mut value = terminal_memory::read_attributes(termios)?;
    value.c_iflag &= !(posix_protocol::TERMINAL_IFLAG_IGNBRK
        | posix_protocol::TERMINAL_IFLAG_BRKINT
        | posix_protocol::TERMINAL_IFLAG_PARMRK
        | posix_protocol::TERMINAL_IFLAG_ISTRIP
        | posix_protocol::TERMINAL_IFLAG_INLCR
        | posix_protocol::TERMINAL_IFLAG_IGNCR
        | posix_protocol::TERMINAL_IFLAG_ICRNL
        | posix_protocol::TERMINAL_IFLAG_IXON);
    value.c_oflag &= !posix_protocol::TERMINAL_OFLAG_OPOST;
    value.c_lflag &= !(posix_protocol::TERMINAL_LFLAG_ECHO
        | posix_protocol::TERMINAL_LFLAG_ECHONL
        | posix_protocol::TERMINAL_LFLAG_ICANON
        | posix_protocol::TERMINAL_LFLAG_ISIG
        | posix_protocol::TERMINAL_LFLAG_IEXTEN);
    value.c_cflag &= !((3 << 4) | (1 << 8));
    value.c_cflag |= posix_protocol::TERMINAL_CFLAG_CS8;
    value.c_cc[posix_protocol::TERMINAL_CC_VMIN] = 1;
    value.c_cc[posix_protocol::TERMINAL_CC_VTIME] = 0;
    terminal_memory::write_attributes(termios, value)
}
