//! Process-local view spelling only; ownership and authority stay in libc state.
pub const PREFIX: &[u8] = b"/.__mochi_resources/";
pub const ROOT_LEN: usize = PREFIX.len() + 16;
pub fn parse(path: &[u8]) -> Result<Option<(u64, usize)>, i32> {
    if !path.starts_with(PREFIX) {
        return Ok(None);
    }
    if path.len() < ROOT_LEN || path.get(ROOT_LEN).is_some_and(|c| *c != b'/') {
        return Err(2);
    }
    let mut token = 0u64;
    for &b in &path[PREFIX.len()..ROOT_LEN] {
        let n = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => return Err(2),
        };
        token = (token << 4) | u64::from(n);
    }
    if token == 0 {
        return Err(2);
    }
    Ok(Some((
        token,
        if path.len() == ROOT_LEN {
            ROOT_LEN
        } else {
            ROOT_LEN + 1
        },
    )))
}
pub fn spell(token: u64, output: &mut [u8]) -> Result<usize, i32> {
    if token == 0 {
        return Err(2);
    }
    if output.len() < ROOT_LEN {
        return Err(36);
    }
    output[..PREFIX.len()].copy_from_slice(PREFIX);
    let digits = b"0123456789abcdef";
    for i in 0..16 {
        output[PREFIX.len() + i] = digits[((token >> ((15 - i) * 4)) & 15) as usize];
    }
    Ok(ROOT_LEN)
}
pub fn canonical(path: &[u8], output: &mut [u8]) -> Result<usize, i32> {
    let Some((_, skip)) = parse(path)? else {
        return Err(2);
    };
    if output.len() < ROOT_LEN {
        return Err(36);
    }
    output[..ROOT_LEN].copy_from_slice(&path[..ROOT_LEN]);
    let mut used = ROOT_LEN;
    for part in path[skip..].split(|b| *b == b'/') {
        match part {
            b"" | b"." => (),
            b".." => {
                if used == ROOT_LEN {
                    return Err(13);
                }
                used = output[..used]
                    .iter()
                    .rposition(|b| *b == b'/')
                    .filter(|n| *n >= ROOT_LEN)
                    .ok_or(13)?;
            }
            _ => {
                let end = used
                    .checked_add(part.len() + 1)
                    .filter(|n| *n <= output.len())
                    .ok_or(36)?;
                output[used] = b'/';
                output[used + 1..end].copy_from_slice(part);
                used = end;
            }
        }
    }
    Ok(used)
}
