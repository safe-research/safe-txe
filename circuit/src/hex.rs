//! Hexadecimal string decoding.

/// Decodes a hexadecimal string into bytes.
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    let hex = s.strip_prefix("0x").ok_or(Error)?;
    let (bytes, rest) = hex.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(Error);
    }
    bytes
        .iter()
        .map(|&[hi, lo]| Ok((nibble(hi)? << 4) | nibble(lo)?))
        .collect()
}

fn nibble(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => Err(Error),
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Error;
