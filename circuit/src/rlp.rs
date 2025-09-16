//! Poor-man's RLP decoder.

/// An RLP decoder.
pub struct Decoder<'a>(&'a [u8]);

/// An RLP item.
pub enum Item<'a> {
    /// A byte string.
    Bytes(&'a [u8]),
    /// A list of RLP items.
    List(Decoder<'a>),
}

impl<'a> Decoder<'a> {
    /// Create a new RLP decoder.
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
    }

    /// Decodes a list item.
    pub fn list(&mut self) -> Result<Self, Error> {
        match self.next()? {
            Some(Item::List(list)) => Ok(list),
            _ => Err(Error),
        }
    }

    /// Decodes a bytes item.
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        match self.next()? {
            Some(Item::Bytes(data)) => Ok(data),
            _ => Err(Error),
        }
    }

    /// Decodes an address item
    pub fn address(&mut self) -> Result<[u8; 20], Error> {
        self.bytes()?.try_into().map_err(|_| Error)
    }

    /// Decodes an uint item
    pub fn uint(&mut self) -> Result<[u8; 32], Error> {
        let mut uint = [0; 32];
        let bytes = self.bytes()?;
        let offset = 32_usize.checked_sub(bytes.len() as _).ok_or(Error)?;
        unsafe {
            bytes
                .as_ptr()
                .copy_to(uint.get_unchecked_mut(offset..).as_mut_ptr(), bytes.len())
        };
        Ok(uint)
    }

    /// Decodes an boolean item
    pub fn bool(&mut self) -> Result<bool, Error> {
        match self.bytes()? {
            [] => Ok(false),
            [1] => Ok(true),
            _ => Err(Error),
        }
    }

    /// Ensures a decoder is empty.
    pub fn done(&self) -> Result<(), Error> {
        self.0.is_empty().then_some(()).ok_or(Error)
    }

    /// Decode the next RLP item.
    pub fn next(&mut self) -> Result<Option<Item<'a>>, Error> {
        let Some(&tag) = self.0.first() else {
            return Ok(None);
        };
        let (item, rest) = if tag <= 0x7f {
            let (data, rest) = unsafe { self.0.split_at_unchecked(1) };
            (Item::Bytes(data), rest)
        } else if tag <= 0xbf {
            let (data, rest) = prefixed_len(tag, 0x80, self.0)?;
            (Item::Bytes(data), rest)
        } else {
            let (data, rest) = prefixed_len(tag, 0x80, self.0)?;
            (Item::List(Decoder(data)), rest)
        };
        self.0 = rest;
        Ok(Some(item))
    }
}

fn prefixed_len(tag: u8, offset: u8, data: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    Some(())
        .and_then(|()| {
            let long = offset + 55;
            if tag <= long {
                let len = (tag - offset) as usize;
                data.get(1..)?.split_at_checked(len)
            } else {
                let llen = (tag - long) as usize;
                if llen > 4 {
                    // Too long!
                    return None;
                }
                let lend = llen.wrapping_add(1);
                let lbytes = data.get(1..lend)?;
                let len = {
                    let mut be = [0; 4];
                    let offset = 4_usize.wrapping_sub(llen as _);
                    unsafe {
                        lbytes
                            .as_ptr()
                            .copy_to(be.get_unchecked_mut(offset..).as_mut_ptr(), llen)
                    };
                    u32::from_be_bytes(be)
                };
                data.get(lend..)?.split_at_checked(len as _)
            }
        })
        .ok_or(Error)
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Error;
