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

    /// Decodes a struct from an RLP-encoded list.
    pub fn decode_struct<T, F>(&mut self, mut f: F) -> Result<T, Error>
    where
        T: 'a,
        F: FnMut(&mut Decoder<'a>) -> Result<T, Error> + 'a,
    {
        let mut list = self.list()?;
        self.done()?;
        let result = f(&mut list)?;
        list.done()?;
        Ok(result)
    }

    /// Decodes a list item.
    pub fn list(&mut self) -> Result<Self, Error> {
        match self.next()? {
            Some(Item::List(list)) => Ok(list),
            _ => Err(Error),
        }
    }

    /// Decodes a vector.
    pub fn vec<T, F>(&mut self, mut f: F) -> Result<Vec<T>, Error>
    where
        T: 'a,
        F: FnMut(&mut Decoder<'a>) -> Result<T, Error> + 'a,
    {
        let mut list = self.list()?;
        let count = {
            let mut list = Decoder(list.0);
            let mut count = 0;
            while list.next()?.is_some() {
                count += 1;
            }
            count
        };
        let mut result = Vec::with_capacity(count);
        let mut cursor = list.0;
        while list.next()?.is_some() {
            let size = cursor.len().wrapping_sub(list.0.len());
            let (item, rest) = unsafe { cursor.split_at_unchecked(size) };
            let item = f(&mut Decoder(item))?;
            cursor = rest;
            result.push(item);
        }
        Ok(result)
    }

    /// Decodes a bytes item.
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        match self.next()? {
            Some(Item::Bytes(data)) => Ok(data),
            _ => Err(Error),
        }
    }

    /// Decodes a bytes array item.
    pub fn bytes_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.bytes()?.try_into().map_err(|_| Error)
    }

    /// Decodes an address item
    pub fn address(&mut self) -> Result<[u8; 20], Error> {
        self.bytes_array()
    }

    /// Decodes an uint item
    pub fn uint(&mut self) -> Result<[u8; 32], Error> {
        let mut uint = [0; 32];
        let bytes = self.bytes()?;
        let offset = 32_usize.checked_sub(bytes.len() as _).ok_or(Error)?;
        unsafe {
            bytes
                .as_ptr()
                .copy_to_nonoverlapping(uint.as_mut_ptr().add(offset), bytes.len())
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
            let (data, rest) = prefixed_len(tag, 0xc0, self.0)?;
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
                            .copy_to_nonoverlapping(be.as_mut_ptr().add(offset), llen)
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
