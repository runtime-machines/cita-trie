use std::borrow::Borrow;
use std::ops::Deref;

#[derive(Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct NibbleSlice([u8]);

impl NibbleSlice {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn at(&self, i: usize) -> usize {
        self.0[i] as usize
    }

    pub fn common_prefix(&self, other_partial: &Self) -> usize {
        self.0
            .iter()
            .zip(other_partial.0.iter())
            .take_while(|it| it.0 == it.1)
            .count()
    }

    /// Takes a slice from `index` to the end.
    ///
    /// `Panics` if `index` > slice length
    pub fn offset(&self, index: usize) -> &Self {
        self.slice(index, self.len())
    }

    pub fn _as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn slice(&self, start: usize, end: usize) -> &Self {
        let data = &self.0[start..end];
        // safety: NibbleSlice is `repr(transparent)` over `[u8]`, so transmutes between the two are okay.
        unsafe {
            let slice = data;
            std::mem::transmute::<&[u8], &Self>(slice)
        }
    }
}

impl ToOwned for NibbleSlice {
    type Owned = NibbleVec;

    fn to_owned(&self) -> Self::Owned {
        NibbleVec {
            hex_data: self.0.to_vec(),
        }
    }
}

impl Borrow<NibbleSlice> for NibbleVec {
    fn borrow(&self) -> &NibbleSlice {
        // safety: NibbleSlice is `repr(transparent)` over `[u8]`, so transmutes between the two are okay.
        unsafe {
            let slice = self.hex_data.as_slice();
            std::mem::transmute::<&[u8], &NibbleSlice>(slice)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NibbleVec {
    hex_data: Vec<u8>,
}

impl NibbleVec {
    pub fn from_hex(hex: Vec<u8>) -> Self {
        NibbleVec { hex_data: hex }
    }

    pub fn from_raw(raw: Vec<u8>, is_leaf: bool) -> Self {
        let mut hex_data = Vec::with_capacity(raw.len() * 2 + is_leaf as usize);
        for item in raw.into_iter() {
            hex_data.push(item / 16);
            hex_data.push(item % 16);
        }
        if is_leaf {
            hex_data.push(16);
        }
        NibbleVec { hex_data }
    }

    pub fn from_compact(compact: Vec<u8>) -> Self {
        let flag = compact[0];

        let is_odd = (flag >> 4) & 1 == 1;
        let is_leaf = (flag >> 4) & 0b10 == 0b10;
        assert_eq!(flag & 0b1100_0000, 0, "reserved flag bits used");

        let mut hex =
            Vec::with_capacity((compact.len() - 1) * 2 + is_leaf as usize + is_odd as usize);

        if is_odd {
            hex.push(flag % 16);
        }

        for item in &compact[1..] {
            hex.push(item / 16);
            hex.push(item % 16);
        }
        if is_leaf {
            hex.push(16);
        }

        NibbleVec { hex_data: hex }
    }

    pub fn is_leaf(&self) -> bool {
        *self.hex_data.last().unwrap() == 16
    }

    pub fn encode_compact(&self) -> Vec<u8> {
        let is_leaf = self.is_leaf();
        let mut hex = if is_leaf {
            &self.hex_data[0..self.hex_data.len() - 1]
        } else {
            &self.hex_data[0..]
        };
        // node type    path length    |    prefix    hexchar
        // --------------------------------------------------
        // extension    even           |    0000      0x0
        // extension    odd            |    0001      0x1
        // leaf         even           |    0010      0x2
        // leaf         odd            |    0011      0x3
        let v = if hex.len() % 2 == 1 {
            let v = 0x10 + hex[0];
            hex = &hex[1..];
            v
        } else {
            0x00
        };

        let mut compact = Vec::with_capacity(hex.len() / 2 + 1);

        compact.push(v + if is_leaf { 0x20 } else { 0x00 });
        for hex in hex.chunks_exact(2) {
            compact.push((hex[0] * 16) + (hex[1]));
        }

        compact
    }

    pub fn encode_raw(&self) -> (Vec<u8>, bool) {
        let is_leaf = self.is_leaf();
        let mut raw = Vec::with_capacity(self.hex_data.len() / 2);
        // if `is_leaf` then we don't care about the last nibble anyway.
        for hex in self.hex_data.chunks_exact(2) {
            raw.push((hex[0] * 16) + (hex[1]));
        }

        (raw, is_leaf)
    }

    pub fn _get_data(&self) -> &[u8] {
        &self.hex_data
    }

    pub fn join(&self, b: &NibbleVec) -> NibbleVec {
        let mut hex_data = Vec::with_capacity(self.hex_data.len() + b.hex_data.len());
        hex_data.extend_from_slice(&self.hex_data);
        hex_data.extend_from_slice(&b.hex_data);
        NibbleVec::from_hex(hex_data)
    }

    pub fn extend_from_slice(&mut self, b: &NibbleSlice) {
        self.hex_data.extend_from_slice(&b.0);
    }

    pub fn truncate(&mut self, len: usize) {
        self.hex_data.truncate(len)
    }

    pub fn pop(&mut self) -> Option<u8> {
        self.hex_data.pop()
    }

    pub fn push(&mut self, e: u8) {
        self.hex_data.push(e)
    }
}

impl Deref for NibbleVec {
    type Target = NibbleSlice;

    fn deref(&self) -> &Self::Target {
        self.borrow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nibble() {
        let n = NibbleVec::from_raw(b"key1".to_vec(), true);
        let compact = n.encode_compact();
        let n2 = NibbleVec::from_compact(compact);
        let (raw, is_leaf) = n2.encode_raw();
        assert!(is_leaf);
        assert_eq!(raw, b"key1");
    }
}
