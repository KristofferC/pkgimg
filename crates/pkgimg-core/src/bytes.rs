//! Little-endian cursor over a byte slice.

use anyhow::{Context, Result, bail};

pub struct Cursor<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8], pos: usize) -> Self {
        Cursor { buf, pos }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let Some(end) = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()) else {
            bail!("unexpected end of data at offset {} (need {n} bytes)", self.pos);
        };
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// NUL-terminated string.
    pub fn cstr(&mut self) -> Result<String> {
        let rest = &self.buf[self.pos.min(self.buf.len())..];
        let Some(n) = rest.iter().position(|&b| b == 0) else {
            bail!("unterminated string at offset {}", self.pos);
        };
        let s = String::from_utf8_lossy(&rest[..n]).into_owned();
        self.pos += n + 1;
        Ok(s)
    }

    /// Length-prefixed (i32) string.
    pub fn lstr(&mut self, n: usize) -> Result<String> {
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    pub fn align(&mut self, a: usize) {
        self.pos = self.pos.div_ceil(a) * a;
    }
}

#[inline]
pub fn rd_u64(buf: &[u8], off: usize) -> u64 {
    buf.get(off..).and_then(|b| b.get(..8)).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()))
}
#[inline]
pub fn rd_u32(buf: &[u8], off: usize) -> u32 {
    buf.get(off..).and_then(|b| b.get(..4)).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
}
#[inline]
pub fn rd_u16(buf: &[u8], off: usize) -> u16 {
    buf.get(off..).and_then(|b| b.get(..2)).map_or(0, |b| u16::from_le_bytes(b.try_into().unwrap()))
}

/// Decode a 0-terminated list of LEB128-style deltas (`jl_write_offsetlist`). Lists are not
/// necessarily sorted: a backwards step is written as a wrapped (10-byte) delta, and the
/// loader adds deltas with wrapping arithmetic, as done here.
pub fn read_offsetlist(buf: &[u8], pos: &mut usize) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    let mut last: u64 = 0;
    loop {
        let mut d: u64 = 0;
        let mut shift = 0;
        loop {
            let Some(&c) = buf.get(*pos) else { bail!("truncated offset list") };
            *pos += 1;
            if shift >= 64 || (shift == 63 && c & 0x7f > 1) {
                bail!("corrupt offset list");
            }
            d |= ((c & 0x7f) as u64) << shift;
            shift += 7;
            if c & 0x80 == 0 {
                break;
            }
        }
        if d == 0 {
            return Ok(out);
        }
        last = last.wrapping_add(d);
        out.push(u32::try_from(last).context("corrupt offset list")?);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_reads_handle_invalid_offsets() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(rd_u64(&bytes, 0), 0x0807060504030201);
        assert_eq!(rd_u32(&bytes, 4), 0x08070605);
        assert_eq!(rd_u16(&bytes, 6), 0x0807);
        for offset in [8, usize::MAX - 1, usize::MAX] {
            assert_eq!(rd_u64(&bytes, offset), 0);
            assert_eq!(rd_u32(&bytes, offset), 0);
            assert_eq!(rd_u16(&bytes, offset), 0);
        }
        assert_eq!(rd_u64(&bytes, 1), 0);
    }

    #[test]
    fn offset_lists_preserve_backwards_steps() {
        // 16, then -8 encoded as a wrapped u64, then the terminator.
        let bytes = [16, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0];
        assert_eq!(read_offsetlist(&bytes, &mut 0).unwrap(), vec![16, 8]);
    }

    #[test]
    fn offset_lists_reject_overflow_and_truncation() {
        // The tenth byte used to discard overflowing bits and decode as zero.
        let mut bytes = vec![0x80; 9];
        bytes.push(2);
        assert!(read_offsetlist(&bytes, &mut 0).is_err());
        assert!(read_offsetlist(&[0x80], &mut 0).is_err());
        assert!(read_offsetlist(&[1], &mut 0).is_err());
    }
}
