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
    buf.get(off..off + 8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()))
}
#[inline]
pub fn rd_u32(buf: &[u8], off: usize) -> u32 {
    buf.get(off..off + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
}
#[inline]
pub fn rd_u16(buf: &[u8], off: usize) -> u16 {
    buf.get(off..off + 2).map_or(0, |b| u16::from_le_bytes(b.try_into().unwrap()))
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
            if shift >= 64 {
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
