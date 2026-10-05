//! The serialized heap (`jl_save_system_image_to_stream`): sections, relocation lists and roots.

use crate::bytes::{Cursor, rd_u64, read_offsetlist};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

/// Cheaply clonable view into shared bytes (a file mapping or an owned buffer).
#[derive(Clone)]
pub struct Blob {
    inner: Arc<dyn AsRef<[u8]> + Send + Sync>,
    start: usize,
    len: usize,
}

impl Blob {
    pub fn new(inner: Arc<dyn AsRef<[u8]> + Send + Sync>) -> Self {
        let len = (*inner).as_ref().len();
        Blob { inner, start: 0, len }
    }
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self::new(Arc::new(v))
    }
    pub fn slice(&self, start: usize, len: usize) -> Result<Blob> {
        if start.checked_add(len).is_none_or(|e| e > self.len) {
            bail!("slice {start}+{len} out of bounds ({})", self.len);
        }
        Ok(Blob { inner: self.inner.clone(), start: self.start + start, len })
    }
}

impl Deref for Blob {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &(*self.inner).as_ref()[self.start..self.start + self.len]
    }
}

pub const RELOC_TAG_OFFSET: u32 = 61;
pub const DEPS_IDX_OFFSET: u32 = 40;
const RELOC_MASK: u64 = (1 << RELOC_TAG_OFFSET) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RefTag {
    Data,
    ConstData,
    Tag,
    Symbol,
    Function,
    SysimageLinkage,
    ExternalLinkage,
    Invalid,
}

#[inline]
pub fn split_reloc(w: u64) -> (RefTag, u64) {
    let tag = match w >> RELOC_TAG_OFFSET {
        0 => RefTag::Data,
        1 => RefTag::ConstData,
        2 => RefTag::Tag,
        3 => RefTag::Symbol,
        4 => RefTag::Function,
        5 => RefTag::SysimageLinkage,
        6 => RefTag::ExternalLinkage,
        _ => RefTag::Invalid,
    };
    (tag, w & RELOC_MASK)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SectionSizes {
    pub objects: usize,
    pub const_data: usize,
    pub symbols: usize,
    pub relocs: usize,
    pub gvar_record: usize,
    pub fptr_record: usize,
    pub tail: usize,
}

/// Root objects recorded at the end of an incremental image (reloc words).
#[derive(Debug, Clone, Default)]
pub struct Roots {
    pub restored: u64,
    pub init_order: u64,
    pub extext_methods: u64,
    pub new_ext: u64,
    pub method_roots_list: u64,
}

pub struct Heap {
    /// Uncompressed heap bytes, starting at the `.ji` `datastartpos`.
    pub data: Blob,
    pub incremental: bool,
    /// Offset in `data` of the object section base. Positions in relocation lists and
    /// `DataRef`s are relative to this (it is 8 bytes before the first payload byte).
    pub sys_base: usize,
    pub sys_len: usize,
    pub const_base: usize,
    pub const_len: usize,
    pub sizes: SectionSizes,
    pub symbols: Vec<Box<str>>,
    /// Positions of type-tag words, one per object in the object section (sorted).
    pub gctags: Vec<u32>,
    /// Positions of pointer fields (sorted).
    pub relocs: Vec<u32>,
    pub memowner: Vec<u32>,
    pub memref: Vec<u32>,
    pub uniquing_types: Vec<u64>,
    pub uniquing_objs: Vec<u64>,
    pub fixup_types: Vec<u64>,
    pub fixup_objs: Vec<u64>,
    pub gvar_record: Vec<u64>,
    pub fptr_record: Vec<u64>,
    pub roots: Option<Roots>,
    pub link_ids_gvars: Vec<u32>,
    pub link_ids_external_fnvars: Vec<u32>,
    pub external_fns_begin: u32,
    /// `ExternalLinkage` words: position -> depsidx (from the link-id tables).
    pub ext_link: HashMap<u32, u32>,
}

fn read_section(c: &mut Cursor, align: usize) -> Result<(usize, usize)> {
    let len = c.u64()? as usize;
    c.align(align);
    let start = c.pos;
    c.take(len).context("section exceeds heap")?;
    Ok((start, len))
}

fn read_arraylist(c: &mut Cursor) -> Result<Vec<u64>> {
    let n = c.u64()? as usize;
    let b = c.take(n.checked_mul(8).context("bad list length")?)?;
    Ok(b.as_chunks::<8>().0.iter().map(|&x| u64::from_le_bytes(x)).collect())
}

fn read_u32s(c: &mut Cursor) -> Result<Vec<u32>> {
    let n = c.u32()? as usize;
    let b = c.take(n * 4)?;
    Ok(b.as_chunks::<4>().0.iter().map(|&x| u32::from_le_bytes(x)).collect())
}

impl Heap {
    pub fn parse(data: Blob, incremental: bool, cache_align: usize) -> Result<Heap> {
        let buf: &[u8] = &data;
        let mut c = Cursor::new(buf, 0);
        // The object section is written with skip=8: its size word occupies the first 8
        // bytes of the stream, so stream positions are relative to the size word.
        let sys_base = c.pos;
        let (sys_start, sys_payload) = read_section(&mut c, 1)?;
        debug_assert_eq!(sys_start, sys_base + 8);
        let sys_len = sys_payload + 8;
        let (const_base, const_len) = read_section(&mut c, cache_align)?;
        let (sym_start, sym_len) = read_section(&mut c, 8)?;
        let (rel_start, rel_len) = read_section(&mut c, 8)?;
        let (gv_start, gv_len) = read_section(&mut c, 8)?;
        let (fp_start, fp_len) = read_section(&mut c, 8)?;

        let mut symbols = Vec::new();
        let sym = &buf[sym_start..sym_start + sym_len];
        let mut k = 0;
        while k + 4 <= sym.len() {
            let l = u32::from_le_bytes(sym[k..k + 4].try_into().unwrap()) as usize;
            let s = sym.get(k + 4..k + 4 + l).context("truncated symbol table")?;
            symbols.push(String::from_utf8_lossy(s).into());
            k += 4 + l + 1;
        }

        let rel = &buf[rel_start..rel_start + rel_len];
        let mut rp = 0;
        let gctags = read_offsetlist(rel, &mut rp)?;
        let relocs = read_offsetlist(rel, &mut rp)?;
        let memowner = read_offsetlist(rel, &mut rp)?;
        let memref = read_offsetlist(rel, &mut rp)?;
        let mut rc = Cursor::new(rel, rp);
        let (mut uniquing_types, mut uniquing_objs, mut fixup_types) = (vec![], vec![], vec![]);
        if incremental {
            uniquing_types = read_arraylist(&mut rc)?;
            uniquing_objs = read_arraylist(&mut rc)?;
            fixup_types = read_arraylist(&mut rc)?;
        }
        let fixup_objs = read_arraylist(&mut rc)?;

        let words = |s: usize, l: usize| -> Vec<u64> {
            buf[s..s + l].as_chunks::<8>().0.iter().map(|&x| u64::from_le_bytes(x)).collect()
        };
        let gvar_record = words(gv_start, gv_len);
        let fptr_record = words(fp_start, fp_len);

        let mut roots = None;
        let mut link = [vec![], vec![], vec![], vec![]];
        let mut external_fns_begin = 0;
        c.align(8);
        let tail_start = c.pos;
        if incremental {
            let r = Roots {
                restored: c.u64()?,
                init_order: c.u64()?,
                extext_methods: c.u64()?,
                new_ext: c.u64()?,
                method_roots_list: c.u64()?,
            };
            roots = Some(r);
            for l in link.iter_mut() {
                *l = read_u32s(&mut c)?;
            }
            external_fns_begin = c.u32()?;
        }
        let [link_gctags, link_relocs, link_ids_gvars, link_ids_external_fnvars] = link;

        let sys = &buf[sys_base..sys_base + sys_len];
        let mut ext_link = HashMap::new();
        for (list, ids) in [(&gctags, &link_gctags), (&relocs, &link_relocs)] {
            let mut li = 0;
            for &p in list.iter() {
                let (t, _) = split_reloc(rd_u64(sys, p as usize));
                if t == RefTag::ExternalLinkage {
                    if let Some(&d) = ids.get(li) {
                        ext_link.insert(p, d);
                    }
                    li += 1;
                }
            }
        }

        let sizes = SectionSizes {
            objects: sys_payload,
            const_data: const_len,
            symbols: sym_len,
            relocs: rel_len,
            gvar_record: gv_len,
            fptr_record: fp_len,
            tail: buf.len().saturating_sub(tail_start),
        };
        Ok(Heap {
            data, incremental, sys_base, sys_len, const_base, const_len, sizes, symbols,
            gctags, relocs, memowner, memref, uniquing_types, uniquing_objs, fixup_types,
            fixup_objs, gvar_record, fptr_record, roots, link_ids_gvars,
            link_ids_external_fnvars, external_fns_begin, ext_link,
        })
    }

    /// The object section (index 0 = section base).
    #[inline]
    pub fn sys(&self) -> &[u8] {
        &self.data[self.sys_base..self.sys_base + self.sys_len]
    }
    #[inline]
    pub fn cdata(&self) -> &[u8] {
        &self.data[self.const_base..self.const_base + self.const_len]
    }
}
