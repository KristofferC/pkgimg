//! `.ji` file header (`write_header` + `jl_write_header_for_incremental` in staticdata*.c).

use crate::bytes::Cursor;
use anyhow::{Result, bail};
use serde::Serialize;

pub const JI_MAGIC: &[u8] = b"\xfbjli\r\n\x1a\n";
pub const JI_FLAG_PKGIMAGE: u32 = 1 << 0;
pub const JI_FLAG_SPLIT: u32 = 1 << 1;

#[derive(Debug, Clone, Serialize)]
pub struct ModuleId {
    pub name: String,
    pub uuid: String,
    /// `build_id.hi` (0 when the header does not record it).
    pub build_id_hi: u64,
    pub build_id_lo: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncludeDep {
    pub module: String,
    pub path: String,
    pub fsize: u64,
    pub hash: u32,
    pub mtime: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheFlags {
    pub raw: u8,
    pub use_pkgimages: bool,
    pub debug_level: u8,
    pub check_bounds: u8,
    pub inline: bool,
    pub opt_level: u8,
}

impl CacheFlags {
    fn new(f: u8) -> Self {
        CacheFlags {
            raw: f,
            use_pkgimages: f & 1 != 0,
            debug_level: (f >> 1) & 3,
            check_bounds: (f >> 3) & 3,
            inline: (f >> 5) & 1 != 0,
            opt_level: (f >> 6) & 3,
        }
    }
}

/// The fixed prefix shared by system and package images.
#[derive(Debug, Clone, Serialize)]
pub struct BaseHeader {
    pub format_version: u16,
    pub ptr_size: u8,
    pub uname: String,
    pub arch: String,
    pub julia_version: String,
    pub gc_abi: String,
    pub flags: u32,
    pub git_branch: Option<String>,
    pub git_commit: Option<String>,
    pub checksum: u64,
    pub data_start: u64,
    pub data_end: u64,
    /// 1.13 split images: this is the header copy embedded in the native library.
    pub native_header: bool,
}

impl BaseHeader {
    pub fn is_pkgimage(&self) -> bool {
        self.flags & JI_FLAG_PKGIMAGE != 0
    }
    /// `JL_CACHE_BYTE_ALIGNMENT` of the platform that wrote the image.
    pub fn cache_align(&self) -> usize {
        let arch = self.arch.to_ascii_lowercase();
        if (arch == "aarch64" || arch == "arm64") && self.uname == "Darwin" || arch.starts_with("ppc64") {
            128
        } else {
            64
        }
    }
    /// "1.14.0-DEV" -> (1, 14)
    pub fn major_minor(&self) -> Option<(u32, u32)> {
        let mut it = self.julia_version.split(['.', '-', '+']);
        Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PkgHeader {
    pub cache_flags: CacheFlags,
    pub coverage: u8,
    pub syntax_version: u8,
    /// Modules this image defines (name, uuid, build_id.lo).
    pub worklist: Vec<ModuleId>,
    pub includes: Vec<IncludeDep>,
    /// `(module, required package)` pairs recorded via `Base._require_dependencies`.
    pub requires: Vec<(String, String)>,
    pub preferences: String,
    pub srctext_pos: i64,
    /// Modules that must be loaded first; `depsidx` j >= 1 in relocations refers to entry j-1.
    pub required_modules: Vec<ModuleId>,
    pub clone_targets: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub base: BaseHeader,
    pub pkg: Option<PkgHeader>,
}

fn uuid_str(hi: u64, lo: u64) -> String {
    if hi == 0 && lo == 0 {
        return String::new();
    }
    let x = ((hi as u128) << 64) | lo as u128;
    let h = format!("{x:032x}");
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn read_module_list(c: &mut Cursor, has_hi: bool) -> Result<Vec<ModuleId>> {
    let mut out = Vec::new();
    loop {
        let n = c.i32()?;
        if n == 0 {
            return Ok(out);
        }
        let name = c.lstr(n as usize)?;
        let (uhi, ulo) = (c.u64()?, c.u64()?);
        let build_id_hi = if has_hi { c.u64()? } else { 0 };
        let build_id_lo = c.u64()?;
        out.push(ModuleId { name, uuid: uuid_str(uhi, ulo), build_id_hi, build_id_lo });
    }
}

/// Header formats this reader understands: 16 (master), 12 (1.13).
pub const SUPPORTED_FORMATS: &[u16] = &[12, 16];

pub fn parse_base(buf: &[u8]) -> Result<(BaseHeader, usize)> {
    if !buf.starts_with(JI_MAGIC) {
        bail!("not a Julia image (bad magic)");
    }
    let mut c = Cursor::new(buf, JI_MAGIC.len());
    let format_version = c.u16()?;
    if !SUPPORTED_FORMATS.contains(&format_version) {
        bail!("unsupported image format version {format_version} (supported: {SUPPORTED_FORMATS:?})");
    }
    let bom = c.u16()?;
    if bom != 0xFEFF {
        bail!("unsupported byte order");
    }
    let ptr_size = c.u8()?;
    if ptr_size != 8 {
        bail!("only 64-bit images are supported");
    }
    let uname = c.cstr()?;
    let arch = c.cstr()?;
    let julia_version = c.cstr()?;
    if format_version == 12 {
        // 1.12 shares the format number with 1.13 but differs in layout.
        let mut it = julia_version.split(['.', '-', '+']);
        let mm: (u32, u32) = (it.next().and_then(|x| x.parse().ok()).unwrap_or(0), it.next().and_then(|x| x.parse().ok()).unwrap_or(0));
        if mm < (1, 13) {
            bail!("Julia {julia_version} images are not supported (supported: 1.13 and master)");
        }
    }
    let h = if format_version >= 16 {
        let gc_abi = c.cstr()?;
        let flags = c.u32()?;
        let (git_branch, git_commit) = if flags & JI_FLAG_PKGIMAGE != 0 {
            (Some(c.cstr()?), Some(c.cstr()?))
        } else {
            (None, None)
        };
        let checksum = c.u32()? as u64;
        BaseHeader {
            format_version, ptr_size, uname, arch, julia_version, gc_abi, flags,
            git_branch, git_commit, checksum, data_start: c.u64()?, data_end: c.u64()?,
            native_header: false,
        }
    } else {
        // 1.13: only incremental images have a header. The `.ji` carries pkgimage=0, the
        // copy embedded in the native library pkgimage=1 (followed by flags + module list).
        let git_branch = Some(c.cstr()?);
        let git_commit = Some(c.cstr()?);
        let native_header = c.u8()? != 0;
        let checksum = c.u64()?;
        BaseHeader {
            format_version, ptr_size, uname, arch, julia_version, gc_abi: String::new(),
            flags: JI_FLAG_PKGIMAGE, git_branch, git_commit, checksum,
            data_start: c.u64()?, data_end: c.u64()?, native_header,
        }
    };
    Ok((h, c.pos))
}

/// Base header plus the worklist, reading as little as possible (for cache-file lookup).
pub fn parse_worklist(buf: &[u8]) -> Result<(BaseHeader, Vec<ModuleId>)> {
    let (base, pos) = parse_base(buf)?;
    let skip = if base.format_version >= 16 { 3 } else { 1 };
    let mut c = Cursor::new(buf, pos + skip);
    let wl = read_module_list(&mut c, false)?;
    Ok((base, wl))
}

/// Synthesized header for a headerless (1.13) system image heap.
pub fn raw_sysimage_header(uname: &str, arch: &str) -> Header {
    Header {
        base: BaseHeader {
            format_version: 0, ptr_size: 8, uname: uname.into(), arch: arch.into(),
            julia_version: String::new(), gc_abi: String::new(), flags: 0, git_branch: None,
            git_commit: None, checksum: 0, data_start: 0, data_end: 0, native_header: false,
        },
        pkg: None,
    }
}

pub fn parse(buf: &[u8]) -> Result<Header> {
    let (base, pos) = parse_base(buf)?;
    if !base.is_pkgimage() {
        return Ok(Header { base, pkg: None });
    }
    let mut c = Cursor::new(buf, pos);
    let cache_flags = CacheFlags::new(c.u8()?);
    let (coverage, syntax_version) = if base.format_version >= 16 { (c.u8()?, c.u8()?) } else { (0, 0) };
    let worklist = read_module_list(&mut c, false)?;
    let _totbytes = c.u64()?;
    let mut includes = Vec::new();
    let mut requires = Vec::new();
    loop {
        let n = c.i32()?;
        if n == 0 {
            break;
        }
        let dep = c.take(n as usize)?.to_vec();
        let fsize = c.u64()?;
        let hash = c.u32()?;
        let mtime = c.f64()?;
        let n1 = c.i32()?;
        let module = if n1 == 0 { String::new() } else {
            worklist.get(n1 as usize - 1).map_or_else(|| format!("#{n1}"), |m| m.name.clone())
        };
        let mut modpath = vec![module.clone()];
        if n1 != 0 {
            loop {
                let m = c.i32()?;
                if m == 0 {
                    break;
                }
                modpath.push(c.lstr(m as usize)?);
            }
        }
        if dep.first() == Some(&0) {
            requires.push((modpath.join("."), String::from_utf8_lossy(&dep[1..]).into_owned()));
        } else {
            includes.push(IncludeDep {
                module: modpath.join("."),
                path: String::from_utf8_lossy(&dep).into_owned(),
                fsize, hash, mtime,
            });
        }
    }
    let n = c.i32()?;
    let preferences = c.lstr(n as usize)?;
    let srctext_pos = c.i64()?;
    let required_modules = read_module_list(&mut c, true)?;
    let l = c.u32()?;
    let clone_targets = c.take(l as usize)?.to_vec();
    Ok(Header {
        base,
        pkg: Some(PkgHeader {
            cache_flags, coverage, syntax_version, worklist, includes, requires,
            preferences, srctext_pos, required_modules, clone_targets,
        }),
    })
}

/// Source files embedded after the heap (`write_srctext`): `(path, text)` pairs.
pub fn read_srctext(buf: &[u8], srctext_pos: i64) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if srctext_pos <= 0 || srctext_pos as usize >= buf.len() {
        return out;
    }
    let mut c = Cursor::new(buf, srctext_pos as usize);
    let res: Result<()> = (|| {
        loop {
            let n = c.i32()?;
            if n == 0 {
                return Ok(());
            }
            let path = c.lstr(n as usize)?;
            let len = c.u64()?;
            let text = c.lstr(len as usize)?;
            out.push((path, text));
        }
    })();
    let _ = res;
    out
}
