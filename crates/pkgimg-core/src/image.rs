//! Loading an image from disk: `.ji` (+ sibling native library) or a native library with an
//! embedded heap (the system image).

use crate::header::{self, Header, JI_FLAG_SPLIT};
use crate::heap::{Blob, Heap};
use crate::native::{self, NativeInfo};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct Image {
    pub path: PathBuf,
    pub native_path: Option<PathBuf>,
    pub header: Header,
    /// The `.ji` bytes (header + heap as stored on disk + srctext).
    pub ji: Blob,
    pub heap: Heap,
    /// Size of the heap as stored on disk (compressed or not).
    pub heap_stored_size: usize,
    pub native: Option<NativeInfo>,
    /// Bytes of the native library, for disassembly.
    pub native_bytes: Option<Blob>,
}

pub const DLEXT: &str = if cfg!(target_os = "macos") { "dylib" } else if cfg!(windows) { "dll" } else { "so" };

#[cfg(not(target_arch = "wasm32"))]
fn map_file(p: &Path) -> Result<Blob> {
    let f = std::fs::File::open(p).with_context(|| format!("opening {}", p.display()))?;
    // SAFETY: cache files are not expected to be modified while we read them.
    let m = unsafe { memmap2::Mmap::map(&f) }.with_context(|| format!("mapping {}", p.display()))?;
    Ok(Blob::new(Arc::new(m)))
}

#[cfg(target_arch = "wasm32")]
fn map_file(p: &Path) -> Result<Blob> {
    Ok(Blob::from_vec(std::fs::read(p).with_context(|| format!("reading {}", p.display()))?))
}

fn is_native(p: &Path) -> bool {
    matches!(p.extension().and_then(|e| e.to_str()), Some("so" | "dylib" | "dll"))
}

fn maybe_decompress(b: Blob) -> Result<Blob> {
    if b.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) { Ok(Blob::from_vec(decompress(&b)?)) } else { Ok(b) }
}

fn decompress(b: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut dec = ruzstd::decoding::StreamingDecoder::new(b).map_err(|e| anyhow::anyhow!("zstd: {e}"))?;
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

impl Image {
    /// Load from in-memory bytes (used by the web build). `bytes` is either a `.ji` (with
    /// `native` its native library, if any) or a native library with an embedded heap.
    pub fn from_bytes(path: PathBuf, bytes: Blob, native_path: Option<PathBuf>, native: Option<Blob>) -> Result<Image> {
        if bytes.starts_with(header::JI_MAGIC) {
            return Image::from_ji(path, bytes, native_path, native);
        }
        let (off, len) = native::embedded_image(&bytes)?.context("not a .ji file, and no embedded image in native library")?;
        let emb = bytes.slice(off, len)?;
        if emb.starts_with(header::JI_MAGIC) {
            return Image::from_ji(path.clone(), emb, Some(path), Some(bytes));
        }
        // Headerless heap (1.13 system images), possibly zstd-compressed.
        let (uname, arch) = native::platform(&bytes);
        let header = header::raw_sysimage_header(&uname, &arch);
        let heap_stored_size = emb.len();
        let data = maybe_decompress(emb.clone())?;
        let heap = Heap::parse(data, false, header.base.cache_align())?;
        let native = Some(native::parse(&bytes)?);
        Ok(Image { path: path.clone(), native_path: Some(path), header, ji: emb, heap, heap_stored_size, native, native_bytes: Some(bytes) })
    }

    fn from_ji(path: PathBuf, ji: Blob, native_path: Option<PathBuf>, native_buf: Option<Blob>) -> Result<Image> {
        let header = header::parse(&ji)?;
        let (ds, de) = (header.base.data_start as usize, header.base.data_end as usize);
        let stored = if ds > 0 && de > ds && de <= ji.len() {
            ji.slice(ds, de - ds)?
        } else {
            // 1.13 split images keep the heap in the native library, behind its own header.
            let n = native_buf.as_ref().context("the heap is stored in the native library, which was not found")?;
            let (off, len) = native::embedded_image(n)?.context("no embedded image in native library")?;
            let emb = n.slice(off, len)?;
            let (h, _) = header::parse_base(&emb)?;
            let (ds, de) = (h.data_start as usize, h.data_end as usize);
            if de > emb.len() || ds > de {
                bail!("heap range {ds}..{de} exceeds embedded image size {}", emb.len());
            }
            emb.slice(ds, de - ds)?
        };
        let heap_stored_size = stored.len();
        let data = maybe_decompress(stored)?;
        let heap = Heap::parse(data, header.base.is_pkgimage(), header.base.cache_align())?;
        let native = match &native_buf {
            Some(n) => Some(native::parse(n)?),
            None => None,
        };
        Ok(Image { path, native_path, header, ji, heap, heap_stored_size, native, native_bytes: native_buf })
    }

    /// Open a `.ji`, a pkgimage native library, or a system image (`sys.so`).
    pub fn open(path: &Path) -> Result<Image> {
        let mut path = path.to_path_buf();
        if is_native(&path) {
            let buf = map_file(&path)?;
            let sibling = path.with_extension("ji");
            if native::embedded_image(&buf)?.is_some() && !sibling.exists() {
                return Image::from_bytes(path, buf, None, None);
            }
            // Pkgimage: open via the .ji (the native library is picked up next to it)
            path = sibling;
        }
        let ji = map_file(&path)?;
        let (base, _) = header::parse_base(&ji).with_context(|| format!("reading {}", path.display()))?;
        let so = path.with_extension(DLEXT);
        let (native_path, native) = if so.exists() {
            (Some(so.clone()), Some(map_file(&so)?))
        } else {
            if base.flags & JI_FLAG_SPLIT != 0 {
                eprintln!("warning: {} not found; native code info unavailable", so.display());
            }
            (None, None)
        };
        Image::from_bytes(path, ji, native_path, native)
    }

    pub fn srctext(&self) -> Vec<(String, String)> {
        match &self.header.pkg {
            Some(p) => header::read_srctext(&self.ji, p.srctext_pos),
            None => vec![],
        }
    }

    pub fn display_name(&self) -> String {
        match &self.header.pkg {
            Some(p) => p.worklist.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(","),
            None => "<sysimage>".into(),
        }
    }
}
