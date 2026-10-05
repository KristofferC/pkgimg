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
}

pub const DLEXT: &str = if cfg!(target_os = "macos") { "dylib" } else if cfg!(windows) { "dll" } else { "so" };

fn map_file(p: &Path) -> Result<Blob> {
    let f = std::fs::File::open(p).with_context(|| format!("opening {}", p.display()))?;
    // SAFETY: cache files are not expected to be modified while we read them.
    let m = unsafe { memmap2::Mmap::map(&f) }.with_context(|| format!("mapping {}", p.display()))?;
    Ok(Blob::new(Arc::new(m)))
}

fn is_native(p: &Path) -> bool {
    matches!(p.extension().and_then(|e| e.to_str()), Some("so" | "dylib" | "dll"))
}

fn decompress(b: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut dec = ruzstd::decoding::StreamingDecoder::new(b).map_err(|e| anyhow::anyhow!("zstd: {e}"))?;
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

impl Image {
    /// Load from in-memory bytes (used by the web build). `native` is the optional native library.
    pub fn from_bytes(path: PathBuf, ji: Blob, native_path: Option<PathBuf>, native: Option<Blob>) -> Result<Image> {
        let (ji, native_buf) = match (header::parse_base(&ji), native) {
            (Ok(_), n) => (ji, n),
            (Err(_), None) if !ji.is_empty() => {
                // Maybe `ji` is itself a native library with an embedded heap.
                let (off, len) = native::embedded_image(&ji)?.context("no embedded image in native library")?;
                (ji.slice(off, len)?, Some(ji))
            }
            (Err(e), _) => return Err(e),
        };
        let header = header::parse(&ji)?;
        let (ds, de) = (header.base.data_start as usize, header.base.data_end as usize);
        if de > ji.len() || ds > de {
            bail!("heap range {ds}..{de} exceeds file size {}", ji.len());
        }
        let stored = ji.slice(ds, de - ds)?;
        let heap_stored_size = stored.len();
        let data = if stored.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            Blob::from_vec(decompress(&stored)?)
        } else {
            stored
        };
        let heap = Heap::parse(data, header.base.is_pkgimage(), header.base.cache_align())?;
        let native = match native_buf {
            Some(n) => Some(native::parse(&n)?),
            None => None,
        };
        Ok(Image { path, native_path, header, ji, heap, heap_stored_size, native })
    }

    /// Open a `.ji`, a pkgimage native library, or a system image (`sys.so`).
    pub fn open(path: &Path) -> Result<Image> {
        let mut path = path.to_path_buf();
        if is_native(&path) {
            let buf = map_file(&path)?;
            if let Some((off, len)) = native::embedded_image(&buf)? {
                let ji = buf.slice(off, len)?;
                return Image::from_bytes(path.clone(), ji, Some(path), Some(buf));
            }
            // Split pkgimage: the heap lives in the sibling .ji
            path = path.with_extension("ji");
        }
        let ji = map_file(&path)?;
        let (base, _) = header::parse_base(&ji)?;
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
