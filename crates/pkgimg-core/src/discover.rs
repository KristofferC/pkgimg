//! Finding cache files on this machine: depots, Julia installations and their stdlib caches.

use crate::header::{self, ModuleId};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum RootKind {
    /// `<depot>/compiled`
    Depot,
    /// `<prefix>/share/julia/compiled` of a Julia installation or source build
    Install,
    /// A directory the user pointed at
    Custom,
}

#[derive(Clone, Debug, Serialize)]
pub struct Root {
    pub kind: RootKind,
    /// The depot or installation prefix.
    pub path: PathBuf,
    /// The installation's system image, if any.
    pub sysimage: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CacheFile {
    pub package: String,
    /// `v1.14`
    pub julia: String,
    pub ji: PathBuf,
    pub native: Option<PathBuf>,
    pub ji_size: u64,
    pub native_size: u64,
    #[serde(skip)]
    pub modified: SystemTime,
    /// Index into `Discovery::roots`.
    pub root: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Discovery {
    pub roots: Vec<Root>,
    pub caches: Vec<CacheFile>,
}

/// Header facts cheap to read from the first bytes of a `.ji`.
#[derive(Clone, Debug, Serialize)]
pub struct HeaderSummary {
    pub julia_version: String,
    pub git_commit: Option<String>,
    pub format_version: u16,
    pub modules: Vec<ModuleId>,
    /// Whether this reader understands the image format.
    pub supported: bool,
}

pub fn read_summary(ji: &Path) -> Option<HeaderSummary> {
    use std::io::Read;
    let f = std::fs::File::open(ji).ok()?;
    let mut buf = Vec::with_capacity(1 << 16);
    f.take(1 << 16).read_to_end(&mut buf).ok()?;
    match header::parse_worklist(&buf) {
        Ok((base, modules)) => Some(HeaderSummary {
            julia_version: base.julia_version,
            git_commit: base.git_commit,
            format_version: base.format_version,
            modules,
            supported: true,
        }),
        Err(_) if buf.starts_with(header::JI_MAGIC) && buf.len() > 10 => Some(HeaderSummary {
            julia_version: buf[13..].split(|&b| b == 0).nth(2).map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default(),
            git_commit: None,
            format_version: u16::from_le_bytes([buf[8], buf[9]]),
            modules: vec![],
            supported: false,
        }),
        Err(_) => None,
    }
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Depots in search order: `$JULIA_DEPOT_PATH` (an empty entry means the default), `~/.julia`.
pub fn depots() -> Vec<PathBuf> {
    let mut out = vec![];
    if let Ok(dp) = std::env::var("JULIA_DEPOT_PATH") {
        out.extend(dp.split(':').filter(|s| !s.is_empty()).map(PathBuf::from));
    }
    if let Some(h) = home() {
        out.push(h.join(".julia"));
    }
    dedup(out)
}

fn dedup(v: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = vec![];
    for p in v {
        let c = std::fs::canonicalize(&p).unwrap_or(p);
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// Installation prefixes (directories with `share/julia/compiled` or `lib/julia/sys.*`):
/// juliaup installs, `julia` on `PATH`, `./usr`, and source builds at `~/*/usr`.
pub fn installs() -> Vec<PathBuf> {
    let mut c = vec![];
    if let Ok(cwd) = std::env::current_dir() {
        for a in cwd.ancestors().take(4) {
            c.push(a.join("usr"));
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for d in path.split(':') {
            if let Ok(real) = std::fs::canonicalize(Path::new(d).join("julia"))
                && let Some(prefix) = real.parent().and_then(|p| p.parent())
            {
                c.push(prefix.to_path_buf());
            }
        }
    }
    if let Some(h) = home() {
        for dir in [h.join(".julia").join("juliaup"), h.clone()] {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    c.push(p.join("usr")); // source builds
                    c.push(p); // juliaup installs
                }
            }
        }
    }
    let so = format!("sys.{}", crate::image::DLEXT);
    let c = c.into_iter().filter(|p| p.join("lib").join("julia").join(&so).is_file()).collect();
    dedup(c)
}

/// Short display name for a root: `juliaup 1.12.4`, `~/julia/usr`, `depot ~/.julia`.
pub fn root_label(r: &Root) -> String {
    let p = r.path.display().to_string();
    let short = match std::env::var("HOME") {
        Ok(h) if p.starts_with(&h) => format!("~{}", &p[h.len()..]),
        _ => p,
    };
    if let Some(rest) = short.split("/juliaup/").nth(1) {
        let v = rest.trim_start_matches("julia-");
        let v = v.split(".x64").next().unwrap_or(v).trim_end_matches("+0");
        return format!("juliaup {v}");
    }
    match r.kind {
        RootKind::Depot => format!("depot {short}"),
        _ => short,
    }
}

pub fn sysimage_of(prefix: &Path) -> Option<PathBuf> {
    let p = prefix.join("lib").join("julia").join(format!("sys.{}", crate::image::DLEXT));
    p.is_file().then_some(p)
}

/// Caches under `<root>/vX.Y/<Package>/*.ji` (`compiled` is the directory holding `vX.Y`).
fn scan_compiled(compiled: &Path, root: usize, out: &mut Vec<CacheFile>) {
    let Ok(vers) = std::fs::read_dir(compiled) else { return };
    for v in vers.flatten() {
        let julia = v.file_name().to_string_lossy().into_owned();
        if !julia.starts_with('v') {
            continue;
        }
        let Ok(pkgs) = std::fs::read_dir(v.path()) else { continue };
        for p in pkgs.flatten() {
            let package = p.file_name().to_string_lossy().into_owned();
            let Ok(files) = std::fs::read_dir(p.path()) else { continue };
            for f in files.flatten() {
                let ji = f.path();
                if ji.extension().is_none_or(|e| e != "ji") {
                    continue;
                }
                let Ok(md) = f.metadata() else { continue };
                let so = ji.with_extension(crate::image::DLEXT);
                let native_size = std::fs::metadata(&so).map(|m| m.len()).ok();
                out.push(CacheFile {
                    package: package.clone(),
                    julia: julia.clone(),
                    native: native_size.is_some().then_some(so),
                    ji,
                    ji_size: md.len(),
                    native_size: native_size.unwrap_or(0),
                    modified: md.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    root,
                });
            }
        }
    }
}

/// `.ji` files directly inside `dir` (e.g. a `compiled/vX.Y/<Package>` directory).
fn scan_flat(dir: &Path, root: usize, out: &mut Vec<CacheFile>) {
    let Ok(files) = std::fs::read_dir(dir) else { return };
    let package = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let julia = dir.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).filter(|v| v.starts_with('v')).unwrap_or_else(|| "?".into());
    for f in files.flatten() {
        let ji = f.path();
        if ji.extension().is_none_or(|e| e != "ji") {
            continue;
        }
        let Ok(md) = f.metadata() else { continue };
        let so = ji.with_extension(crate::image::DLEXT);
        let native_size = std::fs::metadata(&so).map(|m| m.len()).ok();
        out.push(CacheFile {
            package: package.clone(), julia: julia.clone(), native: native_size.is_some().then_some(so), ji,
            ji_size: md.len(), native_size: native_size.unwrap_or(0),
            modified: md.modified().unwrap_or(SystemTime::UNIX_EPOCH), root,
        });
    }
}

/// Everything discoverable on this machine, plus `extra` directories (either a `compiled`
/// directory, a depot, an installation prefix, or a directory of cache files).
pub fn discover(extra: &[PathBuf]) -> Discovery {
    let mut d = Discovery::default();
    for p in depots() {
        d.roots.push(Root { kind: RootKind::Depot, sysimage: None, path: p });
    }
    for p in installs() {
        d.roots.push(Root { kind: RootKind::Install, sysimage: sysimage_of(&p), path: p });
    }
    for p in extra {
        d.roots.push(Root { kind: RootKind::Custom, sysimage: None, path: p.clone() });
    }
    for (i, r) in d.roots.iter().enumerate() {
        match r.kind {
            RootKind::Depot => scan_compiled(&r.path.join("compiled"), i, &mut d.caches),
            RootKind::Install => scan_compiled(&r.path.join("share").join("julia").join("compiled"), i, &mut d.caches),
            RootKind::Custom => {
                let p = &r.path;
                for c in [p.join("compiled"), p.join("share").join("julia").join("compiled"), p.clone()] {
                    scan_compiled(&c, i, &mut d.caches);
                }
                scan_flat(p, i, &mut d.caches);
            }
        }
    }
    // The same file can be reachable from several roots (e.g. ./usr and ~/julia/usr).
    let mut seen = std::collections::HashSet::new();
    d.caches.retain(|c| seen.insert(std::fs::canonicalize(&c.ji).unwrap_or_else(|_| c.ji.clone())));
    d
}

/// The system image to pair with a cache found under an installation, if any.
pub fn sysimage_for(d: &Discovery, c: &CacheFile) -> Option<PathBuf> {
    d.roots.get(c.root).and_then(|r| r.sysimage.clone())
}
