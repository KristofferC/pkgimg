//! Optional provenance sidecar written by an instrumented Julia (`JULIA_IMAGE_PROVENANCE=<dir>`):
//! for each CodeInstance in the image, the MethodInstance whose inference requested it
//! (`parent`) and the root of that inference (`root`).

use crate::world::{ImgId, Obj, Val, World};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub enum PRef {
    None,
    /// Object in the image's object section.
    Obj(u32),
    /// Described by the writer (object not in this image).
    Text(String),
}

#[derive(Default)]
pub struct Provenance {
    pub path: PathBuf,
    /// CodeInstance offset -> (parent, root)
    pub by_ci: HashMap<u32, (PRef, PRef)>,
}

fn pref(s: &str) -> PRef {
    match s {
        "-" | "" => PRef::None,
        s if s.starts_with('@') => s[1..].parse().map_or(PRef::Text(s.into()), PRef::Obj),
        s => PRef::Text(s.into()),
    }
}

impl Provenance {
    pub fn parse(text: &str, path: PathBuf) -> Provenance {
        let mut by_ci = HashMap::new();
        for line in text.lines() {
            if line.starts_with('#') {
                continue;
            }
            let mut it = line.split('\t');
            let (Some(ci), Some(p), Some(r)) = (it.next(), it.next(), it.next()) else { continue };
            if let PRef::Obj(off) = pref(ci) {
                by_ci.insert(off, (pref(p), pref(r)));
            }
        }
        Provenance { path, by_ci }
    }

    /// Find the sidecar for the target image: `explicit` (file or directory), else
    /// `$JULIA_IMAGE_PROVENANCE`, else next to the `.ji`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn locate(w: &World, explicit: Option<&Path>) -> Option<Provenance> {
        let im = w.target();
        let top = im.header.pkg.as_ref()?.worklist.last()?;
        let fname = format!("{}-{:016x}.tsv", top.name, top.build_id_lo);
        let mut cands = vec![];
        if let Some(e) = explicit {
            cands.push(if e.is_dir() { e.join(&fname) } else { e.to_path_buf() });
        }
        if let Ok(d) = std::env::var("JULIA_IMAGE_PROVENANCE") {
            cands.push(Path::new(&d).join(&fname));
        }
        if let Some(dir) = im.path.parent() {
            cands.push(dir.join(&fname));
        }
        cands.into_iter().find_map(|p| std::fs::read_to_string(&p).ok().map(|t| Provenance::parse(&t, p)))
    }

    pub fn show(&self, w: &World, img: ImgId, r: &PRef) -> Option<String> {
        match r {
            PRef::None => None,
            PRef::Obj(off) => Some(w.show(Val::Obj(Obj { img, cst: false, off: *off }), 5)),
            PRef::Text(t) => Some(t.clone()),
        }
    }
}
