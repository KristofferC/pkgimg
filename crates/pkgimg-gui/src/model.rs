//! Everything computed once per loaded image, off the UI thread.

use pkgimg_core::analysis::{self, CiRow, ConstLabel, Group, HistRow, MethodRow, ObjEntry, SectionSel};
use pkgimg_core::insights::Insight;
use pkgimg_core::world::Kind;
use pkgimg_core::{Obj, World};
use std::collections::HashMap;
use std::time::Duration;

pub struct Model {
    pub w: World,
    pub objs: Vec<ObjEntry>,
    pub cst: Vec<ObjEntry>,
    /// Type key per entry of `objs ++ cst`, as an index into `keys`.
    pub obj_key: Vec<u32>,
    pub keys: Vec<String>,
    pub cis: Vec<CiRow>,
    pub methods: Vec<MethodRow>,
    /// Per method: code instances and their native bytes.
    pub method_cis: Vec<(u32, u64)>,
    pub insights: Vec<Insight>,
    pub srctext: Vec<(String, String)>,
    pub hist_cache: HashMap<(Group, SectionSel), Vec<HistRow>>,
    pub load_time: Duration,
    pub stats: Stats,
    pub provenance_path: Option<String>,
}

#[derive(Default)]
pub struct Stats {
    pub n_methods: usize,
    pub n_mi: usize,
    pub native_cis: usize,
    pub ext_cis: usize,
    pub dead_cis: usize,
    pub native_bytes: u64,
    pub inferred_bytes: u64,
    pub untyped: usize,
}

impl Model {
    pub fn build(w: World, load_time: Duration) -> Model {
        let objs = analysis::object_table(&w, w.target);
        let cst = analysis::const_table(&w, w.target, &objs);
        let mut keys = vec![];
        let mut key_ix: HashMap<String, u32> = HashMap::new();
        let obj_key = objs
            .iter()
            .chain(&cst)
            .map(|e| {
                let k = analysis::type_key(&w, e, false);
                *key_ix.entry(k.clone()).or_insert_with(|| {
                    keys.push(k);
                    (keys.len() - 1) as u32
                })
            })
            .collect();
        let mut cis = analysis::code_instances(&w, w.target, &objs);
        #[cfg(not(target_arch = "wasm32"))]
        let provenance = pkgimg_core::provenance::Provenance::locate(&w, None);
        #[cfg(target_arch = "wasm32")]
        let provenance: Option<pkgimg_core::provenance::Provenance> = None;
        if let Some(p) = &provenance {
            analysis::annotate_provenance(&w, w.target, &mut cis, p);
        }
        let provenance_path = provenance.map(|p| p.path.display().to_string());
        let methods = analysis::methods(&w, w.target, &objs);
        let mut method_cis = vec![(0, 0); methods.len()];
        let ix: HashMap<Obj, usize> = methods.iter().enumerate().map(|(i, r)| (r.obj, i)).collect();
        for c in &cis {
            if let Some(&i) = c.def.and_then(|d| ix.get(&d)) {
                method_cis[i].0 += 1;
                method_cis[i].1 += c.native_bytes + c.wrapper_bytes;
            }
        }
        let insights = pkgimg_core::insights::insights(&w, &objs, &cst, &methods, &cis);
        let srctext = w.target().srctext();
        let stats = Stats {
            n_methods: methods.len(),
            n_mi: objs.iter().filter(|e| e.ty.is_some() && w.kind(e.obj) == Kind::MethodInstance).count(),
            native_cis: cis.iter().filter(|c| c.native_bytes > 0).count(),
            ext_cis: cis.iter().filter(|c| c.external_method).count(),
            dead_cis: cis.iter().filter(|c| c.status == "dead").count(),
            native_bytes: cis.iter().map(|c| c.native_bytes + c.wrapper_bytes).sum(),
            inferred_bytes: cis.iter().map(|c| c.inferred_bytes).sum(),
            untyped: objs.iter().filter(|e| e.ty.is_none()).count(),
        };
        let mut m = Model {
            w, objs, cst, obj_key, keys, cis, methods, method_cis, insights, srctext,
            hist_cache: HashMap::new(), load_time, stats, provenance_path,
        };
        m.hist(Group::Type, SectionSel::All);
        m
    }

    pub fn hist(&mut self, g: Group, s: SectionSel) -> &Vec<HistRow> {
        if !self.hist_cache.contains_key(&(g, s)) {
            let h = analysis::heap_histogram(&self.w, &self.objs, &self.cst, g, s);
            self.hist_cache.insert((g, s), h);
        }
        &self.hist_cache[&(g, s)]
    }

    pub fn n_entries(&self) -> usize {
        self.objs.len() + self.cst.len()
    }

    pub fn entry(&self, i: usize) -> &ObjEntry {
        if i < self.objs.len() { &self.objs[i] } else { &self.cst[i - self.objs.len()] }
    }

    /// Table entry for an object of the target image.
    pub fn find(&self, o: Obj) -> Option<usize> {
        if o.img != self.w.target {
            return None;
        }
        let (v, base) = if o.cst { (&self.cst, self.objs.len()) } else { (&self.objs, 0) };
        let i = v.binary_search_by_key(&o.off, |e| e.obj.off).ok()?;
        Some(base + i)
    }

    pub fn is_counted(&self, i: usize) -> bool {
        self.entry(i).label != ConstLabel::MemData
    }
}
