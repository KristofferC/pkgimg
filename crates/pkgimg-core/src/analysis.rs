//! Derived tables: objects with types and sizes, histograms, methods, code instances.

use crate::heap::{RefTag, split_reloc};
use crate::bytes::rd_u64;
use crate::world::{ImgId, Kind, Obj, Val, World};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Copy, Debug)]
pub struct ObjEntry {
    pub obj: Obj,
    pub ty: Option<Obj>,
    /// Bytes attributed to the object, including alignment padding after it.
    pub size: u32,
    pub label: ConstLabel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstLabel {
    Object,
    Layout,
    FieldFlags,
    /// Out-of-line element data of a bits-type `GenericMemory` (`ty` is the memory's type).
    MemData,
}

/// All objects of the object section of `img`, in address order.
pub fn object_table(w: &World, img: ImgId) -> Vec<ObjEntry> {
    let heap = &w.img(img).heap;
    let n = heap.gctags.len();
    let mut tags = heap.gctags.clone();
    tags.sort_unstable();
    let mut starts = Vec::with_capacity(n);
    let mut out = Vec::with_capacity(n);
    for &p in &tags {
        let obj = Obj { img, cst: false, off: p + 8 };
        let ty = w.type_of(obj);
        let has_id = ty.and_then(|t| w.datatype(t)).is_some_and(|t| t.has_object_id());
        starts.push(if has_id { p - 8 } else { p });
        out.push(ObjEntry { obj, ty, size: 0, label: ConstLabel::Object });
    }
    let end = heap.sys_len as u32;
    for i in 0..n {
        let next = starts.get(i + 1).copied().unwrap_or(end);
        out[i].size = next.saturating_sub(starts[i]);
    }
    out
}

/// Objects in the constant-data section, found as targets of `ConstDataRef` pointers.
pub fn const_table(w: &World, img: ImgId, objs: &[ObjEntry]) -> Vec<ObjEntry> {
    let heap = &w.img(img).heap;
    let sys = heap.sys();
    let mut targets: BTreeMap<u32, ConstLabel> = BTreeMap::new();
    // Layout pointers live at known fields; everything else referencing const data is an object.
    let mut special: HashMap<u32, ConstLabel> = HashMap::new();
    let mut owner: HashMap<u32, Option<Obj>> = HashMap::new();
    let mut target_owner: HashMap<u32, Option<Obj>> = HashMap::new();
    for e in objs {
        match e.ty.map(|_| w.kind(e.obj)) {
            Some(Kind::DataType) => {
                special.insert(e.obj.off + 40, ConstLabel::Layout);
            }
            Some(Kind::TypeName) => {
                special.insert(e.obj.off + 32, ConstLabel::FieldFlags);
                special.insert(e.obj.off + 40, ConstLabel::FieldFlags);
            }
            Some(Kind::GenericMemory) => {
                special.insert(e.obj.off + 8, ConstLabel::MemData);
                owner.insert(e.obj.off + 8, e.ty);
            }
            _ => {}
        }
    }
    let mut add = |word: u64, pos: Option<u32>| {
        let (t, o) = split_reloc(word);
        if t == RefTag::ConstData {
            let lab = pos.and_then(|p| special.get(&p).copied()).unwrap_or(ConstLabel::Object);
            if lab == ConstLabel::MemData {
                target_owner.insert((o * 8) as u32, pos.and_then(|p| owner.get(&p).copied()).flatten());
            }
            targets.entry((o * 8) as u32).or_insert(lab);
        }
    };
    for &p in &heap.relocs {
        add(rd_u64(sys, p as usize), Some(p));
    }
    for &g in &heap.gvar_record {
        add(g, None);
    }
    let keys: Vec<(u32, ConstLabel)> = targets.into_iter().collect();
    let mut out = Vec::with_capacity(keys.len());
    let end = heap.const_len as u32;
    for (i, &(off, label)) in keys.iter().enumerate() {
        // Tagged objects start one word before the pointer target.
        let start = |k: usize| -> u32 {
            let (o, l) = keys[k];
            if l == ConstLabel::Object { o.saturating_sub(8) } else { o }
        };
        let next = if i + 1 < keys.len() { start(i + 1) } else { end };
        let obj = Obj { img, cst: true, off };
        let ty = match label {
            ConstLabel::Object => w.type_of(obj),
            ConstLabel::MemData => target_owner.get(&off).copied().flatten(),
            _ => None,
        };
        out.push(ObjEntry { obj, ty, size: next.saturating_sub(start(i)), label });
    }
    out
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct HistRow {
    pub key: String,
    pub count: u64,
    pub bytes: u64,
}

pub fn type_key(w: &World, e: &ObjEntry, full: bool) -> String {
    match e.label {
        ConstLabel::Layout => return "<datatype layout>".into(),
        ConstLabel::FieldFlags => return "<field flags>".into(),
        ConstLabel::Object | ConstLabel::MemData => {}
    }
    let Some(t) = e.ty else { return "<unknown>".into() };
    if full {
        return w.show(Val::Obj(t), 4);
    }
    w.datatype(t).map_or_else(|| "<unknown>".into(), |ti| ti.qualified())
}

/// Aggregate `(key, bytes, count)` rows, largest first.
pub fn histogram(rows: impl Iterator<Item = (String, u64, u64)>) -> Vec<HistRow> {
    let mut m: HashMap<String, HistRow> = HashMap::new();
    for (k, b, c) in rows {
        let r = m.entry(k.clone()).or_insert_with(|| HistRow { key: k, ..Default::default() });
        r.count += c;
        r.bytes += b;
    }
    let mut v: Vec<HistRow> = m.into_values().collect();
    v.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.key.cmp(&b.key)));
    v
}

pub fn f16_to_f32(h: u16) -> f32 {
    let s = ((h >> 15) & 1) as u32;
    let e = ((h >> 10) & 0x1f) as i32;
    let m = (h & 0x3ff) as u32;
    let v = if e == 0 {
        (m as f32) * 2f32.powi(-24)
    } else if e == 31 {
        if m == 0 { f32::INFINITY } else { f32::NAN }
    } else {
        (1.0 + m as f32 / 1024.0) * 2f32.powi(e - 15)
    };
    if s == 1 { -v } else { v }
}

#[derive(Clone, Debug, Serialize)]
pub struct MethodRow {
    #[serde(skip)]
    pub obj: Obj,
    pub name: String,
    pub module: String,
    pub file: String,
    pub line: i64,
    pub sig: String,
    /// The method is defined in another image (this image adds specializations to it).
    pub external: bool,
}

pub fn method_info(w: &World, m: Obj) -> MethodRow {
    let name = w.field(m, "name").and_then(|v| w.sym_name(v)).unwrap_or_default();
    let module = w.field(m, "module").and_then(|v| v.obj()).map(|o| w.module_path(o).to_string()).unwrap_or_default();
    let file = w.field(m, "file").and_then(|v| w.sym_name(v)).unwrap_or_default();
    let line = w.field_u64(m, "line").map_or(0, |l| l as i32 as i64);
    let sig = w.field(m, "sig").map(|s| show_sig(w, s)).unwrap_or_default();
    MethodRow { obj: m, name, module, file, line, sig, external: false }
}

/// Render a signature `Tuple{typeof(f), A, B} where T` as `(A, B) where T`.
pub fn show_sig(w: &World, sig: Val) -> String {
    let mut body = sig;
    let mut vars = vec![];
    while let Some(o) = body.obj() {
        if w.kind(o) != Kind::UnionAll || vars.len() > 16 {
            break;
        }
        if let Some(tv) = w.field(o, "var").and_then(|v| v.obj()) {
            vars.push(w.field(tv, "name").and_then(|n| w.sym_name(n)).unwrap_or_default());
        }
        body = w.field(o, "body").unwrap_or(Val::Null);
    }
    let Some(dt) = body.obj().filter(|o| w.kind(*o) == Kind::DataType).and_then(|o| w.datatype(o)) else {
        return w.show(sig, 5);
    };
    let args: Vec<String> = dt.params.iter().skip(1).map(|p| w.show(*p, 4)).collect();
    let mut s = format!("({})", args.join(", "));
    if !vars.is_empty() {
        s.push_str(&format!(" where {}", vars.join(", ")));
    }
    s
}

#[derive(Clone, Debug, Serialize)]
pub struct CiRow {
    #[serde(skip)]
    pub obj: Obj,
    #[serde(skip)]
    pub mi: Option<Obj>,
    pub method: String,
    pub module: String,
    pub file: String,
    pub line: i64,
    pub spec: String,
    /// `nothing` for native compilation; otherwise the abstract interpreter's cache owner.
    pub owner: String,
    /// "live" (valid, revalidated on load), "dead" (invalidated before saving), or raw worlds.
    pub status: String,
    pub external_method: bool,
    pub inferred_bytes: u64,
    pub inferred: String,
    pub invoke: String,
    pub native_bytes: u64,
    pub native_symbol: Option<String>,
    /// Address of the specialized function in the native library.
    #[serde(skip)]
    pub native_addr: Option<u64>,
    pub wrapper_bytes: u64,
    pub infer_self_ms: f32,
    pub infer_total_ms: f32,
    pub rettype: String,
    /// From the provenance sidecar: MethodInstance whose inference requested this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// From the provenance sidecar: root of that inference (entry point).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

pub fn code_instances(w: &World, img: ImgId, objs: &[ObjEntry]) -> Vec<CiRow> {
    let image = w.img(img);
    // fvar index -> (ci offset, is wrapper)
    let mut spec_fn: HashMap<u32, u64> = HashMap::new();
    let mut wrap_fn: HashMap<u32, u64> = HashMap::new();
    if let Some(nat) = &image.native {
        for (i, &rec) in image.heap.fptr_record.iter().enumerate() {
            if rec == 0 {
                continue;
            }
            let (off, wrapper) = if rec >> 63 != 0 { (!rec, true) } else { (rec, false) };
            let addr = nat.fvars.get(i).copied().unwrap_or(0);
            if addr == 0 {
                continue;
            }
            if wrapper { &mut wrap_fn } else { &mut spec_fn }.insert(off as u32, addr);
        }
    }
    let mut out = vec![];
    for e in objs {
        if e.ty.is_none() || w.kind(e.obj) != Kind::CodeInstance {
            continue;
        }
        let ci = e.obj;
        let mut mi = w.field(ci, "def").and_then(|v| v.obj());
        if let Some(d) = mi
            && w.kind(d) != Kind::MethodInstance
        {
            // ABIOverride: def.def is the MethodInstance
            mi = w.field(d, "def").and_then(|v| v.obj());
        }
        let (mut method, mut module, mut file, mut line, mut spec, mut ext) =
            (String::new(), String::new(), String::new(), 0, String::new(), false);
        if let Some(mi) = mi {
            spec = w.field(mi, "specTypes").map(|s| show_sig(w, s)).unwrap_or_default();
            if let Some(m) = w.field(mi, "def").and_then(|v| v.obj()) {
                if w.kind(m) == Kind::Method {
                    let r = method_info(w, m);
                    (method, module, file, line) = (r.name, r.module, r.file, r.line);
                    ext = m.img != img;
                } else if w.kind(m) == Kind::Module {
                    method = "<toplevel thunk>".into();
                    module = w.module_path(m).to_string();
                }
            }
        }
        let owner = w.field(ci, "owner").map(|v| w.show(v, 3)).unwrap_or_default();
        let minw = w.field_u64(ci, "min_world").unwrap_or(0);
        let maxw = w.field_u64(ci, "max_world").unwrap_or(0);
        let status = match (minw, maxw) {
            (u64::MAX, 1) => "live".to_string(),
            (1, 0) => "dead".to_string(),
            (a, b) => format!("{a}..{b}"),
        };
        let inf = w.field(ci, "inferred").unwrap_or(Val::Null);
        let (inferred, inferred_bytes) = match inf {
            Val::Obj(o) => match w.kind(o) {
                Kind::String => ("compressed".to_string(), w.string_len(o)),
                _ => (w.type_info(o).map_or("?".into(), |t| t.name.clone()), e.size as u64),
            },
            Val::Nothing => ("nothing".into(), 0),
            Val::Null => ("#undef".into(), 0),
            v => (w.show(v, 2), 0),
        };
        let invoke = match w.field_bytes(ci, "invoke").map(|_| w.decode_at(ci.img, invoke_pos(w, ci))) {
            Some(Val::Func(f)) => match f & 0xff {
                1 => "args",
                2 => "const_return",
                3 => "sparam",
                4 => "interpreted",
                5 => "specsig",
                _ => "?",
            }
            .to_string(),
            _ => if spec_fn.contains_key(&ci.off) || wrap_fn.contains_key(&ci.off) { "specsig".into() } else { "none".into() },
        };
        let nat = image.native.as_ref();
        let sym = |m: &HashMap<u32, u64>| -> (u64, Option<String>) {
            match (m.get(&ci.off), nat) {
                (Some(&a), Some(n)) => n.func_at(a).map_or((0, None), |f| (f.size, Some(f.name.clone()))),
                _ => (0, None),
            }
        };
        let (native_bytes, native_symbol) = sym(&spec_fn);
        let native_addr = match (spec_fn.get(&ci.off), nat) {
            (Some(&a), Some(n)) => n.func_at(a).map(|f| f.addr),
            _ => None,
        };
        let (wrapper_bytes, _) = sym(&wrap_fn);
        let ms = |name| w.field_u64(ci, name).map_or(0.0, |x| f16_to_f32(x as u16) * 1000.0);
        let rettype = w.field(ci, "rettype").map(|v| w.show(v, 3)).unwrap_or_default();
        out.push(CiRow {
            obj: ci, mi, parent: None, root: None, method, module, file, line, spec, owner, status, external_method: ext,
            inferred_bytes, inferred, invoke, native_bytes, native_symbol, native_addr, wrapper_bytes,
            infer_self_ms: ms("time_infer_self"), infer_total_ms: ms("time_infer_total"), rettype,
        });
    }
    out
}

fn invoke_pos(w: &World, ci: Obj) -> usize {
    let ti = w.type_info(ci).unwrap();
    let i = ti.field_index("invoke").unwrap();
    (ci.off + ti.layout.as_ref().unwrap().fields[i].offset) as usize
}

pub fn methods(w: &World, img: ImgId, objs: &[ObjEntry]) -> Vec<MethodRow> {
    objs.iter()
        .filter(|e| e.ty.is_some() && w.kind(e.obj) == Kind::Method)
        .map(|e| MethodRow { external: e.obj.img != img, ..method_info(w, e.obj) })
        .collect()
}

/// Bytes attributed to each module: objects are charged to the module of their
/// nearest owning Method/TypeName/Module where cheap to find, else to "<other>".
pub fn module_of(w: &World, e: &ObjEntry) -> Option<String> {
    let o = e.obj;
    match w.kind(o) {
        Kind::Method => w.field(o, "module").and_then(|v| v.obj()).map(|m| w.module_path(m).to_string()),
        Kind::Module => Some(w.module_path(o).to_string()),
        Kind::TypeName => w.field(o, "module").and_then(|v| v.obj()).map(|m| w.module_path(m).to_string()),
        Kind::DataType => w.datatype(o).map(|t| t.module.clone()),
        _ => None,
    }
}

/// Label for the slot at `pos` inside object `e` (`Type.field` or `Type[]`).
pub fn slot_label(w: &World, e: &ObjEntry, pos: u32) -> String {
    let Some(ti) = e.ty.and_then(|t| w.datatype(t)) else { return "<unknown>".into() };
    let rel = pos.wrapping_sub(e.obj.off);
    match ti.kind {
        Kind::SimpleVector => return "SimpleVector[]".into(),
        Kind::GenericMemory => {
            let elt = ti.params.get(1).map(|p| w.show(*p, 2)).unwrap_or_default();
            return if rel == 8 { "GenericMemory.ptr".into() } else { format!("Memory{{{elt}}}[]") };
        }
        Kind::Module => return "Module".into(),
        _ => {}
    }
    if let Some(l) = &ti.layout {
        for (i, f) in l.fields.iter().enumerate() {
            if rel >= f.offset && rel < f.offset + f.size.max(8) {
                return format!("{}.{}", ti.name, ti.field_names.get(i).map_or("?", |s| s.as_str()));
            }
        }
    }
    format!("{}+{rel}", ti.name)
}

/// For every object (in either section) the first slot that references it.
pub fn first_referrers(w: &World, img: ImgId, objs: &[ObjEntry]) -> HashMap<Obj, (usize, u32)> {
    let heap = &w.img(img).heap;
    let mut out: HashMap<Obj, (usize, u32)> = HashMap::with_capacity(heap.relocs.len());
    let mut relocs = heap.relocs.clone();
    relocs.sort_unstable();
    for &p in &relocs {
        let oi = objs.partition_point(|e| e.obj.off <= p + 8).saturating_sub(1);
        if let Val::Obj(t) = w.decode_at(img, p as usize)
            && t.img == img
        {
            // Pointers into the middle of an object (memory data) count for that object.
            out.entry(t).or_insert((oi, p));
        }
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    Type,
    FullType,
    Referrer,
    Section,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SectionSel {
    All,
    Objects,
    Const,
}

/// Grouping key of one entry; `refs` is needed for `Group::Referrer`.
pub fn group_key(w: &World, objs: &[ObjEntry], refs: &HashMap<Obj, (usize, u32)>, e: &ObjEntry, by: Group) -> String {
    match by {
        Group::Type => type_key(w, e, false),
        Group::FullType => type_key(w, e, true),
        Group::Section => if e.obj.cst { "const_data".into() } else { "objects".into() },
        Group::Referrer => {
            let t = type_key(w, e, false);
            match refs.get(&e.obj) {
                _ if e.label == ConstLabel::MemData => format!("{t} (element data)"),
                Some(&(oi, pos)) => format!("{t} <- {}", slot_label(w, &objs[oi], pos)),
                None => format!("{t} <- (root)"),
            }
        }
    }
}

pub fn heap_histogram(w: &World, objs: &[ObjEntry], cst: &[ObjEntry], by: Group, sel: SectionSel) -> Vec<HistRow> {
    let refs = if by == Group::Referrer { first_referrers(w, objs.first().map_or(w.target, |e| e.obj.img), objs) } else { HashMap::new() };
    let it: Box<dyn Iterator<Item = &ObjEntry>> = match sel {
        SectionSel::All => Box::new(objs.iter().chain(cst)),
        SectionSel::Objects => Box::new(objs.iter()),
        SectionSel::Const => Box::new(cst.iter()),
    };
    histogram(it.map(|e| {
        let count = if e.label == ConstLabel::MemData { 0 } else { 1 };
        (group_key(w, objs, &refs, e, by), e.size as u64, count)
    }))
}

/// `Module.f(argtypes)` for a MethodInstance.
pub fn mi_label(w: &World, mi: Obj) -> String {
    let spec = w.field(mi, "specTypes").map(|s| show_sig(w, s)).unwrap_or_default();
    match w.field(mi, "def").and_then(|v| v.obj()) {
        Some(m) if w.kind(m) == Kind::Method => {
            let r = method_info(w, m);
            format!("{}.{}{}", r.module, r.name, spec)
        }
        Some(m) if w.kind(m) == Kind::Module => format!("<toplevel> {}", w.module_path(m)),
        _ => w.show(Val::Obj(mi), 4),
    }
}

/// Fill `parent`/`root` of code instances from a provenance sidecar.
pub fn annotate_provenance(w: &World, img: ImgId, cis: &mut [CiRow], p: &crate::provenance::Provenance) {
    use crate::provenance::PRef;
    let label = |r: &PRef| -> Option<String> {
        match r {
            PRef::None => None,
            PRef::Obj(off) => {
                let o = Obj { img, cst: false, off: *off };
                Some(if w.kind(o) == Kind::MethodInstance { mi_label(w, o) } else { w.show(Val::Obj(o), 4) })
            }
            PRef::Text(t) => Some(t.strip_prefix("MethodInstance for ").unwrap_or(t).to_string()),
        }
    };
    for c in cis.iter_mut() {
        if let Some((par, root)) = p.by_ci.get(&c.obj.off) {
            c.parent = label(par);
            c.root = label(root).or_else(|| Some("<self>".into()));
        }
    }
}
