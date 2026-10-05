//! A set of loaded images (system image + package images) with cross-image pointer
//! resolution and type-layout driven object decoding.

use crate::bytes::{rd_u16, rd_u32, rd_u64};
use crate::header::ModuleId;
use crate::heap::{RefTag, split_reloc, DEPS_IDX_OFFSET};
use crate::image::Image;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub type ImgId = u16;

/// An object in some image: `off` is the address of its data (just past the type tag),
/// relative to the object section base, or to the start of the constant-data section.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Obj {
    pub img: ImgId,
    pub cst: bool,
    pub off: u32,
}

/// A decoded pointer slot.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Val {
    Null,
    Obj(Obj),
    Sym(ImgId, u32),
    Nothing,
    RootTask,
    Int64(i64),
    Int32(i32),
    UInt8(u8),
    /// `FunctionRef` payload (invoke API / builtin id).
    Func(u64),
    /// Reference into a dependency image that could not be found.
    Unresolved { dep: u32, off: u64 },
    Bad(u64),
}

impl Val {
    pub fn obj(self) -> Option<Obj> {
        if let Val::Obj(o) = self { Some(o) } else { None }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    DataType,
    TypeName,
    UnionAll,
    Union,
    TypeVar,
    SimpleVector,
    String,
    Module,
    GenericMemory,
    Array,
    Method,
    MethodInstance,
    CodeInstance,
    Binding,
    Other,
}

#[derive(Clone, Copy, Debug)]
pub struct FieldDesc {
    pub isptr: bool,
    pub size: u32,
    pub offset: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Layout {
    pub size: u32,
    pub nfields: u32,
    pub npointers: u32,
    pub first_ptr: i32,
    pub alignment: u16,
    pub flags: u16,
    pub fields: Vec<FieldDesc>,
    /// Pointer offsets in words.
    pub ptrs: Vec<u32>,
}

impl Layout {
    pub fn arrayelem_isboxed(&self) -> bool {
        self.flags & (1 << 3) != 0
    }
    pub fn arrayelem_isunion(&self) -> bool {
        self.flags & (1 << 4) != 0
    }
}

pub struct TypeInfo {
    pub obj: Obj,
    pub name: String,
    pub module: String,
    pub kind: Kind,
    pub mutable: bool,
    pub smalltag: u8,
    pub layout: Option<Layout>,
    pub field_names: Vec<String>,
    pub params: Vec<Val>,
}

impl TypeInfo {
    pub fn qualified(&self) -> String {
        if self.module.is_empty() { self.name.clone() } else { format!("{}.{}", self.module, self.name) }
    }
    /// Whether a mutable instance carries an object-id word before its tag.
    pub fn has_object_id(&self) -> bool {
        self.mutable
            && !matches!(self.kind, Kind::DataType | Kind::TypeName | Kind::String | Kind::SimpleVector | Kind::Module)
    }
    pub fn field_index(&self, name: &str) -> Option<usize> {
        self.field_names.iter().position(|n| n == name)
    }
}

// C struct offsets needed to bootstrap generic decoding (julia.h, master / 1.13).
const DT_NAME: u32 = 0;
const DT_PARAMETERS: u32 = 16;
const DT_LAYOUT: u32 = 40;
const DT_FLAGS: u32 = 52;
const TN_NAME: u32 = 0;
const TN_MODULE: u32 = 8;
const TN_NAMES: u32 = 24;
const MOD_NAME: u32 = 0;
const MOD_PARENT: u32 = 8;
const MOD_BUILD_ID: u32 = 320;
const MOD_UUID: u32 = 336;
const NBOX_C: u64 = 1024;

pub struct Options {
    pub sysimage: Option<PathBuf>,
    /// Depots to search for dependency cache files (`<depot>/compiled/vX.Y/<name>/*.ji`).
    pub depots: Vec<PathBuf>,
    pub verbose: bool,
}

pub struct World {
    pub images: Vec<Image>,
    /// Per image: depsidx -> image (0 = system image).
    deps: Vec<Vec<Option<ImgId>>>,
    pub sysimg: Option<ImgId>,
    pub target: ImgId,
    pub missing: Vec<ModuleId>,
    types: RefCell<HashMap<Obj, Rc<TypeInfo>>>,
    modpaths: RefCell<HashMap<Obj, Rc<str>>>,
    smalltags: Vec<Option<Obj>>,
    datatype_type: Option<Obj>,
    /// DataTypes defined in Core, by name (from the system image).
    pub core_types: HashMap<String, Obj>,
}

fn uuid_of(buf: &[u8], off: usize) -> String {
    // jl_uuid_t { hi, lo }
    let hi = rd_u64(buf, off) as u128;
    let lo = rd_u64(buf, off + 8) as u128;
    let x = (hi << 64) | lo;
    if x == 0 {
        return String::new();
    }
    let h = format!("{x:032x}");
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn default_depots() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(dp) = std::env::var("JULIA_DEPOT_PATH") {
        v.extend(dp.split(':').filter(|s| !s.is_empty()).map(PathBuf::from));
    }
    if let Some(h) = std::env::var_os("HOME") {
        v.push(Path::new(&h).join(".julia"));
    }
    v
}

impl World {
    pub fn open(target: &Path, mut opts: Options) -> Result<World> {
        let target_img = Image::open(target)?;
        if opts.depots.is_empty() {
            opts.depots = default_depots();
        }
        let is_sys = target_img.header.pkg.is_none();
        let mut w = World {
            images: vec![target_img],
            deps: vec![],
            sysimg: is_sys.then_some(0),
            target: 0,
            missing: vec![],
            types: RefCell::default(),
            modpaths: RefCell::default(),
            smalltags: vec![None; 64],
            datatype_type: None,
            core_types: HashMap::new(),
        };
        if !is_sys {
            let cands = match &opts.sysimage {
                Some(p) => vec![p.clone()],
                None => sysimage_candidates(&w.images[0]),
            };
            for p in cands {
                match w.try_sysimage(&p, opts.sysimage.is_some()) {
                    Ok(true) => {
                        if opts.verbose {
                            eprintln!("using system image {}", p.display());
                        }
                        break;
                    }
                    Ok(false) => {
                        if opts.verbose {
                            eprintln!("skipping {}: Core build id does not match", p.display());
                        }
                    }
                    Err(e) => eprintln!("warning: {}: {e:#}", p.display()),
                }
            }
            if w.sysimg.is_none() {
                eprintln!("warning: no matching system image found (use --sysimage); external references stay unresolved");
            }
        } else {
            w.index_sysimage();
        }
        // stdlib caches live next to the system image: <prefix>/share/julia/compiled
        if let Some(s) = w.sysimg {
            let p = &w.images[s as usize].path;
            if let Some(prefix) = p.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
                opts.depots.push(prefix.join("share").join("julia"));
            }
        }
        w.deps = vec![vec![]; w.images.len()];
        w.resolve_deps(&opts)?;
        Ok(w)
    }

    /// Load `p` as the system image if its `Core` matches the target's (or `force`).
    fn try_sysimage(&mut self, p: &Path, force: bool) -> Result<bool> {
        let im = Image::open(p)?;
        if im.header.pkg.is_some() {
            anyhow::bail!("not a system image");
        }
        self.images.push(im);
        let id = (self.images.len() - 1) as ImgId;
        self.sysimg = Some(id);
        self.index_sysimage();
        let want = self.images[0].header.pkg.as_ref().and_then(|p| p.required_modules.iter().find(|m| m.name == "Core")).map(|m| m.build_id_lo);
        let have = self.toplevel_modules(id).into_iter().find(|m| m.0 == "Core").map(|m| m.3);
        if force || want.is_none() || want == have {
            return Ok(true);
        }
        self.images.pop();
        self.sysimg = None;
        self.types.borrow_mut().clear();
        self.modpaths.borrow_mut().clear();
        Ok(false)
    }

    pub fn img(&self, id: ImgId) -> &Image {
        &self.images[id as usize]
    }

    pub fn target(&self) -> &Image {
        self.img(self.target)
    }

    /// Find `DataType` (the object whose type is itself), the small-tag table and
    /// top-level modules of the system image.
    fn index_sysimage(&mut self) {
        let Some(si) = self.sysimg else { return };
        let heap = &self.images[si as usize].heap;
        let sys = heap.sys();
        let mut dt = None;
        for &p in &heap.gctags {
            let (t, o) = split_reloc(rd_u64(sys, p as usize));
            if t == RefTag::Data && o == p as u64 + 8 {
                dt = Some(Obj { img: si, cst: false, off: o as u32 });
                break;
            }
        }
        self.datatype_type = dt;
        let Some(dt) = dt else { return };
        let mut tags = vec![None; 64];
        let mut dts = vec![];
        for &p in &heap.gctags {
            let (t, o) = split_reloc(rd_u64(sys, p as usize));
            if t == RefTag::Data && o == dt.off as u64 {
                let obj = p as usize + 8;
                dts.push(Obj { img: si, cst: false, off: obj as u32 });
                let st = (rd_u16(sys, obj + DT_FLAGS as usize) >> 10) as usize & 63;
                if st != 0 && tags[st].is_none() {
                    tags[st] = Some(Obj { img: si, cst: false, off: obj as u32 });
                }
            }
        }
        self.smalltags = tags;
        let mut core = HashMap::new();
        for d in dts {
            let Some(tn) = self.ptr(d, DT_NAME).obj() else { continue };
            let Some(m) = self.ptr(tn, TN_MODULE).obj() else { continue };
            if self.sym_name(self.ptr(m, MOD_NAME)).as_deref() != Some("Core") {
                continue;
            }
            if let Some(n) = self.sym_name(self.ptr(tn, TN_NAME)) {
                // Keep the first (the TypeName's primary DataType precedes instantiations).
                core.entry(n).or_insert(d);
            }
        }
        self.core_types = core;
    }

    /// Top-level modules defined in an image: (name, uuid, build_id.hi, build_id.lo).
    fn toplevel_modules(&self, img: ImgId) -> Vec<(String, String, u64, u64)> {
        let Some(&modty) = self.core_types.get("Module") else {
            return vec![];
        };
        let heap = &self.img(img).heap;
        let sys = heap.sys();
        let mut out = vec![];
        for &p in &heap.gctags {
            let ty = self.decode_at(img, p as usize);
            if ty != Val::Obj(modty) {
                continue;
            }
            let o = p as usize + 8;
            let me = Obj { img, cst: false, off: o as u32 };
            if !self.is_root_module(me) {
                continue;
            }
            let name = self.sym_name(self.decode_at(img, o + MOD_NAME as usize)).unwrap_or_default();
            out.push((
                name,
                uuid_of(sys, o + MOD_UUID as usize),
                rd_u64(sys, o + MOD_BUILD_ID as usize),
                rd_u64(sys, o + MOD_BUILD_ID as usize + 8),
            ));
        }
        out
    }

    fn resolve_deps(&mut self, opts: &Options) -> Result<()> {
        let mut by_id: HashMap<(String, u64), ImgId> = HashMap::new();
        if let Some(si) = self.sysimg {
            for (name, uuid, _hi, lo) in self.toplevel_modules(si) {
                by_id.insert((format!("{name}/{uuid}"), lo), si);
            }
        }
        let mut cands: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let ver = self.images[0].header.base.major_minor();
        let mut i = 0;
        while i < self.images.len() {
            let Some(pkg) = self.images[i].header.pkg.clone() else {
                i += 1;
                continue;
            };
            for m in &pkg.worklist {
                by_id.entry((format!("{}/{}", m.name, m.uuid), m.build_id_lo)).or_insert(i as ImgId);
            }
            let mut map = vec![self.sysimg];
            for m in &pkg.required_modules {
                let key = (format!("{}/{}", m.name, m.uuid), m.build_id_lo);
                let id = match by_id.get(&key) {
                    Some(&id) => Some(id),
                    None => {
                        let found = find_cache_file(m, ver, &opts.depots, &mut cands);
                        match found {
                            Some(p) => match Image::open(&p) {
                                Ok(im) => {
                                    if opts.verbose {
                                        eprintln!("loaded dependency {} from {}", m.name, p.display());
                                    }
                                    self.images.push(im);
                                    self.deps.push(vec![]);
                                    let id = (self.images.len() - 1) as ImgId;
                                    by_id.insert(key, id);
                                    Some(id)
                                }
                                Err(e) => {
                                    eprintln!("warning: {}: {e:#}", p.display());
                                    None
                                }
                            },
                            None => {
                                if !self.missing.iter().any(|x| x.name == m.name && x.uuid == m.uuid) {
                                    self.missing.push(m.clone());
                                }
                                None
                            }
                        }
                    }
                };
                map.push(id);
            }
            self.deps[i] = map;
            i += 1;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- decoding

    /// Decode the pointer-sized slot at position `pos` of `img`'s object section.
    pub fn decode_at(&self, img: ImgId, pos: usize) -> Val {
        let heap = &self.img(img).heap;
        self.decode_word(img, rd_u64(heap.sys(), pos), Some(pos as u32))
    }

    pub fn decode_word(&self, img: ImgId, w: u64, pos: Option<u32>) -> Val {
        if w == 0 {
            return Val::Null;
        }
        let (tag, off) = split_reloc(w);
        match tag {
            RefTag::Data => Val::Obj(Obj { img, cst: false, off: off as u32 }),
            RefTag::ConstData => Val::Obj(Obj { img, cst: true, off: (off * 8) as u32 }),
            RefTag::Symbol => Val::Sym(img, off as u32),
            RefTag::Tag => match off {
                0 => Val::RootTask,
                1 => Val::Nothing,
                o if o < 2 + NBOX_C => Val::Int64(o as i64 - 2 - (NBOX_C / 2) as i64),
                o if o < 2 + 2 * NBOX_C => Val::Int32((o - 2 - NBOX_C) as i32 - (NBOX_C / 2) as i32),
                o if o < 2 + 2 * NBOX_C + 256 => Val::UInt8((o - 2 - 2 * NBOX_C) as u8),
                _ => Val::Bad(w),
            },
            RefTag::Function => Val::Func(off),
            RefTag::SysimageLinkage => {
                let dep = (off >> DEPS_IDX_OFFSET) as u32;
                let o = (off & ((1 << DEPS_IDX_OFFSET) - 1)) * 8;
                self.link(img, dep, o)
            }
            RefTag::ExternalLinkage => {
                let dep = pos.and_then(|p| self.img(img).heap.ext_link.get(&p).copied());
                match dep {
                    Some(d) => self.link(img, d, off * 8),
                    None => Val::Bad(w),
                }
            }
            RefTag::Invalid => Val::Bad(w),
        }
    }

    fn link(&self, img: ImgId, dep: u32, off: u64) -> Val {
        let target = if self.img(img).header.pkg.is_none() {
            None
        } else {
            self.deps.get(img as usize).and_then(|d| d.get(dep as usize).copied().flatten())
        };
        match target {
            Some(t) => Val::Obj(self.obj_at_image_offset(t, off)),
            None => Val::Unresolved { dep, off },
        }
    }

    /// Objects are addressed relative to the image base; offsets past the object section
    /// land in the constant-data section, which follows it in the file.
    pub fn obj_at_image_offset(&self, img: ImgId, off: u64) -> Obj {
        let h = &self.img(img).heap;
        if off >= h.sys_len as u64 {
            let c = off - (h.const_base - h.sys_base) as u64;
            Obj { img, cst: true, off: c as u32 }
        } else {
            Obj { img, cst: false, off: off as u32 }
        }
    }

    pub fn word(&self, o: Obj, at: u32) -> u64 {
        let heap = &self.img(o.img).heap;
        let buf = if o.cst { heap.cdata() } else { heap.sys() };
        rd_u64(buf, (o.off + at) as usize)
    }

    /// Pointer field at byte offset `at` of object `o`.
    pub fn ptr(&self, o: Obj, at: u32) -> Val {
        if o.cst {
            // Constant data holds no pointers to relocate except via smalltags.
            return Val::Null;
        }
        self.decode_at(o.img, (o.off + at) as usize)
    }

    pub fn bytes(&self, o: Obj, at: u32, len: u32) -> &[u8] {
        let heap = &self.img(o.img).heap;
        let buf = if o.cst { heap.cdata() } else { heap.sys() };
        let s = (o.off + at) as usize;
        buf.get(s..s + len as usize).unwrap_or(&[])
    }

    pub fn sym_name(&self, v: Val) -> Option<String> {
        match v {
            Val::Sym(img, i) => self.img(img).heap.symbols.get(i as usize).map(|s| s.to_string()),
            _ => None,
        }
    }

    /// The type of object `o`.
    pub fn type_of(&self, o: Obj) -> Option<Obj> {
        if o.cst {
            let w = self.word(Obj { off: o.off.checked_sub(8)?, ..o }, 0);
            let st = ((w >> 4) & 63) as usize;
            return self.smalltags.get(st).copied().flatten();
        }
        self.decode_at(o.img, o.off.checked_sub(8)? as usize).obj()
    }

    pub fn type_info(&self, o: Obj) -> Option<Rc<TypeInfo>> {
        let t = self.type_of(o)?;
        self.datatype(t)
    }

    /// Information about a DataType object.
    pub fn datatype(&self, t: Obj) -> Option<Rc<TypeInfo>> {
        if let Some(ti) = self.types.borrow().get(&t) {
            return Some(ti.clone());
        }
        let ti = Rc::new(self.build_typeinfo(t)?);
        self.types.borrow_mut().insert(t, ti.clone());
        Some(ti)
    }

    fn build_typeinfo(&self, t: Obj) -> Option<TypeInfo> {
        let tn = self.ptr(t, DT_NAME).obj()?;
        let name = self.sym_name(self.ptr(tn, TN_NAME)).unwrap_or_else(|| "?".into());
        let module = self.ptr(tn, TN_MODULE).obj().map(|m| self.module_path(m).to_string()).unwrap_or_default();
        let layout = self.ptr(t, DT_LAYOUT).obj().and_then(|l| self.read_layout(l));
        let mut field_names = vec![];
        if let Some(names) = self.ptr(tn, TN_NAMES).obj() {
            for v in self.svec(names) {
                field_names.push(match v {
                    Val::Sym(..) => self.sym_name(v).unwrap_or_default(),
                    Val::Int64(i) => i.to_string(),
                    _ => String::new(),
                });
            }
        }
        let flags = rd_u16(self.bytes(t, DT_FLAGS, 2), 0);
        let params = self.ptr(t, DT_PARAMETERS).obj().map(|p| self.svec(p)).unwrap_or_default();
        let kind = if module == "Core" {
            match name.as_str() {
                "DataType" => Kind::DataType,
                "TypeName" => Kind::TypeName,
                "UnionAll" => Kind::UnionAll,
                "Union" => Kind::Union,
                "TypeVar" => Kind::TypeVar,
                "SimpleVector" => Kind::SimpleVector,
                "String" => Kind::String,
                "Module" => Kind::Module,
                "GenericMemory" => Kind::GenericMemory,
                "Array" => Kind::Array,
                "Method" => Kind::Method,
                "MethodInstance" => Kind::MethodInstance,
                "CodeInstance" => Kind::CodeInstance,
                "Binding" => Kind::Binding,
                _ => Kind::Other,
            }
        } else {
            Kind::Other
        };
        // TypeName flags byte: abstract:1, mutabl:1, ... (see jl_typename_t)
        let mutable = self.typename_mutable(tn, kind);
        Some(TypeInfo {
            obj: t, name, module, kind, mutable,
            smalltag: ((flags >> 10) & 63) as u8,
            layout, field_names, params,
        })
    }

    fn typename_mutable(&self, tn: Obj, kind: Kind) -> bool {
        // Use TypeName's own layout to find its `flags` field.
        if kind == Kind::DataType || kind == Kind::TypeName || kind == Kind::Module {
            return true;
        }
        let Some(tnt) = self.type_of(tn) else { return false };
        let Some(tnti) = self.datatype(tnt) else { return false };
        let (Some(idx), Some(l)) = (tnti.field_index("flags"), tnti.layout.as_ref()) else { return false };
        let Some(fd) = l.fields.get(idx) else { return false };
        self.bytes(tn, fd.offset, 1).first().is_some_and(|b| b & 2 != 0)
    }

    fn read_layout(&self, l: Obj) -> Option<Layout> {
        let h = self.bytes(l, 0, 20);
        if h.len() < 20 {
            return None;
        }
        let size = rd_u32(h, 0);
        let nfields = rd_u32(h, 4);
        let npointers = rd_u32(h, 8);
        let first_ptr = rd_u32(h, 12) as i32;
        let alignment = rd_u16(h, 16);
        let flags = rd_u16(h, 18);
        let fdt = (flags >> 1) & 3;
        let mut fields = Vec::with_capacity(nfields as usize);
        let (fsz, psz) = match fdt {
            0 => (2u32, 1u32),
            1 => (4, 2),
            2 => (8, 4),
            _ => return Some(Layout { size, nfields, npointers, first_ptr, alignment, flags, ..Default::default() }),
        };
        let fb = self.bytes(l, 20, nfields * fsz);
        for i in 0..nfields as usize {
            let (isptr, size, offset) = match fdt {
                0 => (fb[2 * i] & 1 != 0, (fb[2 * i] >> 1) as u32, fb[2 * i + 1] as u32),
                1 => {
                    let a = rd_u16(fb, 4 * i);
                    (a & 1 != 0, (a >> 1) as u32, rd_u16(fb, 4 * i + 2) as u32)
                }
                _ => {
                    let a = rd_u32(fb, 8 * i);
                    (a & 1 != 0, a >> 1, rd_u32(fb, 8 * i + 4))
                }
            };
            fields.push(FieldDesc { isptr, size, offset });
        }
        let mut ptrs = vec![];
        if first_ptr != -1 {
            let pb = self.bytes(l, 20 + nfields * fsz, npointers * psz);
            for i in 0..npointers as usize {
                ptrs.push(match psz {
                    1 => pb.get(i).copied().unwrap_or(0) as u32,
                    2 => rd_u16(pb, 2 * i) as u32,
                    _ => rd_u32(pb, 4 * i),
                });
            }
        }
        Some(Layout { size, nfields, npointers, first_ptr, alignment, flags, fields, ptrs })
    }

    /// Elements of a SimpleVector.
    pub fn svec(&self, o: Obj) -> Vec<Val> {
        let n = self.word(o, 0).min(1 << 20) as u32;
        (0..n).map(|i| self.ptr(o, 8 + 8 * i)).collect()
    }

    /// Elements of a boxed `GenericMemory`.
    pub fn memory_elems(&self, mem: Obj) -> Vec<Val> {
        let n = self.word(mem, 0).min(1 << 24) as u32;
        match self.ptr(mem, 8) {
            Val::Obj(d) if !d.cst && d.img == mem.img => (0..n).map(|i| self.ptr(d, 8 * i)).collect(),
            _ => vec![],
        }
    }

    /// Elements of a boxed `Vector` (`Array` with pointer elements).
    pub fn array_elems(&self, a: Obj) -> Vec<Val> {
        let Some(mem) = self.ptr(a, 8).obj() else { return vec![] };
        let off = (self.word(a, 0) / 8) as usize;
        let len = self.word(a, 16) as usize;
        self.memory_elems(mem).into_iter().skip(off).take(len).collect()
    }

    pub fn string(&self, o: Obj) -> String {
        let n = self.word(o, 0).min(1 << 30) as u32;
        String::from_utf8_lossy(self.bytes(o, 8, n)).into_owned()
    }

    pub fn string_len(&self, o: Obj) -> u64 {
        self.word(o, 0)
    }

    /// Matches `is_serialization_root_module`: parent is itself, `Main` or `Base`.
    pub fn is_root_module(&self, m: Obj) -> bool {
        match self.ptr(m, MOD_PARENT).obj() {
            Some(p) if p == m => true,
            Some(p) => {
                let toplevel = self.ptr(p, MOD_PARENT).obj() == Some(p);
                toplevel && matches!(self.sym_name(self.ptr(p, MOD_NAME)).as_deref(), Some("Main" | "Base"))
                    && self.sym_name(self.ptr(m, MOD_NAME)).as_deref() != Some("Main")
            }
            None => false,
        }
    }

    /// `Parent.Child` path of a module object.
    pub fn module_path(&self, m: Obj) -> Rc<str> {
        if let Some(p) = self.modpaths.borrow().get(&m) {
            return p.clone();
        }
        let mut parts = vec![];
        let mut cur = m;
        for _ in 0..32 {
            parts.push(self.sym_name(self.ptr(cur, MOD_NAME)).unwrap_or_else(|| "?".into()));
            if self.is_root_module(cur) {
                break;
            }
            match self.ptr(cur, MOD_PARENT).obj() {
                Some(p) if p != cur => cur = p,
                _ => break,
            }
        }
        parts.reverse();
        let s: Rc<str> = parts.join(".").into();
        self.modpaths.borrow_mut().insert(m, s.clone());
        s
    }

    /// Field `name` of `o`, decoded via the type's layout.
    pub fn field(&self, o: Obj, name: &str) -> Option<Val> {
        let ti = self.type_info(o)?;
        let i = ti.field_index(name)?;
        let fd = ti.layout.as_ref()?.fields.get(i)?;
        if fd.isptr {
            Some(self.ptr(o, fd.offset))
        } else {
            None
        }
    }

    /// Raw bytes of a non-pointer field.
    pub fn field_bytes(&self, o: Obj, name: &str) -> Option<&[u8]> {
        let ti = self.type_info(o)?;
        let i = ti.field_index(name)?;
        let fd = *ti.layout.as_ref()?.fields.get(i)?;
        Some(self.bytes(o, fd.offset, fd.size))
    }

    pub fn field_u64(&self, o: Obj, name: &str) -> Option<u64> {
        let b = self.field_bytes(o, name)?;
        let mut x = [0u8; 8];
        let n = b.len().min(8);
        x[..n].copy_from_slice(&b[..n]);
        Some(u64::from_le_bytes(x))
    }

    pub fn kind(&self, o: Obj) -> Kind {
        self.type_info(o).map_or(Kind::Other, |t| t.kind)
    }

    // ---------------------------------------------------------------- display

    /// Render a type (or a value appearing as a type parameter).
    pub fn show(&self, v: Val, depth: u32) -> String {
        let mut s = String::new();
        self.show_into(&mut s, v, depth);
        s
    }

    fn show_into(&self, s: &mut String, v: Val, depth: u32) {
        use std::fmt::Write;
        match v {
            Val::Null => s.push_str("#undef"),
            Val::Nothing => s.push_str("nothing"),
            Val::RootTask => s.push_str("<roottask>"),
            Val::Int64(i) => write!(s, "{i}").unwrap(),
            Val::Int32(i) => write!(s, "Int32({i})").unwrap(),
            Val::UInt8(i) => write!(s, "0x{i:02x}").unwrap(),
            Val::Sym(..) => write!(s, ":{}", self.sym_name(v).unwrap_or_default()).unwrap(),
            Val::Func(f) => write!(s, "<fptr {f:#x}>").unwrap(),
            Val::Unresolved { dep, off } => write!(s, "<dep{dep}+{off:#x}>").unwrap(),
            Val::Bad(w) => write!(s, "<bad {w:#x}>").unwrap(),
            Val::Obj(o) => {
                let Some(ti) = self.type_info(o) else {
                    s.push('?');
                    return;
                };
                if depth == 0 {
                    s.push('…');
                    return;
                }
                match ti.kind {
                    Kind::DataType => {
                        let Some(dt) = self.datatype(o) else { return s.push('?') };
                        if dt.name == "Tuple" && dt.module == "Core" {
                            s.push_str("Tuple");
                        } else {
                            s.push_str(&dt.name);
                        }
                        if !dt.params.is_empty() {
                            s.push('{');
                            for (i, p) in dt.params.iter().enumerate() {
                                if i > 0 {
                                    s.push_str(", ");
                                }
                                if i >= 8 {
                                    s.push('…');
                                    break;
                                }
                                self.show_into(s, *p, depth - 1);
                            }
                            s.push('}');
                        }
                    }
                    Kind::UnionAll => {
                        let mut body = o;
                        let mut vars = vec![];
                        while self.kind(body) == Kind::UnionAll && vars.len() < 16 {
                            if let Some(tv) = self.field(body, "var").and_then(|v| v.obj()) {
                                vars.push(self.field(tv, "name").and_then(|n| self.sym_name(n)).unwrap_or_default());
                            }
                            match self.field(body, "body").and_then(|b| b.obj()) {
                                Some(b) => body = b,
                                None => break,
                            }
                        }
                        self.show_into(s, Val::Obj(body), depth - 1);
                        write!(s, " where {}", vars.join(", ")).unwrap();
                    }
                    Kind::Union => {
                        s.push_str("Union{");
                        let mut first = true;
                        let mut cur = Some(o);
                        let mut n = 0;
                        while let Some(u) = cur {
                            n += 1;
                            if n > 16 {
                                break;
                            }
                            let a = self.field(u, "a").unwrap_or(Val::Null);
                            let b = self.field(u, "b").unwrap_or(Val::Null);
                            if !first {
                                s.push_str(", ");
                            }
                            first = false;
                            self.show_into(s, a, depth - 1);
                            match b.obj() {
                                Some(bo) if self.kind(bo) == Kind::Union => cur = Some(bo),
                                _ => {
                                    s.push_str(", ");
                                    self.show_into(s, b, depth - 1);
                                    cur = None;
                                }
                            }
                        }
                        s.push('}');
                    }
                    Kind::TypeVar => {
                        s.push_str(&self.field(o, "name").and_then(|n| self.sym_name(n)).unwrap_or_default());
                    }
                    Kind::String => {
                        let st = self.string(o);
                        write!(s, "{:?}", st.chars().take(40).collect::<String>()).unwrap();
                    }
                    Kind::Module => s.push_str(&self.module_path(o)),
                    _ if ti.module == "Core" && (ti.name == "TypeEq" || ti.name == "TypeEgal") => {
                        s.push_str(if ti.name == "TypeEq" { "Type{" } else { "TypeEgal{" });
                        self.show_into(s, self.ptr(o, 0), depth - 1);
                        s.push('}');
                    }
                    _ => {
                        // Bits values of common primitive types
                        let lay = ti.layout.as_ref();
                        if ti.module == "Core" && lay.is_some_and(|l| l.nfields == 0 && l.size <= 8) {
                            let w = self.word(o, 0);
                            match ti.name.as_str() {
                                "Int64" => return write!(s, "{}", w as i64).unwrap(),
                                "Bool" => return write!(s, "{}", w & 1 != 0).unwrap(),
                                "Char" => {
                                    let b = (w as u32).to_be_bytes();
                                    let n = b.iter().rposition(|&x| x != 0).map_or(1, |i| i + 1);
                                    return write!(s, "{:?}", String::from_utf8_lossy(&b[..n]).chars().next().unwrap_or('?')).unwrap();
                                }
                                _ => {}
                            }
                        }
                        if ti.layout.as_ref().is_some_and(|l| l.size == 0) && ti.field_names.is_empty() {
                            // singleton instance
                            write!(s, "{}()", ti.name).unwrap();
                        } else {
                            write!(s, "<{}>", ti.name).unwrap();
                        }
                    }
                }
            }
        }
    }
}

/// Locate a dependency's cache file in the depots by uuid and build id.
fn find_cache_file(
    m: &ModuleId,
    ver: Option<(u32, u32)>,
    depots: &[PathBuf],
    cache: &mut HashMap<String, Vec<PathBuf>>,
) -> Option<PathBuf> {
    let (maj, min) = ver?;
    let cands = cache.entry(m.name.clone()).or_insert_with(|| {
        let mut v = vec![];
        for d in depots {
            let dir = d.join("compiled").join(format!("v{maj}.{min}")).join(&m.name);
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.extension().is_some_and(|x| x == "ji") {
                        v.push(p);
                    }
                }
            }
        }
        v
    });
    for p in cands.iter() {
        // Only the header is needed; read a prefix of the file.
        let Ok(f) = std::fs::File::open(p) else { continue };
        let mut buf = vec![0u8; 1 << 16];
        use std::io::Read;
        let n = (&f).take(1 << 16).read(&mut buf).unwrap_or(0);
        buf.truncate(n);
        let Ok((base, pos)) = crate::header::parse_base(&buf) else { continue };
        let mut c = crate::bytes::Cursor::new(&buf, pos + 3);
        // worklist entries: name, uuid, build_id.lo
        let mut ok = false;
        while let Ok(n) = c.i32() {
            if n == 0 {
                break;
            }
            let Ok(name) = c.lstr(n as usize) else { break };
            let (Ok(_), Ok(_), Ok(lo)) = (c.u64(), c.u64(), c.u64()) else { break };
            if name == m.name && lo == m.build_id_lo && (m.build_id_hi == 0 || m.build_id_hi == base.checksum as u64) {
                ok = true;
            }
        }
        if ok {
            return Some(p.clone());
        }
    }
    None
}

/// Candidate system images for a package image, most likely first.
fn sysimage_candidates(img: &Image) -> Vec<PathBuf> {
    let so = format!("sys.{}", crate::image::DLEXT);
    let mut prefixes: Vec<PathBuf> = vec![];
    if let Ok(p) = std::env::var("JULIA_SYSIMAGE") {
        return vec![PathBuf::from(p)];
    }
    // stdlib caches: <prefix>/share/julia/compiled/vX.Y/<Name>/<file>.ji
    if let Some(prefix) = img.path.ancestors().nth(6) {
        prefixes.push(prefix.to_path_buf());
    }
    if let Ok(path) = std::env::var("PATH") {
        for d in path.split(':') {
            if let Ok(real) = std::fs::canonicalize(Path::new(d).join("julia"))
                && let Some(prefix) = real.parent().and_then(|p| p.parent())
            {
                prefixes.push(prefix.to_path_buf());
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        prefixes.push(cwd.join("usr"));
    }
    // juliaup installations
    if let Some(h) = std::env::var_os("HOME")
        && let Ok(rd) = std::fs::read_dir(Path::new(&h).join(".julia").join("juliaup"))
    {
        prefixes.extend(rd.flatten().map(|e| e.path()));
    }
    let want = &img.header.base.julia_version;
    let mut out = vec![];
    for prefix in prefixes {
        let c = prefix.join("lib").join("julia").join(&so);
        if out.contains(&c) || !c.exists() {
            continue;
        }
        // Cheap pre-filter on the version string in the embedded header.
        if let Ok(f) = std::fs::File::open(&c)
            && let Ok(m) = unsafe { memmap2::Mmap::map(&f) }
            && let Ok(Some((off, len))) = crate::native::embedded_image(&m)
            && let Ok((h, _)) = crate::header::parse_base(&m[off..off + len.min(4096)])
            && &h.julia_version == want
        {
            out.push(c);
        }
    }
    out
}
