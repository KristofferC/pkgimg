//! Generic object inspection: decoded fields, elements and referrers.

use crate::analysis::{ObjEntry, slot_label};
use crate::bytes::{rd_u32, rd_u64};
use crate::world::{ImgId, Kind, Obj, Val, World};

#[derive(Clone, Debug)]
pub enum FieldValue {
    Ptr(Val),
    Bits(String),
}

#[derive(Clone, Debug)]
pub struct FieldView {
    pub name: String,
    pub offset: u32,
    pub ty: String,
    pub value: FieldValue,
}

fn fmt_bits(ty: &str, b: &[u8]) -> String {
    let u = |n: usize| -> u64 {
        let mut x = [0u8; 8];
        x[..n.min(b.len())].copy_from_slice(&b[..n.min(b.len())]);
        u64::from_le_bytes(x)
    };
    match (ty, b.len()) {
        ("Bool", 1) => (b[0] != 0).to_string(),
        ("Int8", 1) => (b[0] as i8).to_string(),
        ("UInt8", 1) => format!("0x{:02x}", b[0]),
        ("Int16", 2) => (u(2) as i16).to_string(),
        ("UInt16", 2) => format!("0x{:04x}", u(2)),
        ("Int32", 4) => (u(4) as i32).to_string(),
        ("UInt32", 4) => format!("0x{:08x}", u(4)),
        ("Int64", 8) => (u(8) as i64).to_string(),
        ("UInt64", 8) if u(8) == u64::MAX => "typemax(UInt64)".into(),
        ("UInt64", 8) => u(8).to_string(),
        ("Float64", 8) => f64::from_bits(u(8)).to_string(),
        ("Float32", 4) => f32::from_bits(u(4) as u32).to_string(),
        _ if b.len() <= 8 => format!("0x{:0w$x}", u(b.len()), w = b.len() * 2),
        _ => {
            let hex: Vec<String> = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
            format!("{}{}", hex.join(" "), if b.len() > 32 { " …" } else { "" })
        }
    }
}

/// Decoded fields of `o` according to its type's layout.
pub fn fields(w: &World, o: Obj) -> Vec<FieldView> {
    let Some(ti) = w.type_info(o) else { return vec![] };
    let mut out = vec![];
    if ti.kind == Kind::Module {
        // jl_module_t is opaque to Julia; show the fields the serializer relocates.
        for (name, off) in [("name", 0), ("parent", 8), ("bindings", 16), ("bindingkeyset", 24), ("file", 32), ("usings_backedges", 48), ("scanned_methods", 56)] {
            out.push(FieldView { name: name.into(), offset: off, ty: String::new(), value: FieldValue::Ptr(w.ptr(o, off)) });
        }
        out.push(FieldView { name: "line".into(), offset: 40, ty: "Int32".into(), value: FieldValue::Bits((rd_u32(w.bytes(o, 40, 4), 0) as i32).to_string()) });
        return out;
    }
    let Some(l) = ti.layout.as_ref() else { return out };
    if matches!(ti.kind, Kind::SimpleVector | Kind::String) {
        return out;
    }
    for (i, f) in l.fields.iter().enumerate() {
        let name = ti.field_names.get(i).cloned().unwrap_or_else(|| i.to_string());
        let fty = ti.field_types.get(i).copied().unwrap_or(Val::Null);
        let tyname = match fty.obj() {
            Some(t) if w.kind(t) == Kind::DataType => w.datatype(t).map(|d| d.name.clone()).unwrap_or_default(),
            _ => String::new(),
        };
        let value = if f.isptr {
            FieldValue::Ptr(w.ptr(o, f.offset))
        } else {
            FieldValue::Bits(fmt_bits(&tyname, w.bytes(o, f.offset, f.size)))
        };
        out.push(FieldView { name, offset: f.offset, ty: w.show(fty, 3), value });
    }
    out
}

/// Elements of a SimpleVector, boxed Memory or boxed Array: `(total, first `max`)`.
pub fn elements(w: &World, o: Obj, max: usize) -> Option<(usize, Vec<Val>)> {
    let ti = w.type_info(o)?;
    let all = match ti.kind {
        Kind::SimpleVector => w.svec(o),
        Kind::GenericMemory if ti.layout.as_ref().is_some_and(|l| l.arrayelem_isboxed()) => w.memory_elems(o),
        Kind::Array => {
            let mem = w.ptr(o, 8).obj()?;
            let mti = w.type_info(mem)?;
            if !mti.layout.as_ref().is_some_and(|l| l.arrayelem_isboxed()) {
                return None;
            }
            w.array_elems(o)
        }
        _ => return None,
    };
    let n = all.len();
    Some((n, all.into_iter().take(max).collect()))
}

/// String contents, if `o` is a String.
pub fn string_value(w: &World, o: Obj) -> Option<String> {
    (w.kind(o) == Kind::String).then(|| w.string(o))
}

/// Objects of `img` holding a pointer to `target`: `(object index, slot label)`.
pub fn referrers(w: &World, img: ImgId, objs: &[ObjEntry], target: Obj) -> Vec<(usize, String)> {
    let heap = &w.img(img).heap;
    let mut out = vec![];
    for &p in &heap.relocs {
        if w.decode_at(img, p as usize) != Val::Obj(target) {
            continue;
        }
        let i = objs.partition_point(|e| e.obj.off <= p + 8).saturating_sub(1);
        if let Some(e) = objs.get(i) {
            out.push((i, slot_label(w, e, p)));
        }
        if out.len() >= 1000 {
            break;
        }
    }
    out
}

/// Hex dump of an object's bytes (starting at the type tag).
pub fn hexdump(w: &World, o: Obj, len: u32) -> String {
    let start = o.off.saturating_sub(8);
    let b = w.bytes(Obj { off: start, ..o }, 0, len.min(4096) + 8);
    let mut s = String::new();
    for (i, chunk) in b.chunks(16).enumerate() {
        let words: Vec<String> = chunk.chunks(8).map(|c| format!("{:016x}", rd_u64(c, 0))).collect();
        let ascii: String = chunk.iter().map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '.' }).collect();
        s.push_str(&format!("{:08x}  {:<34} {}\n", start as usize + 16 * i, words.join(" "), ascii));
    }
    s
}
