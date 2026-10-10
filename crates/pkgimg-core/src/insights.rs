//! Heuristics that point at unusual, likely costly, parts of an image.

use crate::analysis::{CiRow, ConstLabel, MethodRow, ObjEntry};
use crate::world::{Obj, World};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Notable,
    High,
}

#[derive(Clone, Debug, Serialize)]
pub struct Insight {
    /// Stable identifier, e.g. `many-methods`.
    pub kind: &'static str,
    pub severity: Severity,
    pub title: String,
    /// One line with the key numbers.
    pub summary: String,
    /// Why it matters and what usually helps.
    pub detail: &'static str,
    pub items: Vec<Item>,
    /// Number of items before truncation.
    pub total_items: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Item {
    pub label: String,
    pub value: String,
    /// Size relative to the largest item (0..1), for bars.
    pub weight: f32,
    pub link: Link,
}

/// What an item refers to; the GUI navigates there.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Link {
    /// Methods of a function (`MethodRow::func`).
    Function { func: String },
    /// Methods defined at a source line.
    Location { file: String, line: i64 },
    /// Code instances of a method.
    Specializations { #[serde(skip)] method: Obj, offset: u32 },
    /// One object of the target image.
    Object { #[serde(skip)] obj: Obj, offset: u32, #[serde(rename = "const")] cst: bool },
}

impl Link {
    fn object(obj: Obj) -> Link {
        Link::Object { obj, offset: obj.off, cst: obj.cst }
    }
}

const MAX_ITEMS: usize = 12;

fn plural(n: usize, s: &str) -> String {
    format!("{n} {s}{}", if n == 1 { "" } else { "s" })
}

fn human(b: u64) -> String {
    match b {
        b if b >= 10 << 20 => format!("{:.1} MiB", b as f64 / (1 << 20) as f64),
        b if b >= 10 << 10 => format!("{:.1} KiB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

/// Keep the largest `MAX_ITEMS` of `rows` (sorted by `key` descending) as items.
fn top<T>(mut rows: Vec<T>, key: impl Fn(&T) -> f64, item: impl Fn(&T, f32) -> Item) -> (Vec<Item>, usize) {
    rows.sort_by(|a, b| key(b).total_cmp(&key(a)));
    let max = rows.first().map_or(1.0, &key).max(f64::MIN_POSITIVE);
    let n = rows.len();
    (rows.iter().take(MAX_ITEMS).map(|r| item(r, (key(r) / max) as f32)).collect(), n)
}

/// Methods that add to one function. ReverseDiff's ~2000 `materialize` methods are the
/// motivating case (JuliaDiff/ReverseDiff.jl#226).
fn many_methods(methods: &[MethodRow]) -> Option<Insight> {
    let mut by: HashMap<&str, (usize, bool)> = HashMap::new();
    // A keyword method duplicates the positional method it forwards to.
    for m in methods.iter().filter(|m| !m.external && !m.kwcall && !m.func.is_empty() && !m.func.contains('#')) {
        let e = by.entry(&m.func).or_default();
        e.0 += 1;
        e.1 |= m.func_external;
    }
    let rows: Vec<_> = by.into_iter().filter(|r| r.1.0 >= 50).collect();
    let (&(f, (n, ext)), total) = (rows.iter().max_by_key(|r| (r.1.0, r.0))?, methods.len());
    let in_rows: usize = rows.iter().map(|r| r.1.0).sum();
    let severity = if n >= 500 || (ext && n >= 250) { Severity::High } else { Severity::Notable };
    let (items, total_items) = top(rows, |r| r.1.0 as f64, |r, w| Item {
        label: r.0.to_string(),
        value: format!("{}{}", plural(r.1.0, "method"), if r.1.1 { " · external function" } else { "" }),
        weight: w,
        link: Link::Function { func: r.0.to_string() },
    });
    Some(Insight {
        kind: "many-methods",
        severity,
        title: "Functions with very many methods".into(),
        summary: format!(
            "{f} has {} defined here{}; functions with ≥50 methods ({}) hold {:.0}% of all {total} methods",
            plural(n, "method"), if ext { " (function owned by another module)" } else { "" },
            total_items, 100.0 * in_rows as f64 / total.max(1) as f64,
        ),
        detail: "Every method is deserialized and inserted into the method table when the package loads, \
                 so hundreds of methods on one function slow down loading and widen dispatch and invalidation. \
                 They usually come from @eval loops over types; a few generic methods (or a trait) can often replace them.",
        items,
        total_items,
    })
}

/// Many methods defined at one source line: code generation loops.
fn generated_methods(methods: &[MethodRow]) -> Option<Insight> {
    let mut by: HashMap<(&str, i64), (usize, Vec<&str>)> = HashMap::new();
    // Builtins have no source location.
    for m in methods.iter().filter(|m| !m.external && !m.file.is_empty() && m.line > 0) {
        let e = by.entry((&m.file, m.line)).or_default();
        e.0 += 1;
        if e.1.len() < 4 && !e.1.contains(&m.name.as_str()) {
            e.1.push(&m.name);
        }
    }
    let rows: Vec<_> = by.into_iter().filter(|r| r.1.0 >= 50).collect();
    let n = rows.iter().map(|r| r.1.0).max()?;
    let in_rows: usize = rows.iter().map(|r| r.1.0).sum();
    let severity = if n >= 300 { Severity::High } else { Severity::Notable };
    let (items, total_items) = top(rows, |r| r.1.0 as f64, |r, w| Item {
        label: format!("{}:{}", crate::analysis::short_path(r.0.0), r.0.1),
        value: format!("{} ({})", plural(r.1.0, "method"), r.1.1.join(", ")),
        weight: w,
        link: Link::Location { file: r.0.0.to_string(), line: r.0.1 },
    });
    Some(Insight {
        kind: "generated-methods",
        severity,
        title: "Methods generated in loops".into(),
        summary: format!("{} each define ≥50 methods ({in_rows} in total, up to {n} from one line)", plural(total_items, "source line")),
        detail: "Many methods attributed to the same line come from code generation (@eval inside loops over \
                 functions and types). The cost grows with the product of the loop ranges.",
        items,
        total_items,
    })
}

/// Methods of other modules' functions where no argument type is the package's own.
fn piracy(w: &World, methods: &[MethodRow]) -> Option<Insight> {
    let mut by: HashMap<&str, (usize, Obj)> = HashMap::new();
    for m in methods.iter().filter(|m| m.pirate && !m.external) {
        by.entry(&m.func).or_insert((0, m.obj)).0 += 1;
    }
    let n: usize = by.values().map(|v| v.0).sum();
    if n == 0 {
        return None;
    }
    // Extensions exist to add methods for types owned by other packages.
    let ext = crate::analysis::own_modules(w).iter().any(|m| m.ends_with("Ext"));
    let (items, total_items) = top(by.into_iter().collect(), |r| r.1.0 as f64, |r, w| Item {
        label: r.0.to_string(),
        value: plural(r.1.0, "method"),
        weight: w,
        link: Link::Function { func: r.0.to_string() },
    });
    Some(Insight {
        kind: "piracy",
        severity: if ext { Severity::Info } else { Severity::Notable },
        title: "Possible type piracy".into(),
        summary: format!(
            "{} {} owned elsewhere without any argument type from this package{}",
            plural(n, "method"), if n == 1 { "extends a function" } else { "extend functions" }, if ext { " (expected in a package extension)" } else { "" },
        ),
        detail: "Such methods change behavior for code that never uses this package and can invalidate \
                 compiled code in other packages when this one loads.",
        items,
        total_items,
    })
}

/// Per-method aggregates of code instances: (count, native bytes, inference ms, label).
fn ci_by_method<'a>(w: &World, cis: impl IntoIterator<Item = &'a CiRow>) -> HashMap<Obj, (usize, u64, f32, String)> {
    let mut by: HashMap<Obj, (usize, u64, f32, String)> = HashMap::new();
    for c in cis {
        let Some(d) = c.def else { continue };
        let e = by.entry(d).or_insert_with(|| (0, 0, 0.0, ci_label(c)));
        e.0 += 1;
        e.1 += c.native_total();
        e.2 += c.infer_self_ms;
    }
    // Methods that share a name and line (e.g. `f(x)` and `f(x, y)` from one definition).
    let mut seen: HashMap<String, usize> = HashMap::new();
    for v in by.values() {
        *seen.entry(v.3.clone()).or_default() += 1;
    }
    for (d, v) in by.iter_mut() {
        if seen[&v.3] > 1 {
            v.3 = format!("{}  {}", v.3, crate::analysis::method_info(w, *d).sig);
        }
    }
    by
}

fn ci_label(c: &CiRow) -> String {
    format!("{}.{}  ({}:{})", c.module, c.method, crate::analysis::short_path(&c.file), c.line)
}

fn specializations(w: &World, cis: &[CiRow]) -> Option<Insight> {
    let rows: Vec<_> = ci_by_method(w, cis).into_iter().filter(|r| r.1.0 >= 30).collect();
    let n = rows.iter().map(|r| r.1.0).max()?;
    let severity = if n >= 100 { Severity::High } else { Severity::Notable };
    let (items, total_items) = top(rows, |r| r.1.0 as f64, |r, w| Item {
        label: r.1.3.clone(),
        value: format!("{} · {} native", plural(r.1.0, "specialization"), human(r.1.1)),
        weight: w,
        link: Link::Specializations { method: r.0, offset: r.0.off },
    });
    Some(Insight {
        kind: "many-specializations",
        severity,
        title: "Methods compiled for many argument types".into(),
        summary: format!("{} have ≥30 specializations each (up to {n})", plural(total_items, "method")),
        detail: "Each specialization is inferred and possibly compiled during precompilation and stored in the \
                 image. @nospecialize, function barriers, or less type-diverse workloads reduce them.",
        items,
        total_items,
    })
}

fn native_concentration(w: &World, cis: &[CiRow]) -> Option<Insight> {
    let total: u64 = cis.iter().map(|c| c.native_total()).sum();
    if total < 64 << 10 {
        return None;
    }
    let rows: Vec<_> = ci_by_method(w, cis).into_iter().filter(|r| r.1.1 > 0).collect();
    let max = rows.iter().map(|r| r.1.1).max()?;
    let share = max as f64 / total as f64;
    let severity = if share >= 0.25 && max >= 256 << 10 { Severity::Notable } else { Severity::Info };
    let (items, total_items) = top(rows, |r| r.1.1 as f64, |r, w| Item {
        label: r.1.3.clone(),
        value: format!("{} ({:.0}%) · {}", human(r.1.1), 100.0 * r.1.1 as f64 / total as f64, plural(r.1.0, "CI")),
        weight: w,
        link: Link::Specializations { method: r.0, offset: r.0.off },
    });
    Some(Insight {
        kind: "native-code",
        severity,
        title: "Largest compiled methods".into(),
        summary: format!("The largest method has {:.0}% of the {} of native code", 100.0 * share, human(total)),
        detail: "Native code is mapped on load and its relocations processed; large shares often come from \
                 aggressive inlining, unrolled tuples or big generated functions.",
        items,
        total_items,
    })
}

fn inference_time(w: &World, cis: &[CiRow]) -> Option<Insight> {
    // In a system image, leave out code the compiler may have inferred while bootstrapping
    // itself: it ran (partly) interpreted then, so those times say little about the code.
    let (cis, boot): (Vec<&CiRow>, Vec<&CiRow>) = cis.iter().partition(|c| !c.bootstrap);
    let total: f32 = cis.iter().map(|c| c.infer_self_ms).sum();
    if total < 50.0 {
        return None;
    }
    let boot_ms: f32 = boot.iter().map(|c| c.infer_self_ms).sum();
    let rows: Vec<_> = ci_by_method(w, cis).into_iter().filter(|r| r.1.2 > 0.0).collect();
    let (items, total_items) = top(rows, |r| r.1.2 as f64, |r, w| Item {
        label: r.1.3.clone(),
        value: format!("{:.1} ms · {}", r.1.2, plural(r.1.0, "CI")),
        weight: w,
        link: Link::Specializations { method: r.0, offset: r.0.off },
    });
    let sys = w.target().heap.worlds;
    Some(Insight {
        kind: "inference-time",
        severity: if total >= 5000.0 { Severity::Notable } else { Severity::Info },
        title: "Most inference time".into(),
        summary: match sys {
            Some(wd) => format!(
                "{:.1} s of inference recorded for code instances valid only after the compiler's world {} \
                 (the {:.1} s in older ones, which includes the compiler bootstrapping itself, is left out)",
                total / 1000.0, wd.typeinf_world, boot_ms / 1000.0,
            ),
            None => format!("{:.1} s of inference recorded for code instances in this image", total / 1000.0),
        },
        detail: if sys.is_some() {
            "Self inference time recorded while building the system image. Code instances valid since \
             before the compiler's world are left out: many were inferred while the compiler was \
             bootstrapping itself and still largely interpreted, which inflates their times."
        } else {
            "Self inference time recorded during precompilation. It is paid again by every session that \
             needs code which is missing or invalidated."
        },
        items,
        total_items,
    })
}

/// The definition that ended world `w`: a method added or deleted in `w + 1`, or a binding
/// changed then.
fn ended_by(w: &World, objs: &[ObjEntry], end: u64) -> Option<String> {
    use crate::world::Kind;
    let next = end.checked_add(1)?;
    let mut found = vec![];
    for e in objs.iter().filter(|e| e.ty.is_some()) {
        let o = e.obj;
        match w.kind(o) {
            Kind::Method if w.field_u64(o, "primary_world") == Some(next) => found.push(format!("{} defined", w.show(crate::Val::Obj(o), 3))),
            Kind::Binding => {
                let mut p = w.field(o, "partitions").and_then(|v| v.obj());
                for _ in 0..64 {
                    let Some(bp) = p.filter(|b| w.type_info(*b).is_some_and(|t| t.name == "BindingPartition")) else { break };
                    if w.field_u64(bp, "min_world") == Some(next) {
                        found.push(format!("{} changed", w.show(crate::Val::Obj(o), 3).trim_start_matches("Binding ")));
                        break;
                    }
                    p = w.field(bp, "next").and_then(|v| v.obj());
                }
            }
            _ if w.type_info(o).is_some_and(|t| t.name == "TypeMapEntry") && w.field_u64(o, "max_world") == Some(end) => {
                if let Some(m) = w.field(o, "func").and_then(|v| v.obj()).filter(|m| w.kind(*m) == Kind::Method) {
                    found.push(format!("{} replaced", w.show(crate::Val::Obj(m), 3)));
                }
            }
            _ => {}
        }
        if found.len() >= 2 {
            break;
        }
    }
    (!found.is_empty()).then(|| found.join("; "))
}

/// System images: code kept twice, once for the world the compiler runs in.
fn compiler_world(w: &World, objs: &[ObjEntry], cis: &[CiRow]) -> Option<Insight> {
    let worlds = w.target().heap.worlds?;
    let rows: Vec<&CiRow> = cis.iter().filter(|c| c.status == "compiler-world").collect();
    if rows.is_empty() {
        return None;
    }
    let bytes = |c: &CiRow| c.native_total() + c.clone_bytes;
    let total: u64 = rows.iter().map(|c| bytes(c)).sum();
    let all: u64 = cis.iter().map(bytes).sum();
    let mut by: HashMap<u64, (usize, u64)> = HashMap::new();
    for c in &rows {
        let e = by.entry(c.max_world).or_default();
        e.0 += 1;
        e.1 += bytes(c);
    }
    let (mut items, total_items) = top(by.into_iter().collect(), |r| r.1.1 as f64, |r, wt| Item {
        label: format!("ended at world {}", r.0),
        value: format!("{} · {}", plural(r.1.0, "CI"), human(r.1.1)),
        weight: wt,
        link: Link::Object { obj: rows[0].obj, offset: rows[0].obj.off, cst: false },
    });
    // Name the definitions only for the items shown: it scans all objects.
    for it in items.iter_mut() {
        let end: u64 = it.label.rsplit(' ').next().and_then(|x| x.parse().ok()).unwrap_or(0);
        if let Some(d) = ended_by(w, objs, end) {
            it.label = format!("{} by {d}", it.label);
        }
        if let Some(c) = rows.iter().filter(|c| c.max_world == end).max_by_key(|c| bytes(c)) {
            it.link = Link::object(c.obj);
        }
    }
    Some(Insight {
        kind: "compiler-world",
        severity: if total >= 4 << 20 { Severity::Notable } else { Severity::Info },
        title: "Code kept for the compiler's world".into(),
        summary: format!(
            "{} ({}, {:.0}% of native code including CPU-target clones) are valid only in world {}, where the compiler runs",
            plural(rows.len(), "code instance"), human(total), 100.0 * total as f64 / all.max(1) as f64, worlds.typeinf_world,
        ),
        detail: "The compiler runs in the world in which it was bootstrapped. Code it uses that later \
                 definitions replaced is saved twice: once for that world and once for everything else. \
                 Each group lists the definition that ended the world range.",
        items,
        total_items,
    })
}

fn dead_code(cis: &[CiRow]) -> Option<Insight> {
    let dead: Vec<&CiRow> = cis.iter().filter(|c| c.status == "dead").collect();
    if dead.is_empty() {
        return None;
    }
    let frac = dead.len() as f64 / cis.len().max(1) as f64;
    let severity = if dead.len() >= 20 || frac >= 0.05 { Severity::Notable } else { Severity::Info };
    let (items, total_items) = top(dead.clone(), |c| (c.inferred_bytes + c.native_bytes) as f64, |c, w| Item {
        label: c.label(),
        value: format!("{} inferred", human(c.inferred_bytes)),
        weight: w,
        link: Link::object(c.obj),
    });
    Some(Insight {
        kind: "invalidated",
        severity,
        title: "Invalidated code instances".into(),
        summary: format!("{} ({:.1}%) were invalidated before the image was saved", plural(dead.len(), "code instance"), 100.0 * frac),
        detail: "These were inferred during precompilation and then invalidated by a later method definition, \
                 so the work is unusable. Loading order or broad method definitions are typical causes.",
        items,
        total_items,
    })
}

fn large_objects(w: &World, objs: &[ObjEntry], cst: &[ObjEntry]) -> Option<Insight> {
    const MIN: u32 = 256 << 10;
    let rows: Vec<&ObjEntry> = objs.iter().chain(cst).filter(|e| e.size >= MIN).collect();
    let max = rows.iter().map(|e| e.size).max()?;
    let (items, total_items) = top(rows, |e| e.size as f64, |e, wt| {
        let ty = crate::analysis::type_key(w, e, false);
        Item {
            label: if e.label == ConstLabel::MemData { format!("{ty} (element data)") } else { w.show(crate::Val::Obj(e.obj), 3) },
            value: human(e.size as u64),
            weight: wt,
            link: Link::object(e.obj),
        }
    });
    Some(Insight {
        kind: "large-objects",
        severity: if max >= 4 << 20 { Severity::Notable } else { Severity::Info },
        title: "Large single objects".into(),
        summary: format!("{} of at least 256 KiB, the largest {}", plural(total_items, "object"), human(max as u64)),
        detail: "Big constants (tables, strings, arrays) baked into the image at precompile time. Consider \
                 computing them lazily or storing them as artifacts if they are rarely used.",
        items,
        total_items,
    })
}

/// All insights, most severe first.
pub fn insights(w: &World, objs: &[ObjEntry], cst: &[ObjEntry], methods: &[MethodRow], cis: &[CiRow]) -> Vec<Insight> {
    let mut v: Vec<Insight> = [
        many_methods(methods),
        generated_methods(methods),
        specializations(w, cis),
        piracy(w, methods),
        dead_code(cis),
        native_concentration(w, cis),
        inference_time(w, cis),
        compiler_world(w, objs, cis),
        large_objects(w, objs, cst),
    ]
    .into_iter()
    .flatten()
    .collect();
    v.sort_by_key(|i| std::cmp::Reverse(i.severity));
    v
}
