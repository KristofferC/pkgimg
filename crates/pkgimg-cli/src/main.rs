use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use pkgimg_core::analysis::{self, CiRow, ConstLabel, HistRow, ObjEntry};
use pkgimg_core::{Options, World};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "pkgimg", about = "Inspect Julia package images (.ji/.so) and system images")]
struct Cli {
    /// Emit JSON instead of text tables.
    #[arg(long, global = true)]
    json: bool,
    /// System image to resolve references against (default: guessed, or $JULIA_SYSIMAGE).
    #[arg(long, global = true)]
    sysimage: Option<PathBuf>,
    /// Depot to search for dependency caches (repeatable; default: $JULIA_DEPOT_PATH, ~/.julia).
    #[arg(long = "depot", global = true)]
    depots: Vec<PathBuf>,
    /// Maximum rows to print (0 = all).
    #[arg(long, short = 'n', global = true, default_value_t = 30)]
    limit: usize,
    #[arg(long, short, global = true)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Overview: header, sizes, counts, largest types.
    Summary { file: PathBuf },
    /// Heap usage grouped by type or module.
    Heap {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = HeapBy::Type)]
        by: HeapBy,
        #[arg(long, value_enum, default_value_t = Section::All)]
        section: Section,
    },
    /// Code instances stored in the image (one per compiled/inferred specialization).
    Compiled {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = CiBy::None)]
        by: CiBy,
        #[arg(long, value_enum, default_value_t = CiSort::Native)]
        sort: CiSort,
        /// Only code instances whose method name or module contains this string.
        #[arg(long)]
        filter: Option<String>,
        /// Only code instances of methods owned by other packages.
        #[arg(long)]
        external: bool,
    },
    /// Methods defined in the image.
    Methods { file: PathBuf },
    /// Required modules and where they were resolved.
    Deps { file: PathBuf },
    /// Source files embedded in the cache file.
    Sources {
        file: PathBuf,
        /// Print the text of this file (suffix match).
        #[arg(long)]
        show: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum HeapBy {
    Type,
    FullType,
    /// Type plus the field of the first object referencing it, e.g. `String <- DebugInfo.codelocs`.
    Referrer,
    Section,
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum Section {
    All,
    Objects,
    Const,
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum CiBy {
    None,
    Method,
    File,
    Module,
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum CiSort {
    Native,
    Inferred,
    InferTime,
    Name,
}

struct Ctx {
    json: bool,
    limit: usize,
}

impl Ctx {
    fn rows<T: Serialize>(&self, cmd: &str, w: &World, rows: &[T], cols: &[(&str, &str)], extra: Value) {
        let n = if self.limit == 0 { rows.len() } else { rows.len().min(self.limit) };
        if self.json {
            let mut v = json!({
                "schema": "pkgimg/1",
                "command": cmd,
                "image": image_id(w),
                "total_rows": rows.len(),
                "truncated": n < rows.len(),
                "rows": &rows[..n],
            });
            if let (Value::Object(m), Value::Object(e)) = (&mut v, extra) {
                m.extend(e);
            }
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            return;
        }
        let vals: Vec<Value> = rows[..n].iter().map(|r| serde_json::to_value(r).unwrap()).collect();
        print_table(&vals, cols);
        if n < rows.len() {
            println!("… {} more rows (use -n 0 for all)", rows.len() - n);
        }
    }
}

fn cell(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Number(n) => {
            if let Some(f) = n.as_f64().filter(|_| n.is_f64()) { format!("{f:.2}") } else { n.to_string() }
        }
        v => v.to_string(),
    }
}

fn print_table(rows: &[Value], cols: &[(&str, &str)]) {
    let mut widths: Vec<usize> = cols.iter().map(|(_, h)| h.len()).collect();
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| cols.iter().map(|(k, _)| cell(&r[*k])).collect())
        .collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count().min(90));
        }
    }
    let line = |vals: Vec<String>| {
        let mut s = String::new();
        for (i, v) in vals.iter().enumerate() {
            let v: String = if v.chars().count() > 90 { v.chars().take(89).chain(['…']).collect() } else { v.clone() };
            let numeric = v.parse::<f64>().is_ok();
            if numeric {
                s.push_str(&format!("{:>w$}  ", v, w = widths[i]));
            } else if i + 1 == vals.len() {
                s.push_str(&v);
            } else {
                s.push_str(&format!("{:<w$}  ", v, w = widths[i]));
            }
        }
        println!("{}", s.trim_end());
    };
    line(cols.iter().map(|(_, h)| h.to_string()).collect());
    for row in cells {
        line(row);
    }
}

fn image_id(w: &World) -> Value {
    let im = w.target();
    let h = &im.header;
    json!({
        "path": im.path,
        "native_path": im.native_path,
        "modules": h.pkg.as_ref().map(|p| p.worklist.iter().map(|m| &m.name).collect::<Vec<_>>()),
        "julia_version": h.base.julia_version,
    })
}

fn kb(b: u64) -> String {
    if b >= 10 << 20 { format!("{:.1} MiB", b as f64 / (1 << 20) as f64) } else { format!("{:.1} KiB", b as f64 / 1024.0) }
}

fn tables(w: &World) -> (Vec<ObjEntry>, Vec<ObjEntry>) {
    let objs = analysis::object_table(w, w.target);
    let cst = analysis::const_table(w, w.target, &objs);
    (objs, cst)
}

fn heap_hist(w: &World, objs: &[ObjEntry], cst: &[ObjEntry], by: HeapBy, section: Section) -> Vec<HistRow> {
    let sel: Vec<&ObjEntry> = match section {
        Section::All => objs.iter().chain(cst).collect(),
        Section::Objects => objs.iter().collect(),
        Section::Const => cst.iter().collect(),
    };
    let refs = if by == HeapBy::Referrer { analysis::first_referrers(w, w.target, objs) } else { Default::default() };
    analysis::histogram(sel.into_iter().map(|e| {
        let key = match by {
            HeapBy::Referrer => {
                let t = analysis::type_key(w, e, false);
                match refs.get(&e.obj) {
                    _ if e.label == ConstLabel::MemData => format!("{t} (element data)"),
                    Some(&(oi, pos)) => format!("{t} <- {}", analysis::slot_label(w, &objs[oi], pos)),
                    None => format!("{t} <- (root)"),
                }
            }
            HeapBy::Type => analysis::type_key(w, e, false),
            HeapBy::FullType => analysis::type_key(w, e, true),
            HeapBy::Section => if e.obj.cst { "const_data".into() } else { "objects".into() },
        };
        let count = if e.label == ConstLabel::MemData { 0 } else { 1 };
        (key, e.size as u64, count)
    }))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = Ctx { json: cli.json, limit: cli.limit };
    let file = match &cli.cmd {
        Cmd::Summary { file } | Cmd::Heap { file, .. } | Cmd::Compiled { file, .. } | Cmd::Methods { file }
        | Cmd::Deps { file } | Cmd::Sources { file, .. } => file.clone(),
    };
    let t0 = Instant::now();
    let w = World::open(&file, Options { sysimage: cli.sysimage.clone(), depots: cli.depots.clone(), verbose: cli.verbose })?;
    if cli.verbose {
        eprintln!("loaded {} images in {:.0?}", w.images.len(), t0.elapsed());
    }
    match cli.cmd {
        Cmd::Summary { .. } => summary(&ctx, &w),
        Cmd::Heap { by, section, .. } => {
            let (objs, cst) = tables(&w);
            let rows = heap_hist(&w, &objs, &cst, by, section);
            ctx.rows("heap", &w, &rows, &[("bytes", "bytes"), ("count", "count"), ("key", "type")], json!({}));
        }
        Cmd::Compiled { by, sort, filter, external, .. } => compiled(&ctx, &w, by, sort, filter, external),
        Cmd::Methods { .. } => {
            let (objs, _) = tables(&w);
            let mut rows = analysis::methods(&w, w.target, &objs);
            rows.sort_by(|a, b| (&a.module, &a.name, &a.file, a.line).cmp(&(&b.module, &b.name, &b.file, b.line)));
            ctx.rows("methods", &w, &rows, &[("module", "module"), ("name", "name"), ("sig", "signature"), ("file", "file"), ("line", "line")], json!({}));
        }
        Cmd::Deps { .. } => deps(&ctx, &w),
        Cmd::Sources { show, .. } => {
            let src = w.target().srctext();
            if let Some(s) = show {
                match src.iter().find(|(p, _)| p.ends_with(&s)) {
                    Some((_, t)) => print!("{t}"),
                    None => anyhow::bail!("no embedded source matching {s}"),
                }
            } else {
                let rows: Vec<Value> = src.iter().map(|(p, t)| json!({"path": p, "bytes": t.len(), "lines": t.lines().count()})).collect();
                ctx.rows("sources", &w, &rows, &[("bytes", "bytes"), ("lines", "lines"), ("path", "path")], json!({}));
            }
        }
    }
    if cli.verbose {
        eprintln!("done in {:.0?}", t0.elapsed());
    }
    Ok(())
}

fn summary(ctx: &Ctx, w: &World) {
    let im = w.target();
    let (objs, cst) = tables(w);
    let cis = analysis::code_instances(w, w.target, &objs);
    let n_methods = objs.iter().filter(|e| e.ty.is_some() && w.kind(e.obj) == pkgimg_core::world::Kind::Method).count();
    let n_mi = objs.iter().filter(|e| e.ty.is_some() && w.kind(e.obj) == pkgimg_core::world::Kind::MethodInstance).count();
    let unknown = objs.iter().filter(|e| e.ty.is_none()).count();
    let native_ci = cis.iter().filter(|c| c.native_bytes > 0).count();
    let native_bytes: u64 = cis.iter().map(|c| c.native_bytes + c.wrapper_bytes).sum();
    let ext_ci = cis.iter().filter(|c| c.external_method).count();
    let dead = cis.iter().filter(|c| c.status == "dead").count();
    let inferred_bytes: u64 = cis.iter().map(|c| c.inferred_bytes).sum();
    let top = heap_hist(w, &objs, &cst, HeapBy::Type, Section::All);
    let h = &im.header;
    let s = &im.heap.sizes;
    let ji_len = im.ji.len() as u64;
    let src_bytes: usize = im.srctext().iter().map(|(_, t)| t.len()).sum();
    let nat = im.native.as_ref();
    let v = json!({
        "schema": "pkgimg/1",
        "command": "summary",
        "image": image_id(w),
        "format_version": h.base.format_version,
        "git_commit": h.base.git_commit,
        "flags": h.pkg.as_ref().map(|p| &p.cache_flags),
        "files": {
            "ji_bytes": ji_len,
            "heap_stored_bytes": im.heap_stored_size,
            "srctext_bytes": src_bytes,
            "native_bytes": nat.map(|n| n.file_size),
            "native_text_bytes": nat.map(|n| n.text_size),
        },
        "heap_sections": s,
        "counts": {
            "objects": objs.len(),
            "const_objects": cst.iter().filter(|e| e.label != ConstLabel::MemData).count(),
            "untyped_objects": unknown,
            "methods": n_methods,
            "method_instances": n_mi,
            "code_instances": cis.len(),
            "code_instances_with_native_code": native_ci,
            "code_instances_for_external_methods": ext_ci,
            "dead_code_instances": dead,
            "native_functions": nat.map(|n| n.fvars.len()),
            "symbols": im.heap.symbols.len(),
            "required_modules": h.pkg.as_ref().map(|p| p.required_modules.len()),
            "unresolved_dependencies": w.missing.iter().map(|m| &m.name).collect::<Vec<_>>(),
        },
        "bytes": {
            "native_code_for_code_instances": native_bytes,
            "compressed_inferred_ir": inferred_bytes,
        },
        "top_types": &top[..top.len().min(ctx.limit.max(1))],
    });
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return;
    }
    println!("{}  ({})", im.display_name(), im.path.display());
    println!("  julia {}  format v{}  commit {}", h.base.julia_version, h.base.format_version, h.base.git_commit.as_deref().unwrap_or("-"));
    if let Some(p) = &h.pkg {
        let f = &p.cache_flags;
        println!("  flags: opt={} debug={} check_bounds={} inline={}  deps: {}", f.opt_level, f.debug_level, f.check_bounds, f.inline, p.required_modules.len());
    }
    println!("files");
    println!("  .ji {:>12}   heap {:>12}   embedded sources {}", kb(ji_len), kb(im.heap_stored_size as u64), kb(src_bytes as u64));
    if let Some(n) = nat {
        println!("  native {:>9}   .text {}", kb(n.file_size), kb(n.text_size));
    }
    println!("heap sections");
    for (k, b) in [("objects", s.objects), ("const_data", s.const_data), ("symbols", s.symbols), ("relocs", s.relocs), ("gvar_record", s.gvar_record), ("fptr_record", s.fptr_record)] {
        println!("  {k:<12} {:>12}", kb(b as u64));
    }
    println!("counts");
    println!("  objects {}  const objects {}  methods {}  method instances {}", objs.len(), v["counts"]["const_objects"], n_methods, n_mi);
    println!("  code instances {}  (with native code {}, for external methods {}, dead {})", cis.len(), native_ci, ext_ci, dead);
    println!("  native code for code instances {}  compressed inferred IR {}", kb(native_bytes), kb(inferred_bytes));
    if unknown > 0 {
        println!("  objects with unresolved type: {unknown}");
    }
    if !w.missing.is_empty() {
        println!("  unresolved dependencies: {}", w.missing.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", "));
    }
    println!("largest types");
    let vals: Vec<Value> = top.iter().take(ctx.limit.clamp(1, 15)).map(|r| serde_json::to_value(r).unwrap()).collect();
    print_table(&vals, &[("bytes", "bytes"), ("count", "count"), ("key", "type")]);
}

#[derive(Serialize, Default, Clone)]
struct CiGroup {
    key: String,
    code_instances: u64,
    native_bytes: u64,
    inferred_bytes: u64,
    infer_self_ms: f32,
}

fn compiled(ctx: &Ctx, w: &World, by: CiBy, sort: CiSort, filter: Option<String>, external: bool) {
    let (objs, _) = tables(w);
    let mut rows: Vec<CiRow> = analysis::code_instances(w, w.target, &objs);
    if let Some(f) = &filter {
        rows.retain(|r| r.method.contains(f.as_str()) || r.module.contains(f.as_str()));
    }
    if external {
        rows.retain(|r| r.external_method);
    }
    let total_native: u64 = rows.iter().map(|r| r.native_bytes + r.wrapper_bytes).sum();
    let extra = json!({"totals": {"code_instances": rows.len(), "native_bytes": total_native,
        "inferred_bytes": rows.iter().map(|r| r.inferred_bytes).sum::<u64>()}});
    if by != CiBy::None {
        let mut m: std::collections::HashMap<String, CiGroup> = Default::default();
        for r in &rows {
            let key = match by {
                CiBy::Method => format!("{}.{} @ {}:{}", r.module, r.method, r.file, r.line),
                CiBy::File => r.file.clone(),
                CiBy::Module => r.module.clone(),
                CiBy::None => unreachable!(),
            };
            let g = m.entry(key.clone()).or_insert_with(|| CiGroup { key, ..Default::default() });
            g.code_instances += 1;
            g.native_bytes += r.native_bytes + r.wrapper_bytes;
            g.inferred_bytes += r.inferred_bytes;
            g.infer_self_ms += r.infer_self_ms;
        }
        let mut g: Vec<CiGroup> = m.into_values().collect();
        g.sort_by(|a, b| match sort {
            CiSort::Native => b.native_bytes.cmp(&a.native_bytes),
            CiSort::Inferred => b.inferred_bytes.cmp(&a.inferred_bytes),
            CiSort::InferTime => b.infer_self_ms.total_cmp(&a.infer_self_ms),
            CiSort::Name => a.key.cmp(&b.key),
        }.then(b.code_instances.cmp(&a.code_instances)));
        ctx.rows("compiled", w, &g, &[("code_instances", "CIs"), ("native_bytes", "native"), ("inferred_bytes", "inferred"), ("infer_self_ms", "infer ms"), ("key", "group")], extra);
        return;
    }
    rows.sort_by(|a, b| match sort {
        CiSort::Native => (b.native_bytes + b.wrapper_bytes).cmp(&(a.native_bytes + a.wrapper_bytes)),
        CiSort::Inferred => b.inferred_bytes.cmp(&a.inferred_bytes),
        CiSort::InferTime => b.infer_self_ms.total_cmp(&a.infer_self_ms),
        CiSort::Name => (&a.module, &a.method).cmp(&(&b.module, &b.method)),
    });
    #[derive(Serialize)]
    struct Shown<'a> {
        #[serde(flatten)]
        r: &'a CiRow,
        func: String,
    }
    let shown: Vec<Shown> = rows.iter().map(|r| Shown { r, func: format!("{}.{}{}", r.module, r.method, r.spec) }).collect();
    ctx.rows("compiled", w, &shown, &[("native_bytes", "native"), ("inferred_bytes", "inferred"), ("infer_self_ms", "infer ms"), ("status", "status"), ("invoke", "invoke"), ("func", "specialization")], extra);
}

fn deps(ctx: &Ctx, w: &World) {
    let Some(p) = &w.target().header.pkg else {
        println!("system image: no dependencies");
        return;
    };
    let rows: Vec<Value> = p
        .required_modules
        .iter()
        .map(|m| {
            let found = w.images.iter().find(|im| {
                im.header.pkg.as_ref().is_some_and(|pk| pk.worklist.iter().any(|x| x.name == m.name && x.uuid == m.uuid && x.build_id_lo == m.build_id_lo))
            });
            let missing = w.missing.iter().any(|x| x.name == m.name && x.uuid == m.uuid);
            let loc = match (found, missing) {
                (Some(im), _) => im.path.display().to_string(),
                (None, false) => "<sysimage>".into(),
                (None, true) => "<not found>".into(),
            };
            json!({"name": m.name, "uuid": m.uuid, "build_id": format!("{:016x}{:016x}", m.build_id_hi, m.build_id_lo), "location": loc})
        })
        .collect();
    ctx.rows("deps", w, &rows, &[("name", "module"), ("location", "location")], json!({}));
}
