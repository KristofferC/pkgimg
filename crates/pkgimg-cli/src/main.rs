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
    /// Provenance sidecar (file, or directory as given to JULIA_IMAGE_PROVENANCE).
    #[arg(long, global = true)]
    provenance: Option<PathBuf>,
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
    /// Unusual, likely costly, parts of the image (many methods per function, piracy, ...).
    Insights { file: PathBuf },
    /// Disassemble the native code of a code instance (x86-64).
    Asm {
        file: PathBuf,
        /// Code instance offset, or a substring of its specialization (largest match wins).
        what: String,
    },
    /// Why a code instance is in the image: its inference chain (needs a provenance sidecar).
    Why {
        file: PathBuf,
        /// Code instance offset, or a substring of its specialization (largest match wins).
        what: String,
    },
    /// List individual objects.
    Objects {
        file: PathBuf,
        /// Only objects whose type name contains this string (e.g. `Module`, `Base.Dict`).
        #[arg(long = "type")]
        ty: Option<String>,
    },
    /// Compare two images (e.g. before/after a change): code instances and heap by type.
    Diff {
        a: PathBuf,
        b: PathBuf,
    },
    /// Decode one object: fields, elements and referrers (offset from `objects`).
    Show {
        file: PathBuf,
        offset: u32,
        /// The offset is in the const-data section.
        #[arg(long = "const")]
        cst: bool,
    },
    /// Cache files found on this machine (depots, Julia installs, source builds).
    List {
        /// Only packages whose name contains this string.
        filter: Option<String>,
        /// Only this Julia version directory, e.g. `1.14`.
        #[arg(long)]
        julia: Option<String>,
        /// Extra directories to scan.
        #[arg(long = "dir")]
        dirs: Vec<PathBuf>,
    },
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
    /// Entry point of the inference that produced each code instance (needs provenance).
    Root,
    /// Caller whose inference requested each code instance (needs provenance).
    Parent,
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
    fn row_count(&self, total: usize) -> usize {
        if self.limit == 0 { total } else { total.min(self.limit) }
    }

    fn rows<T: Serialize>(&self, cmd: &str, image: Value, rows: &[T], cols: &[(&str, &str)], extra: Value) {
        let n = self.row_count(rows.len());
        if self.json {
            let mut v = json!({
                "schema": "pkgimg/1",
                "command": cmd,
                "image": image,
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
        "resolution": {
            "complete": w.sysimg.is_some() && w.missing.is_empty(),
            "sysimage": w.sysimg.map(|id| &w.img(id).path),
            "missing_dependencies": w.missing,
        },
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
    use analysis::{Group, SectionSel};
    let by = match by {
        HeapBy::Type => Group::Type,
        HeapBy::FullType => Group::FullType,
        HeapBy::Referrer => Group::Referrer,
        HeapBy::Section => Group::Section,
    };
    let sel = match section {
        Section::All => SectionSel::All,
        Section::Objects => SectionSel::Objects,
        Section::Const => SectionSel::Const,
    };
    analysis::heap_histogram(w, objs, cst, by, sel)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = Ctx { json: cli.json, limit: cli.limit };
    if let Cmd::List { filter, julia, dirs } = &cli.cmd {
        return list(&ctx, filter.as_deref(), julia.as_deref(), dirs);
    }
    if let Cmd::Diff { a, b } = &cli.cmd {
        let open = |p: &PathBuf| World::open(&resolve_target(p, &cli.depots)?, Options { sysimage: cli.sysimage.clone(), depots: cli.depots.clone(), verbose: cli.verbose });
        return diff(&ctx, &open(a)?, &open(b)?);
    }
    let file = match &cli.cmd {
        Cmd::Diff { .. } | Cmd::List { .. } => unreachable!(),
        Cmd::Summary { file } | Cmd::Heap { file, .. } | Cmd::Compiled { file, .. } | Cmd::Methods { file } | Cmd::Insights { file } | Cmd::Objects { file, .. } | Cmd::Show { file, .. } | Cmd::Why { file, .. } | Cmd::Asm { file, .. }
        | Cmd::Deps { file } | Cmd::Sources { file, .. } => file.clone(),
    };
    let file = resolve_target(&file, &cli.depots)?;
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
            ctx.rows("heap", image_id(&w), &rows, &[("bytes", "bytes"), ("count", "count"), ("key", "type")], json!({}));
        }
        Cmd::Compiled { by, sort, filter, external, .. } => compiled(&ctx, &w, by, sort, filter, external, cli.provenance.as_deref()),
        Cmd::Asm { what, .. } => asm(&ctx, &w, &what)?,
        Cmd::Why { what, .. } => why(&ctx, &w, &what, cli.provenance.as_deref())?,
        Cmd::Methods { .. } => {
            let (objs, _) = tables(&w);
            let mut rows = analysis::methods(&w, w.target, &objs);
            rows.sort_by(|a, b| (&a.module, &a.name, &a.file, a.line).cmp(&(&b.module, &b.name, &b.file, b.line)));
            let rows: Vec<Value> = rows.iter().map(|r| located_row(r, r.obj)).collect();
            ctx.rows("methods", image_id(&w), &rows, &[("module", "module"), ("name", "name"), ("sig", "signature"), ("file", "file"), ("line", "line")], json!({}));
        }
        Cmd::Insights { .. } => insights(&ctx, &w, cli.provenance.as_deref()),
        Cmd::Deps { .. } => deps(&ctx, &w),
        Cmd::Diff { .. } | Cmd::List { .. } => unreachable!(),
        Cmd::Show { offset, cst, .. } => show(&ctx, &w, pkgimg_core::Obj { img: w.target, cst, off: offset }),
        Cmd::Objects { ty, .. } => {
            let (objs, cst) = tables(&w);
            let mut rows = vec![];
            for e in objs.iter().chain(&cst) {
                let t = analysis::type_key(&w, e, false);
                if ty.as_ref().is_some_and(|f| !t.contains(f.as_str())) {
                    continue;
                }
                rows.push(json!({
                    "offset": e.obj.off, "section": if e.obj.cst { "const" } else { "objects" },
                    "size": e.size, "type": t, "value": w.show(pkgimg_core::Val::Obj(e.obj), 3),
                }));
            }
            ctx.rows("objects", image_id(&w), &rows, &[("section", "section"), ("offset", "offset"), ("size", "size"), ("type", "type"), ("value", "value")], json!({}));
        }
        Cmd::Sources { show, .. } => {
            let src = w.target().srctext();
            if let Some(s) = show {
                match src.iter().find(|(p, _)| p.ends_with(&s)) {
                    Some((path, t)) if ctx.json => {
                        println!("{}", serde_json::to_string_pretty(&json!({
                            "schema": "pkgimg/1", "command": "sources", "image": image_id(&w),
                            "path": path, "text": t, "bytes": t.len(), "lines": t.lines().count(),
                        }))?);
                    }
                    Some((_, t)) => print!("{t}"),
                    None => anyhow::bail!("no embedded source matching {s}"),
                }
            } else {
                let rows: Vec<Value> = src.iter().map(|(p, t)| json!({"path": p, "bytes": t.len(), "lines": t.lines().count()})).collect();
                ctx.rows("sources", image_id(&w), &rows, &[("bytes", "bytes"), ("lines", "lines"), ("path", "path")], json!({}));
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
        "total_rows": top.len(),
        "truncated": ctx.row_count(top.len()) < top.len(),
        "top_types": &top[..ctx.row_count(top.len())],
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
    let vals: Vec<Value> = top.iter().take(ctx.row_count(top.len())).map(|r| serde_json::to_value(r).unwrap()).collect();
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

fn load_cis(w: &World, objs: &[ObjEntry], prov: Option<&std::path::Path>, need: bool) -> Vec<CiRow> {
    let mut rows = analysis::code_instances(w, w.target, objs);
    match pkgimg_core::provenance::Provenance::locate(w, prov) {
        Some(p) => {
            eprintln!("provenance: {} ({} records)", p.path.display(), p.by_ci.len());
            analysis::annotate_provenance(w, w.target, &mut rows, &p);
        }
        None if need => eprintln!("warning: no provenance sidecar found; precompile with JULIA_IMAGE_PROVENANCE=<dir> (instrumented Julia) and pass --provenance <dir>"),
        None => {}
    }
    rows
}

fn compiled(ctx: &Ctx, w: &World, by: CiBy, sort: CiSort, filter: Option<String>, external: bool, prov: Option<&std::path::Path>) {
    let (objs, _) = tables(w);
    let mut rows: Vec<CiRow> = load_cis(w, &objs, prov, matches!(by, CiBy::Root | CiBy::Parent));
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
                CiBy::Root => r.root.clone().unwrap_or_else(|| "<no provenance record>".into()),
                CiBy::Parent => r.parent.clone().unwrap_or_else(|| if r.root.is_some() { "<entry point>".into() } else { "<no provenance record>".into() }),
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
        }.then(b.code_instances.cmp(&a.code_instances)).then_with(|| a.key.cmp(&b.key)));
        ctx.rows("compiled", image_id(w), &g, &[("code_instances", "CIs"), ("native_bytes", "native"), ("inferred_bytes", "inferred"), ("infer_self_ms", "infer ms"), ("key", "group")], extra);
        return;
    }
    rows.sort_by(|a, b| match sort {
        CiSort::Native => (b.native_bytes + b.wrapper_bytes).cmp(&(a.native_bytes + a.wrapper_bytes)),
        CiSort::Inferred => b.inferred_bytes.cmp(&a.inferred_bytes),
        CiSort::InferTime => b.infer_self_ms.total_cmp(&a.infer_self_ms),
        CiSort::Name => (&a.module, &a.method).cmp(&(&b.module, &b.method)),
    });
    let shown: Vec<Value> = rows.iter().map(|r| {
        let mut value = located_row(r, r.obj);
        value["func"] = json!(format!("{}.{}{}", r.module, r.method, r.spec));
        value
    }).collect();
    ctx.rows("compiled", image_id(w), &shown, &[("native_bytes", "native"), ("inferred_bytes", "inferred"), ("infer_self_ms", "infer ms"), ("status", "status"), ("invoke", "invoke"), ("func", "specialization")], extra);
}

fn insights(ctx: &Ctx, w: &World, prov: Option<&std::path::Path>) {
    let (objs, cst) = tables(w);
    let cis = load_cis(w, &objs, prov, false);
    let methods = analysis::methods(w, w.target, &objs);
    let mut v = pkgimg_core::insights::insights(w, &objs, &cst, &methods, &cis);
    let n = ctx.row_count(v.len());
    let truncated = n < v.len();
    v.truncate(n);
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&json!({
            "schema": "pkgimg/1", "command": "insights", "image": image_id(w), "truncated": truncated, "insights": v,
        })).unwrap());
        return;
    }
    if v.is_empty() {
        println!("nothing unusual found");
    }
    for i in &v {
        println!("[{:?}] {}\n  {}", i.severity, i.title, i.summary);
        let rows: Vec<Value> = i.items.iter().take(ctx.row_count(i.items.len()).min(8)).map(|it| json!({"label": it.label, "value": it.value})).collect();
        for r in rows {
            println!("    {:<60}  {}", cell(&r["label"]), cell(&r["value"]));
        }
        if i.total_items > 8 {
            println!("    … {} more", i.total_items - 8);
        }
        println!();
    }
}

fn deps(ctx: &Ctx, w: &World) {
    let Some(p) = &w.target().header.pkg else {
        ctx.rows::<Value>("deps", image_id(w), &[], &[("name", "module"), ("location", "location")], json!({}));
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
    ctx.rows("deps", image_id(w), &rows, &[("name", "module"), ("location", "location")], json!({}));
}

/// Drop gensym counters (`#foo#123` -> `#foo#`) so keys are stable across builds.
fn degensym(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        out.push(c);
        if c == '#' {
            while it.peek().is_some_and(|d| d.is_ascii_digit()) {
                it.next();
            }
        }
    }
    out
}

fn ci_key(r: &CiRow) -> String {
    let owner = if r.owner == "nothing" { String::new() } else { format!(" [owner {}]", r.owner) };
    degensym(&format!("{}.{}{}{}", r.module, r.method, r.spec, owner))
}

fn method_key(r: &CiRow) -> String {
    degensym(&format!("{}.{}", r.module, r.method))
}

#[derive(Serialize)]
struct CiDelta {
    change: &'static str,
    native_bytes: i64,
    inferred_bytes: i64,
    specialization: String,
}

#[derive(Serialize)]
struct TypeDelta {
    key: String,
    a_bytes: u64,
    b_bytes: u64,
    delta_bytes: i64,
    a_count: u64,
    b_count: u64,
}

fn diff(ctx: &Ctx, a: &World, b: &World) -> Result<()> {
    let load = |w: &World| {
        let (objs, cst) = tables(w);
        let cis = analysis::code_instances(w, w.target, &objs);
        let hist = heap_hist(w, &objs, &cst, HeapBy::Type, Section::All);
        (cis, hist, objs.len() + cst.len())
    };
    let (ca, ha, na) = load(a);
    let (cb, hb, nb) = load(b);
    let mut ma: std::collections::HashMap<String, (u64, u64)> = Default::default();
    for r in &ca {
        let e = ma.entry(ci_key(r)).or_default();
        e.0 += r.native_bytes + r.wrapper_bytes;
        e.1 += r.inferred_bytes;
    }
    let mut mb: std::collections::HashMap<String, (u64, u64)> = Default::default();
    for r in &cb {
        let e = mb.entry(ci_key(r)).or_default();
        e.0 += r.native_bytes + r.wrapper_bytes;
        e.1 += r.inferred_bytes;
    }
    let mut cis = vec![];
    for (k, &(n, i)) in &mb {
        match ma.get(k) {
            None => cis.push(CiDelta { change: "added", native_bytes: n as i64, inferred_bytes: i as i64, specialization: k.clone() }),
            Some(&(n0, i0)) if (n0, i0) != (n, i) => cis.push(CiDelta { change: "changed", native_bytes: n as i64 - n0 as i64, inferred_bytes: i as i64 - i0 as i64, specialization: k.clone() }),
            _ => {}
        }
    }
    for (k, &(n, i)) in &ma {
        if !mb.contains_key(k) {
            cis.push(CiDelta { change: "removed", native_bytes: -(n as i64), inferred_bytes: -(i as i64), specialization: k.clone() });
        }
    }
    cis.sort_by(|a, b| {
        (b.native_bytes.abs() + b.inferred_bytes.abs()).cmp(&(a.native_bytes.abs() + a.inferred_bytes.abs()))
            .then_with(|| a.specialization.cmp(&b.specialization))
    });
    #[derive(Serialize, Default)]
    struct MethodDelta { method: String, a_code_instances: i64, b_code_instances: i64, delta_code_instances: i64, delta_native_bytes: i64 }
    let mut md: std::collections::HashMap<String, MethodDelta> = Default::default();
    for (rows, sign) in [(&ca, -1i64), (&cb, 1)] {
        for r in rows.iter() {
            let k = method_key(r);
            let e = md.entry(k.clone()).or_insert_with(|| MethodDelta { method: k, ..Default::default() });
            if sign < 0 { e.a_code_instances += 1 } else { e.b_code_instances += 1 }
            e.delta_native_bytes += sign * (r.native_bytes + r.wrapper_bytes) as i64;
        }
    }
    let mut methods: Vec<MethodDelta> = md.into_values().map(|mut m| { m.delta_code_instances = m.b_code_instances - m.a_code_instances; m })
        .filter(|m| m.delta_code_instances != 0 || m.delta_native_bytes != 0).collect();
    methods.sort_by(|a, b| {
        (b.delta_code_instances.abs(), b.delta_native_bytes.abs()).cmp(&(a.delta_code_instances.abs(), a.delta_native_bytes.abs()))
            .then_with(|| a.method.cmp(&b.method))
    });
    let mut types: std::collections::BTreeMap<String, TypeDelta> = Default::default();
    for (h, is_b) in [(&ha, false), (&hb, true)] {
        for r in h.iter() {
            let t = types.entry(r.key.clone()).or_insert_with(|| TypeDelta { key: r.key.clone(), a_bytes: 0, b_bytes: 0, delta_bytes: 0, a_count: 0, b_count: 0 });
            if is_b { t.b_bytes += r.bytes; t.b_count += r.count; } else { t.a_bytes += r.bytes; t.a_count += r.count; }
        }
    }
    let mut types: Vec<TypeDelta> = types.into_values().filter(|t| t.a_bytes != t.b_bytes).map(|mut t| { t.delta_bytes = t.b_bytes as i64 - t.a_bytes as i64; t }).collect();
    types.sort_by(|a, b| b.delta_bytes.abs().cmp(&a.delta_bytes.abs()).then_with(|| a.key.cmp(&b.key)));
    let tot = |c: &[CiRow]| (c.len(), c.iter().map(|r| r.native_bytes + r.wrapper_bytes).sum::<u64>(), c.iter().map(|r| r.inferred_bytes).sum::<u64>());
    let (ta, tb) = (tot(&ca), tot(&cb));
    let heap = |w: &World| w.target().heap.data.len() as i64;
    let summary = json!({
        "code_instances": {"a": ta.0, "b": tb.0, "delta": tb.0 as i64 - ta.0 as i64},
        "native_bytes": {"a": ta.1, "b": tb.1, "delta": tb.1 as i64 - ta.1 as i64},
        "inferred_bytes": {"a": ta.2, "b": tb.2, "delta": tb.2 as i64 - ta.2 as i64},
        "heap_bytes": {"a": heap(a), "b": heap(b), "delta": heap(b) - heap(a)},
        "objects": {"a": na, "b": nb, "delta": nb as i64 - na as i64},
        "code_instances_added": cis.iter().filter(|c| c.change == "added").count(),
        "code_instances_removed": cis.iter().filter(|c| c.change == "removed").count(),
    });
    let lim = |n| ctx.row_count(n);
    if ctx.json {
        let v = json!({
            "schema": "pkgimg/1", "command": "diff",
            "a": image_id(a), "b": image_id(b), "summary": summary,
            "methods": &methods[..lim(methods.len())], "methods_total": methods.len(),
            "code_instances": &cis[..lim(cis.len())], "code_instances_total": cis.len(),
            "types": &types[..lim(types.len())], "types_total": types.len(),
            "total_rows": methods.len() + cis.len() + types.len(),
            "truncated": ([methods.len(), cis.len(), types.len()].iter().any(|&n| lim(n) < n)),
            "methods_truncated": lim(methods.len()) < methods.len(),
            "code_instances_truncated": lim(cis.len()) < cis.len(),
            "types_truncated": lim(types.len()) < types.len(),
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return Ok(());
    }
    println!("a: {}\nb: {}", a.target().path.display(), b.target().path.display());
    for k in ["code_instances", "native_bytes", "inferred_bytes", "heap_bytes", "objects"] {
        let s = &summary[k];
        println!("  {k:<16} {:>12} -> {:>12}  ({:+})", s["a"], s["b"], s["delta"].as_i64().unwrap_or(0));
    }
    println!("\nby method");
    let rows: Vec<Value> = methods[..lim(methods.len())].iter().map(|c| serde_json::to_value(c).unwrap()).collect();
    print_table(&rows, &[("delta_code_instances", "ΔCIs"), ("a_code_instances", "a"), ("b_code_instances", "b"), ("delta_native_bytes", "Δnative"), ("method", "method")]);
    println!("\ncode instances ({} added, {} removed)", summary["code_instances_added"], summary["code_instances_removed"]);
    let rows: Vec<Value> = cis[..lim(cis.len())].iter().map(|c| serde_json::to_value(c).unwrap()).collect();
    print_table(&rows, &[("change", "change"), ("native_bytes", "native"), ("inferred_bytes", "inferred"), ("specialization", "specialization")]);
    println!("\nheap by type");
    let rows: Vec<Value> = types[..lim(types.len())].iter().map(|c| serde_json::to_value(c).unwrap()).collect();
    print_table(&rows, &[("delta_bytes", "delta"), ("a_bytes", "a"), ("b_bytes", "b"), ("key", "type")]);
    Ok(())
}

fn located_row(row: &impl Serialize, obj: pkgimg_core::Obj) -> Value {
    let mut value = serde_json::to_value(row).expect("serializable table row");
    value["offset"] = json!(obj.off);
    value["const"] = json!(obj.cst);
    value
}

fn val_json(w: &World, v: pkgimg_core::Val) -> Value {
    match v {
        pkgimg_core::Val::Obj(o) => json!({
            "value": w.show(v, 3),
            "type": w.type_info(o).map(|t| t.qualified()),
            "image": if o.img == w.target { None } else { Some(w.img(o.img).display_name()) },
            "offset": o.off, "const": o.cst,
        }),
        v => json!({"value": w.show(v, 3)}),
    }
}

fn show(ctx: &Ctx, w: &World, o: pkgimg_core::Obj) {
    use pkgimg_core::inspect::{self, FieldValue};
    let (objs, _) = tables(w);
    let ty = w.type_info(o).map(|t| w.show(pkgimg_core::Val::Obj(t.obj), 4));
    let fields: Vec<Value> = inspect::fields(w, o)
        .into_iter()
        .map(|f| {
            let mut v = match f.value {
                FieldValue::Ptr(p) => val_json(w, p),
                FieldValue::Bits(b) => json!({"value": b}),
            };
            v["name"] = json!(f.name);
            v["field_type"] = json!(f.ty);
            v
        })
        .collect();
    let elems = inspect::elements(w, o, 50).map(|(n, es)| json!({"length": n, "first": es.into_iter().map(|e| val_json(w, e)).collect::<Vec<_>>()}));
    let refs: Vec<Value> = if o.img == w.target {
        inspect::referrers(w, w.target, &objs, o).into_iter().take(50).map(|(i, label)| {
            let e = &objs[i];
            json!({"offset": e.obj.off, "slot": label, "value": w.show(pkgimg_core::Val::Obj(e.obj), 3)})
        }).collect()
    } else { vec![] };
    let v = json!({
        "schema": "pkgimg/1", "command": "show",
        "image": image_id(w),
        "offset": o.off, "const": o.cst, "type": ty,
        "value": w.show(pkgimg_core::Val::Obj(o), 4),
        "string": inspect::string_value(w, o),
        "fields": fields, "elements": elems, "referrers": refs,
    });
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return;
    }
    println!("{} @ {}{}  ::{}", v["value"].as_str().unwrap_or(""), if o.cst { "const+" } else { "" }, o.off, ty.unwrap_or_default());
    if let Some(s) = v["string"].as_str() {
        println!("  {:?}", s.chars().take(400).collect::<String>());
    }
    for f in &fields {
        let loc = match (f["offset"].as_u64(), f["image"].as_str()) {
            (Some(off), Some(img)) => format!("  [{img} @{off}]"),
            (Some(off), None) => format!("  [@{}{off}]", if f["const"] == json!(true) { "const+" } else { "" }),
            _ => String::new(),
        };
        println!("  {:<24} {}{}", f["name"].as_str().unwrap_or(""), f["value"].as_str().unwrap_or(""), loc);
    }
    if let Some(e) = &elems {
        println!("elements ({})", e["length"]);
        for (i, x) in e["first"].as_array().unwrap().iter().enumerate() {
            println!("  [{}] {}", i + 1, x["value"].as_str().unwrap_or(""));
        }
    }
    if !refs.is_empty() {
        println!("referenced from");
        for r in &refs {
            println!("  @{:<10} {:<32} {}", r["offset"], r["slot"].as_str().unwrap_or(""), r["value"].as_str().unwrap_or(""));
        }
    }
}

fn why(ctx: &Ctx, w: &World, what: &str, prov: Option<&std::path::Path>) -> Result<()> {
    let (objs, _) = tables(w);
    let rows = load_cis(w, &objs, prov, true);
    let pick = match what.parse::<u32>() {
        Ok(off) => rows.iter().find(|r| r.obj.off == off),
        Err(_) => rows
            .iter()
            .filter(|r| format!("{}.{}{}", r.module, r.method, r.spec).contains(what))
            .max_by_key(|r| r.native_bytes + r.wrapper_bytes + r.inferred_bytes),
    };
    let Some(start) = pick else { anyhow::bail!("no code instance matches {what:?}") };
    // Follow parents: parent label -> code instance with that MethodInstance label.
    let by_label: std::collections::HashMap<String, &CiRow> =
        rows.iter().filter_map(|r| r.mi.map(|mi| (analysis::mi_label(w, mi), r))).collect();
    let mut chain = vec![];
    let mut cur = Some(start);
    let mut seen = std::collections::HashSet::new();
    while let Some(r) = cur {
        if !seen.insert(r.obj.off) {
            break;
        }
        chain.push(json!({
            "specialization": format!("{}.{}{}", r.module, r.method, r.spec),
            "offset": r.obj.off, "native_bytes": r.native_bytes + r.wrapper_bytes,
            "inferred_bytes": r.inferred_bytes, "file": r.file, "line": r.line,
        }));
        cur = r.parent.as_ref().and_then(|p| by_label.get(p).copied());
        if cur.is_none()
            && let Some(p) = &r.parent
        {
            chain.push(json!({"specialization": p, "note": "caller not compiled into this image"}));
        }
    }
    let v = json!({"schema": "pkgimg/1", "command": "why", "image": image_id(w), "root": start.root, "chain": chain});
    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return Ok(());
    }
    println!("root (inference entry point): {}", start.root.as_deref().unwrap_or("<unknown>"));
    for (i, c) in chain.iter().enumerate() {
        let arrow = if i == 0 { "  " } else { "  ← called from " };
        let extra = c["native_bytes"].as_u64().map(|n| format!("  [{n} B native, {} B IR]", c["inferred_bytes"])).unwrap_or_default();
        println!("{}{}{}", "  ".repeat(i.min(12)) + arrow, c["specialization"].as_str().unwrap_or(""), extra);
    }
    Ok(())
}

/// Accept a package name in place of a path: the most recently written cache for it that
/// this reader supports, among all discovered depots and Julia installations.
fn resolve_target(p: &std::path::Path, depots: &[PathBuf]) -> Result<PathBuf> {
    use pkgimg_core::discover;
    if p.exists() || p.components().count() > 1 {
        return Ok(p.to_path_buf());
    }
    let name = p.to_string_lossy();
    let d = discover::discover(depots);
    let mut cands: Vec<&discover::CacheFile> = d.caches.iter().filter(|c| c.package == name).collect();
    cands.sort_by_key(|c| std::cmp::Reverse(c.modified));
    match cands.into_iter().find(|c| discover::read_summary(&c.ji).is_some_and(|s| s.supported)) {
        Some(c) => {
            eprintln!("using {}", c.ji.display());
            Ok(c.ji.clone())
        }
        None => anyhow::bail!("{name}: no such file, and no supported cache file for a package of that name (see `pkgimg list {name}`)"),
    }
}

fn list(ctx: &Ctx, filter: Option<&str>, julia: Option<&str>, dirs: &[PathBuf]) -> Result<()> {
    use pkgimg_core::discover;
    let d = discover::discover(dirs);
    let f = filter.map(|f| f.to_lowercase());
    let jv = julia.map(|j| if j.starts_with('v') { j.to_string() } else { format!("v{j}") });
    let mut rows: Vec<&discover::CacheFile> = d
        .caches
        .iter()
        .filter(|c| f.as_ref().is_none_or(|f| c.package.to_lowercase().contains(f)))
        .filter(|c| jv.as_ref().is_none_or(|j| &c.julia == j))
        .collect();
    rows.sort_by_key(|c| std::cmp::Reverse(c.modified));
    let now = std::time::SystemTime::now();
    let vals: Vec<Value> = rows
        .iter()
        .map(|c| {
            let age = now.duration_since(c.modified).map(|d| d.as_secs()).unwrap_or(0);
            let r = &d.roots[c.root];
            json!({
                "package": c.package, "julia": c.julia, "path": c.ji, "ji_bytes": c.ji_size,
                "native_bytes": c.native_size, "age": human_age(age), "age_seconds": age,
                "location": format!("{:?} {}", r.kind, r.path.display()).to_lowercase().replacen(' ', ": ", 1),
                "sysimage": discover::sysimage_for(&d, c),
            })
        })
        .collect();
    ctx.rows("list", Value::Null, &vals, &[("package", "package"), ("julia", "julia"), ("age", "modified"), ("ji_bytes", ".ji"), ("native_bytes", "native"), ("path", "path")], json!({"roots": d.roots}));
    Ok(())
}

fn human_age(s: u64) -> String {
    match s {
        s if s < 120 => format!("{s}s ago"),
        s if s < 7200 => format!("{}m ago", s / 60),
        s if s < 172800 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

fn pick_ci<'a>(w: &World, rows: &'a [CiRow], what: &str) -> Option<&'a CiRow> {
    let _ = w;
    match what.parse::<u32>() {
        Ok(off) => rows.iter().find(|r| r.obj.off == off),
        Err(_) => rows
            .iter()
            .filter(|r| format!("{}.{}{}", r.module, r.method, r.spec).contains(what))
            .max_by_key(|r| r.native_bytes + r.wrapper_bytes + r.inferred_bytes),
    }
}

fn asm(ctx: &Ctx, w: &World, what: &str) -> Result<()> {
    let (objs, _) = tables(w);
    let rows = analysis::code_instances(w, w.target, &objs);
    let r = pick_ci(w, &rows, what).ok_or_else(|| anyhow::anyhow!("no code instance matches {what:?}"))?;
    let (Some(addr), Some(buf)) = (r.native_addr, w.target().native_bytes.as_ref()) else {
        anyhow::bail!("{}.{}{} has no native code in this image", r.module, r.method, r.spec);
    };
    let lines = pkgimg_core::native::disassemble(buf, addr, r.native_bytes)?;
    if ctx.json {
        let v = json!({"schema": "pkgimg/1", "command": "asm", "specialization": format!("{}.{}{}", r.module, r.method, r.spec),
            "symbol": r.native_symbol, "bytes": r.native_bytes,
            "instructions": lines.iter().map(|(a, t)| json!({"address": format!("{a:#x}"), "text": t})).collect::<Vec<_>>()});
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return Ok(());
    }
    println!("; {}.{}{}  ({}, {} bytes)", r.module, r.method, r.spec, r.native_symbol.as_deref().unwrap_or("?"), r.native_bytes);
    for (a, t) in lines {
        println!("{a:8x}  {t}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_rows_include_inspectable_location() {
        let obj = pkgimg_core::Obj { img: 0, off: 128, cst: true };
        let value = located_row(&json!({"method": "f"}), obj);
        assert_eq!(value, json!({"method": "f", "offset": 128, "const": true}));
    }

    #[test]
    fn row_limits_include_zero_as_unlimited() {
        for json in [false, true] {
            assert_eq!(Ctx { json, limit: 0 }.row_count(100), 100);
            assert_eq!(Ctx { json, limit: 20 }.row_count(100), 20);
            assert_eq!(Ctx { json, limit: 20 }.row_count(3), 3);
            assert_eq!(Ctx { json, limit: 0 }.row_count(0), 0);
        }
    }
}
