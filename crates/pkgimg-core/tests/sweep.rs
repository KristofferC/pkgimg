//! Open many real cache files and run every analysis; nothing may panic (errors are fine).
//! Run with: cargo test -p pkgimg-core --test sweep -- --ignored --nocapture
//! `PKGIMG_SWEEP_MAX` limits the number of files (default 300), `PKGIMG_SWEEP_MAXSIZE` their size.

use pkgimg_core::{analysis, discover, inspect, Options, Val, World};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn exercise(path: &std::path::Path) -> anyhow::Result<usize> {
    let w = World::open(path, Options { sysimage: None, depots: vec![], verbose: false })?;
    let objs = analysis::object_table(&w, w.target);
    let cst = analysis::const_table(&w, w.target, &objs);
    let cis = analysis::code_instances(&w, w.target, &objs);
    let _ = analysis::methods(&w, w.target, &objs);
    for g in [analysis::Group::Type, analysis::Group::FullType, analysis::Group::Referrer] {
        let _ = analysis::heap_histogram(&w, &objs, &cst, g, analysis::SectionSel::All);
    }
    // Decode a spread of objects generically.
    let step = (objs.len() / 200).max(1);
    for e in objs.iter().step_by(step).chain(cst.iter().step_by(step)) {
        let _ = w.show(Val::Obj(e.obj), 5);
        let _ = inspect::fields(&w, e.obj);
        let _ = inspect::elements(&w, e.obj, 20);
        let _ = inspect::hexdump(&w, e.obj, 64);
    }
    if let (Some(c), Some(buf)) = (cis.iter().find(|c| c.native_addr.is_some()), w.target().native_bytes.as_ref()) {
        let _ = pkgimg_core::native::disassemble(buf, c.native_addr.unwrap(), c.native_bytes);
    }
    let _ = w.target().srctext();
    Ok(objs.len())
}

#[test]
#[ignore]
fn sweep() {
    let max: usize = std::env::var("PKGIMG_SWEEP_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    let maxsize: u64 = std::env::var("PKGIMG_SWEEP_MAXSIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(30 << 20);
    let d = discover::discover(&[]);
    // Spread over Julia versions and locations: every k-th file.
    let mut files: Vec<_> = d.caches.iter().filter(|c| c.ji_size <= maxsize).collect();
    files.sort_by(|a, b| (&a.julia, &a.package, &a.ji).cmp(&(&b.julia, &b.package, &b.ji)));
    let max = if max == 0 { files.len().max(1) } else { max };
    let k = files.len().div_ceil(max).max(1);
    let mut picked: Vec<std::path::PathBuf> = files.iter().step_by(k).take(max).map(|c| c.ji.clone()).collect();
    // Also native libraries directly, and system images.
    picked.extend(files.iter().step_by(k * 7).filter_map(|c| c.native.clone()));
    picked.extend(d.roots.iter().filter_map(|r| r.sysimage.clone()).take(4));
    // Apply the size limit to native libraries and system images too.
    picked.retain(|p| p.metadata().is_ok_and(|m| m.len() <= maxsize));
    let (mut ok, mut err, mut panics) = (0, 0, vec![]);
    for p in &picked {
        match catch_unwind(AssertUnwindSafe(|| exercise(p))) {
            Ok(Ok(_)) => ok += 1,
            Ok(Err(e)) => {
                err += 1;
                if std::env::var("PKGIMG_SWEEP_VERBOSE").is_ok() {
                    eprintln!("ERR {}: {}", p.display(), format!("{e:#}").replace('\n', " "));
                }
            }
            Err(e) => {
                let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                eprintln!("PANIC {}: {msg}", p.display());
                panics.push(p.clone());
            }
        }
    }
    eprintln!("{} files: {ok} ok, {err} errors, {} panics", picked.len(), panics.len());
    assert!(panics.is_empty());
}
