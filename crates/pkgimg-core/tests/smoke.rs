//! Invariants on real images. Set `PKGIMG_TEST_IMAGES` to a `:`-separated list of `.ji`
//! files (and `JULIA_SYSIMAGE` if the system image is not found automatically).

use pkgimg_core::analysis;
use pkgimg_core::world::Kind;
use pkgimg_core::{Options, World};

#[test]
fn invariants() {
    let Ok(list) = std::env::var("PKGIMG_TEST_IMAGES") else {
        eprintln!("PKGIMG_TEST_IMAGES not set; skipping");
        return;
    };
    for f in list.split(':').filter(|s| !s.is_empty()) {
        let w = World::open(f.as_ref(), Options { sysimage: None, depots: vec![], verbose: false }).unwrap();
        assert!(w.sysimg.is_some(), "{f}: system image not found");
        assert!(w.missing.is_empty(), "{f}: missing deps {:?}", w.missing);
        let objs = analysis::object_table(&w, w.target);
        let untyped = objs.iter().filter(|e| e.ty.is_none()).count();
        assert_eq!(untyped, 0, "{f}: objects with unresolved type");
        // Object sizes account for the whole object section.
        let total: u64 = objs.iter().map(|e| e.size as u64).sum();
        let first = objs.first().map_or(0, |e| e.obj.off as u64 - 8);
        assert!(total + first + 16 >= w.target().heap.sys_len as u64 - 16, "{f}: sizes do not cover the section");
        let cis = analysis::code_instances(&w, w.target, &objs);
        // Every fptr_record entry belongs to a code instance we found.
        let nrec = w.target().heap.fptr_record.iter().filter(|&&r| r != 0).count();
        let with_native = cis.iter().map(|c| (c.native_bytes > 0) as usize + (c.wrapper_bytes > 0) as usize).sum::<usize>();
        if w.target().native.is_some() {
            assert_eq!(nrec, with_native, "{f}: fptr_record entries vs code instances with native code");
        }
        // Methods decode with names and modules.
        for e in objs.iter().filter(|e| w.kind(e.obj) == Kind::Method) {
            let m = analysis::method_info(&w, e.obj);
            assert!(!m.name.is_empty() && !m.module.is_empty(), "{f}: bad method at {}", e.obj.off);
        }
        eprintln!("{f}: {} objects, {} code instances ok", objs.len(), cis.len());
    }
}
