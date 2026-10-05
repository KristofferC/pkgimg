//! JSON contracts, using tiny self-contained format-v16 images (no Julia installation needed).
use serde_json::Value;
use std::process::Command;

fn heap(incremental: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (alignment, payload) in [(1, vec![]), (64, vec![]), (8, vec![]), (8, vec![0; if incremental { 36 } else { 12 }]), (8, vec![]), (8, vec![])] {
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.resize(bytes.len().div_ceil(alignment) * alignment, 0);
        bytes.extend(payload);
    }
    if incremental {
        bytes.extend([0; 60]); // Five roots, four empty link lists, external_fns_begin.
    }
    bytes
}

fn image(package: bool) -> Vec<u8> {
    let mut bytes = b"\xfbjli\r\n\x1a\n".to_vec();
    bytes.extend(16u16.to_le_bytes());
    bytes.extend(0xfeffu16.to_le_bytes());
    bytes.push(8);
    bytes.extend(b"Linux\0x86_64\0".iter());
    bytes.extend(b"1.14.0-DEV\0gc\0");
    bytes.extend(u32::from(package).to_le_bytes());
    if package { bytes.extend(b"main\0test\0"); }
    bytes.extend([0; 4]); // checksum
    let range = bytes.len();
    bytes.extend([0; 16]);
    let mut source_pos = None;
    if package {
        bytes.extend([0; 3]); // flags, coverage, syntax
        bytes.extend([0; 4]); // worklist
        bytes.extend([0; 8]); // dependency bytes
        bytes.extend([0; 4]); // include dependencies
        bytes.extend([0; 4]); // preferences
        source_pos = Some(bytes.len());
        bytes.extend([0; 8]);
        bytes.extend([0; 8]); // required modules, clone targets
    }
    let start = bytes.len() as u64;
    bytes.extend(heap(package));
    let end = bytes.len() as u64;
    bytes[range..range + 8].copy_from_slice(&start.to_le_bytes());
    bytes[range + 8..range + 16].copy_from_slice(&end.to_le_bytes());
    if let Some(pos) = source_pos {
        bytes[pos..pos + 8].copy_from_slice(&end.to_le_bytes());
        let path = b"src/example.jl";
        let source = "answer() = \"λ\"\n";
        bytes.extend((path.len() as i32).to_le_bytes());
        bytes.extend(path);
        bytes.extend((source.len() as u64).to_le_bytes());
        bytes.extend(source.as_bytes());
        bytes.extend([0; 4]);
    }
    bytes
}

#[test]
fn json_sources_and_system_dependencies_are_machine_readable() {
    let dir = std::env::temp_dir().join(format!("pkgimg-json-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }
    let _cleanup = Cleanup(dir.clone());
    let sys = dir.join("sys.ji");
    let pkg = dir.join("package.ji");
    std::fs::write(&sys, image(false)).unwrap();
    std::fs::write(&pkg, image(true)).unwrap();
    let run = |args: &[&str]| -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_pkgimg"))
            .args(args).arg("--json").arg("--sysimage").arg(&sys).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice(&out.stdout).expect("stdout must be JSON")
    };
    let deps = run(&["deps", sys.to_str().unwrap()]);
    assert_eq!(deps["schema"], "pkgimg/1");
    assert_eq!(deps["rows"], serde_json::json!([]));
    assert_eq!(deps["total_rows"], 0);
    assert_eq!(deps["truncated"], false);
    let src = run(&["sources", pkg.to_str().unwrap(), "--show", "example.jl"]);
    assert_eq!(src["path"], "src/example.jl");
    assert_eq!(src["text"], "answer() = \"λ\"\n");
    assert_eq!(src["bytes"], src["text"].as_str().unwrap().len());
    assert_eq!(src["image"]["resolution"]["complete"], true);
    let diff = run(&["diff", sys.to_str().unwrap(), sys.to_str().unwrap()]);
    assert_eq!(diff["total_rows"], 0);
    assert_eq!(diff["truncated"], false);
}
