# pkgimg

Fast, standalone inspector for Julia package images (`.ji` + `.so`) and system images.
It reads the files directly, so no Julia process is needed, and it resolves references
into the system image and dependency caches to name every type, method and specialization.

- `pkgimg`: CLI with text or JSON output, for humans, scripts and agents
- `pkgimg-gui`: egui desktop app (a web build is planned; the core already compiles for wasm)

Supported formats: Julia master (image format v16) and 1.13 (v12), 64-bit.

## CLI

```
pkgimg summary   <file.ji>                   overview: header, sizes, counts, largest types
pkgimg heap      <file.ji> [--by type|full-type|referrer|section] [--section all|objects|const]
pkgimg compiled  <file.ji> [--by method|file|module|root|parent] [--sort native|inferred|infer-time|name]
                           [--filter STR] [--external]
pkgimg methods   <file.ji>
pkgimg objects   <file.ji> [--type STR]
pkgimg show      <file.ji> <offset> [--const]  decode one object: fields, elements, referrers
pkgimg why       <file.ji> <offset|substring>  inference chain of a code instance (needs provenance)
pkgimg diff      <a.ji> <b.ji>                 before/after: code instances per method, heap per type
pkgimg deps      <file.ji>
pkgimg sources   <file.ji> [--show FILE]       source files embedded in the cache file
```

Global options: `--json`, `-n/--limit N` (0 = all), `--sysimage PATH`, `--depot DIR`,
`--provenance PATH`, `-v`.

The system image is found automatically (next to stdlib caches, via `julia` on `PATH`, the
current directory's `usr/`, or juliaup installs), and checked by matching the `Core` build
id. Set `JULIA_SYSIMAGE` or pass `--sysimage` otherwise. Dependency caches are looked up
in `$JULIA_DEPOT_PATH` / `~/.julia` and the stdlib cache directory by uuid and build id.

### For agents

Every command supports `--json`. The output has a `schema` field, totals, `total_rows` and
`truncated`, and keys that stay stable across builds (signatures with gensym counters
removed in `diff`). A typical loop to reduce compiled code:

1. `pkgimg compiled X.ji --by method --json`: which methods have the most specializations
   and native code
2. `pkgimg compiled X.ji --by root --json`: which entry points (precompile workload calls)
   cause them (needs provenance, see below)
3. change the package, re-precompile, then `pkgimg diff old.ji new.ji --json`

### Provenance (experimental)

An instrumented Julia (branch `kc/image-provenance`) records, for each code instance that
inference publishes during precompilation, the caller whose inference requested it and the
root of that inference. Set `JULIA_IMAGE_PROVENANCE=<dir>` while precompiling. This writes
`<dir>/<Module>-<build_id>.tsv`, which `pkgimg` picks up through `--provenance <dir>` or
the same environment variable.

## GUI

```
cargo run --release -p pkgimg-gui -- path/to/cache.ji
```

Files can also be dropped onto the window. Tabs: overview, heap histogram, objects, code
instances, methods, embedded sources (with per-line method markers) and dependencies. The
inspector decodes any object and links to its fields across images; use alt+←/→ to go
back and forward.

Screenshots of every tab are rendered offscreen with:

```
PKGIMG_SHOT_FILE=x.ji PKGIMG_SHOT_DIR=out cargo test --release -p pkgimg-gui -- --ignored screenshots
```

## How it works

A pkgimage heap is the output of `jl_save_system_image_to_stream` (`src/staticdata.c`). It
is an object section laid out like the live heap, with pointer fields replaced by tagged
relocation words. It is followed by constant data, a symbol table, delta-encoded offset
lists (one type tag per object, plus every pointer slot), and the tables linking code
instances to the native code in the shared library (`fptr_record`, `jl_image_pointers`).
Objects are decoded generically through the type layouts that are themselves serialized
in the images. Only a few C struct offsets (DataType, TypeName, Module) are hard-coded.
