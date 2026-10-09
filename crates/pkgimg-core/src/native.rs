//! Native image (.so/.dylib/.dll): embedded heap symbols, `jl_image_pointers` and function symbols.

use anyhow::{Context, Result, bail};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, SymbolKind};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct NativeFunc {
    pub addr: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NativeInfo {
    pub file_size: u64,
    pub text_size: u64,
    /// Bytes per ELF/Mach-O section name.
    pub sections: Vec<(String, u64)>,
    /// Function symbols sorted by address.
    pub funcs: Vec<NativeFunc>,
    /// Global function index (as used by the heap's `fptr_record`) -> address.
    pub fvars: Vec<u64>,
    pub ngvars: u32,
    pub nshards: u32,
    pub cpu_target: Option<String>,
    /// Function address -> (count, bytes) of its clones for other CPU targets (`name.1`, `name.2`, ...).
    pub clones: HashMap<u64, (u32, u64)>,
}

impl NativeInfo {
    /// Function symbol whose range contains `addr`.
    pub fn func_at(&self, addr: u64) -> Option<&NativeFunc> {
        let i = self.funcs.partition_point(|f| f.addr <= addr);
        let f = self.funcs.get(i.checked_sub(1)?)?;
        (addr < f.addr + f.size.max(1)).then_some(f)
    }

    /// Bytes of the CPU-target clones of the function starting at `addr`.
    pub fn clone_bytes(&self, addr: u64) -> u64 {
        self.clones.get(&addr).map_or(0, |c| c.1)
    }

    /// Bytes of DWARF debug sections.
    pub fn debug_size(&self) -> u64 {
        self.sections.iter().filter(|(n, _)| n.starts_with(".debug") || n.starts_with("__debug")).map(|s| s.1).sum()
    }
}

struct Mem<'a> {
    file: &'a object::File<'a>,
    /// Pointer slots fixed up by `R_*_RELATIVE` dynamic relocations or Mach-O chained
    /// rebases: slot -> target.
    relative: HashMap<u64, u64>,
}

fn le16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn le32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn le64(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

/// Rebases from `LC_DYLD_CHAINED_FIXUPS` (`DYLD_CHAINED_PTR_64` and `_64_OFFSET`, as
/// used by arm64 and x86-64 macOS): pointer slot -> target address. Binds are skipped.
fn chained_rebases(file: &object::File, out: &mut HashMap<u64, u64>) -> Option<()> {
    use object::macho;
    let object::File::MachO64(f) = file else { return None };
    let e = f.endian();
    let buf = f.data();
    // (vmaddr, fileoff, filesize) in load command order, as indexed by the fixups.
    let mut segs = vec![];
    let mut fixups = None;
    let mut cmds = f.macho_load_commands().ok()?;
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, _))) = cmd.segment_64() {
            segs.push((seg.vmaddr.get(e), seg.fileoff.get(e), seg.filesize.get(e)));
        } else if cmd.cmd() == macho::LC_DYLD_CHAINED_FIXUPS {
            let c = cmd.data::<macho::LinkeditDataCommand<object::Endianness>>().ok()?;
            fixups = buf.get(c.dataoff.get(e) as usize..)?.get(..c.datasize.get(e) as usize);
        }
    }
    let d = fixups?;
    // Image base: the segment that maps the Mach-O header.
    let base = segs.iter().find(|s| s.1 == 0 && s.2 > 0)?.0;
    let starts = le32(d, 4)? as usize;
    for (i, &(vmaddr, fileoff, _)) in segs.iter().enumerate().take(le32(d, starts)? as usize) {
        let info = le32(d, starts + 4 + 4 * i)? as usize;
        if info == 0 {
            continue;
        }
        let ss = starts + info;
        let page_size = le16(d, ss + 4)? as u64;
        let format = le16(d, ss + 6)?;
        let offset_based = match format {
            2 => false, // DYLD_CHAINED_PTR_64: target is a vmaddr
            6 => true,  // DYLD_CHAINED_PTR_64_OFFSET: target is an offset from the image base
            _ => continue,
        };
        for page in 0..le16(d, ss + 20)? as u64 {
            let start = le16(d, ss + 22 + 2 * page as usize)?;
            if start == macho::DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            let mut off = page * page_size + start as u64;
            loop {
                let raw = le64(buf, (fileoff + off) as usize)?;
                if raw >> 63 == 0 {
                    let target = (raw & 0xF_FFFF_FFFF) | ((raw >> 36) & 0xFF) << 56;
                    out.insert(vmaddr + off, if offset_based { base + target } else { target });
                }
                let next = (raw >> 51) & 0xFFF;
                if next == 0 {
                    break;
                }
                off += 4 * next;
            }
        }
    }
    Some(())
}

impl<'a> Mem<'a> {
    fn new(file: &'a object::File<'a>) -> Self {
        let mut relative = HashMap::new();
        if let Some(rels) = file.dynamic_relocations() {
            for (off, r) in rels {
                if matches!(r.target(), RelocationTarget::Absolute) {
                    relative.insert(off, r.addend() as u64);
                }
            }
        }
        chained_rebases(file, &mut relative);
        Mem { file, relative }
    }

    fn bytes(&self, addr: u64, len: u64) -> Option<&'a [u8]> {
        for s in self.file.sections() {
            let (a, sz) = (s.address(), s.size());
            if addr >= a && addr + len <= a + sz {
                let d = s.data().ok()?;
                let o = (addr - a) as usize;
                return d.get(o..o + len as usize);
            }
        }
        None
    }

    fn u32(&self, addr: u64) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(addr, 4)?.try_into().ok()?))
    }
    fn u64(&self, addr: u64) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(addr, 8)?.try_into().ok()?))
    }
    /// Read a pointer, applying a relative relocation if one targets this slot.
    fn ptr(&self, addr: u64) -> Option<u64> {
        if let Some(&v) = self.relative.get(&addr) {
            return Some(v);
        }
        self.u64(addr)
    }
    fn cstr(&self, addr: u64) -> Option<String> {
        for s in self.file.sections() {
            let a = s.address();
            if addr >= a && addr < a + s.size() {
                let d = s.data().ok()?;
                let rest = &d[(addr - a) as usize..];
                let n = rest.iter().position(|&b| b == 0)?;
                return Some(String::from_utf8_lossy(&rest[..n]).into_owned());
            }
        }
        None
    }
}

fn find_symbol(file: &object::File, name: &str) -> Option<u64> {
    let dynsym = file.dynamic_symbols().find(|s| s.name() == Ok(name));
    let sym = dynsym.or_else(|| file.symbols().find(|s| s.name() == Ok(name)))?;
    Some(sym.address())
}

/// `(uname, arch)` of a native library, in the spelling of `JL_BUILD_UNAME`/`JL_BUILD_ARCH`.
pub fn platform(buf: &[u8]) -> (String, String) {
    let Ok(f) = object::File::parse(buf) else { return (String::new(), String::new()) };
    let uname = match f.format() {
        object::BinaryFormat::MachO => "Darwin",
        object::BinaryFormat::Coff | object::BinaryFormat::Pe => "NT",
        _ => "Linux",
    };
    let arch = match f.architecture() {
        object::Architecture::X86_64 => "x86_64",
        object::Architecture::Aarch64 => "aarch64",
        object::Architecture::PowerPc64 => "ppc64le",
        object::Architecture::Riscv64 => "riscv64",
        a => return (uname.into(), format!("{a:?}").to_lowercase()),
    };
    (uname.into(), arch.into())
}

/// Bytes of the embedded image (`jl_system_image_data`), if this native image has one.
pub fn embedded_image(buf: &[u8]) -> Result<Option<(usize, usize)>> {
    let file = object::File::parse(buf)?;
    let mem = Mem::new(&file);
    let Some(data) = find_symbol(&file, "jl_system_image_data")
        .or_else(|| find_symbol(&file, "_jl_system_image_data"))
    else {
        return Ok(None);
    };
    let size_sym = find_symbol(&file, "jl_system_image_size")
        .or_else(|| find_symbol(&file, "_jl_system_image_size"))
        .context("jl_system_image_size missing")?;
    let len = mem.u64(size_sym).context("cannot read jl_system_image_size")?;
    for s in file.sections() {
        let a = s.address();
        if data >= a && data < a + s.size() {
            let (foff, _) = s.file_range().context("image data section has no file data")?;
            return Ok(Some(((foff + (data - a)) as usize, len as usize)));
        }
    }
    bail!("jl_system_image_data not in a file-backed section")
}

pub fn parse(buf: &[u8]) -> Result<NativeInfo> {
    let file = object::File::parse(buf)?;
    let mem = Mem::new(&file);
    let mut info = NativeInfo { file_size: buf.len() as u64, ..Default::default() };
    for s in file.sections() {
        let name = s.name().unwrap_or("?").to_string();
        if s.kind() == object::SectionKind::Text {
            info.text_size += s.size();
        }
        info.sections.push((name, s.size()));
    }
    // Mach-O symbols carry no size; each function then extends to the next one.
    let macho = file.format() == object::BinaryFormat::MachO;
    let mut funcs: Vec<NativeFunc> = file
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text && (s.size() > 0 || macho))
        .map(|s| NativeFunc { addr: s.address(), size: s.size(), name: s.name().unwrap_or("").to_string() })
        .collect();
    funcs.sort_by_key(|f| f.addr);
    funcs.dedup_by_key(|f| f.addr);
    if macho {
        let text: Vec<(u64, u64)> = file
            .sections()
            .filter(|s| s.kind() == object::SectionKind::Text)
            .map(|s| (s.address(), s.address() + s.size()))
            .collect();
        for i in 0..funcs.len() {
            let addr = funcs[i].addr;
            let Some(&(_, end)) = text.iter().find(|&&(a, e)| addr >= a && addr < e) else { continue };
            let next = funcs.get(i + 1).map_or(end, |f| f.addr.min(end));
            funcs[i].size = next - addr;
        }
        funcs.retain(|f| f.size > 0);
    }
    let by_name: HashMap<&str, u64> = funcs.iter().map(|f| (f.name.as_str(), f.addr)).collect();
    for f in &funcs {
        let Some((base, n)) = f.name.rsplit_once('.') else { continue };
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Some(&a) = by_name.get(base) {
            let e = info.clones.entry(a).or_default();
            e.0 += 1;
            e.1 += f.size;
        }
    }
    info.funcs = funcs;

    let Some(ptrs) = find_symbol(&file, "jl_image_pointers").or_else(|| find_symbol(&file, "_jl_image_pointers"))
    else {
        return Ok(info);
    };
    // jl_image_pointers_t { header, shards, ptls, jl_small_typeof, target_data, cpu_target_string }
    let header = mem.ptr(ptrs).context("jl_image_pointers.header")?;
    let shards = mem.ptr(ptrs + 8).context("jl_image_pointers.shards")?;
    info.cpu_target = mem.ptr(ptrs + 40).and_then(|p| mem.cstr(p));
    // jl_image_header_t { version, nshards, nfvars, ngvars }
    let version = mem.u32(header).context("image header")?;
    if version != 1 {
        bail!("unsupported native image header version {version}");
    }
    info.nshards = mem.u32(header + 4).unwrap_or(0);
    let nfvars = mem.u32(header + 8).unwrap_or(0) as usize;
    info.ngvars = mem.u32(header + 12).unwrap_or(0);
    let mut fvars = vec![0u64; nfvars];
    for i in 0..info.nshards as u64 {
        // jl_image_shard_t: fvar_count, fvar_ptrs, fvar_idxs, gvar_offsets, gvar_idxs, clone_slots, clone_ptrs, clone_idxs
        let sh = shards + i * 64;
        let (Some(cnt), Some(fptrs), Some(fidxs)) = (mem.ptr(sh), mem.ptr(sh + 8), mem.ptr(sh + 16)) else {
            continue;
        };
        let n = mem.u64(cnt).unwrap_or(0);
        for k in 0..n {
            let (Some(idx), Some(p)) = (mem.u32(fidxs + 4 * k), mem.ptr(fptrs + 8 * k)) else { continue };
            if let Some(slot) = fvars.get_mut(idx as usize) {
                *slot = p;
            }
        }
    }
    info.fvars = fvars;
    Ok(info)
}

/// Disassemble `[addr, addr+size)` of a native library (x86-64 only for now): `(address, text)`.
pub fn disassemble(buf: &[u8], addr: u64, size: u64) -> Result<Vec<(u64, String)>> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, SymbolResolver, SymbolResult};
    let file = object::File::parse(buf)?;
    if file.architecture() != object::Architecture::X86_64 {
        bail!("disassembly is only implemented for x86-64 (this is {:?})", file.architecture());
    }
    let mem = Mem::new(&file);
    let code = mem.bytes(addr, size).context("function bytes not in a file-backed section")?;
    // Name call/jump targets after the symbols they land in.
    struct Syms(Vec<(u64, u64, String)>);
    impl SymbolResolver for Syms {
        fn symbol(&mut self, ins: &iced_x86::Instruction, _: u32, _: Option<u32>, address: u64, _: u32) -> Option<SymbolResult<'_>> {
            // Only branch targets and RIP-relative operands are addresses.
            if ins.flow_control() == iced_x86::FlowControl::Next && !ins.is_ip_rel_memory_operand() {
                return None;
            }
            let i = self.0.partition_point(|s| s.0 <= address).checked_sub(1)?;
            let (a, sz, name) = &self.0[i];
            (address < a + (*sz).max(1)).then(|| SymbolResult::with_string(address, if address == *a { name.clone() } else { format!("{name}+{:#x}", address - a) }))
        }
    }
    let mut syms: Vec<(u64, u64, String)> = file
        .symbols()
        .chain(file.dynamic_symbols())
        .filter(|s| !s.is_undefined() && s.address() != 0 && s.name().is_ok_and(|n| !n.is_empty()))
        .map(|s| (s.address(), s.size(), s.name().unwrap_or("").to_string()))
        .collect();
    syms.sort_by_key(|s| s.0);
    let mut fmt = IntelFormatter::with_options(Some(Box::new(Syms(syms))), None);
    fmt.options_mut().set_first_operand_char_index(8);
    let mut dec = Decoder::with_ip(64, code, addr, DecoderOptions::NONE);
    let mut out = vec![];
    let mut s = String::new();
    while dec.can_decode() {
        let ins = dec.decode();
        s.clear();
        fmt.format(&ins, &mut s);
        out.push((ins.ip(), s.clone()));
    }
    Ok(out)
}
