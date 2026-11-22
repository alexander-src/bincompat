use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::error::{BincompatError, Result};
use crate::version::{Version, VersionTag};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_MIN_SIZE: usize = 56;
const ELF64_SHDR_MIN_SIZE: usize = 64;
const ELF64_DYN_SIZE: usize = 16;
const ELF64_SYM_SIZE: usize = 24;
const ELF64_VERNEED_SIZE: usize = 16;
const ELF64_VERNAUX_SIZE: usize = 16;

const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const ET_CORE: u16 = 4;

const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;

const PF_X: u32 = 0x1;

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

const SHN_UNDEF: u16 = 0;
const SHN_XINDEX: u16 = 0xffff;

const STB_WEAK: u8 = 2;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_BIND_NOW: i64 = 24;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6fff_fffb;

const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;
const DF_1_PIE: u64 = 0x0800_0000;

const VERSYM_HIDDEN_MASK: u16 = 0x8000;
const VERSYM_VERSION_MASK: u16 = 0x7fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

impl Endianness {
    fn read_u16(self, bytes: &[u8], offset: usize) -> Option<u16> {
        let end = offset.checked_add(2)?;
        let raw: [u8; 2] = bytes.get(offset..end)?.try_into().ok()?;
        Some(match self {
            Self::Little => u16::from_le_bytes(raw),
            Self::Big => u16::from_be_bytes(raw),
        })
    }

    fn read_u32(self, bytes: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(4)?;
        let raw: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
        Some(match self {
            Self::Little => u32::from_le_bytes(raw),
            Self::Big => u32::from_be_bytes(raw),
        })
    }

    fn read_u64(self, bytes: &[u8], offset: usize) -> Option<u64> {
        let end = offset.checked_add(8)?;
        let raw: [u8; 8] = bytes.get(offset..end)?.try_into().ok()?;
        Some(match self {
            Self::Little => u64::from_le_bytes(raw),
            Self::Big => u64::from_be_bytes(raw),
        })
    }

    fn read_i64(self, bytes: &[u8], offset: usize) -> Option<i64> {
        let end = offset.checked_add(8)?;
        let raw: [u8; 8] = bytes.get(offset..end)?.try_into().ok()?;
        Some(match self {
            Self::Little => i64::from_le_bytes(raw),
            Self::Big => i64::from_be_bytes(raw),
        })
    }
}

/// Undefined dynamic symbol attributed to a GNU symbol version requirement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttributedSymbol {
    pub name: String,
    pub is_weak: bool,
    pub is_hidden: bool,
}

/// A single version requirement from `.gnu.version_r` (`Elf64_Vernaux`)
/// joined with all undefined `.dynsym` symbols that reference it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRequirement {
    pub library: String,
    pub raw_tag: String,
    pub parsed: VersionTag,
    pub version_index: u16,
    pub symbols: Vec<AttributedSymbol>,
}

/// Non-numeric ABI feature or private tag requirement (for example `GLIBC_ABI_DT_RELR`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AbiTagRequirement {
    pub library: String,
    pub tag: String,
    pub symbol_count: usize,
}

/// Position-independent execution status derived from `e_type`, `PT_INTERP`,
/// `DT_SONAME`, and `DF_1_PIE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieStatus {
    Pie,
    Dso,
    NoPie,
    NotApplicable,
}

impl PieStatus {
    pub fn is_position_independent(self) -> bool {
        matches!(self, Self::Pie | Self::Dso)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pie => "pie",
            Self::Dso => "dso",
            Self::NoPie => "no-pie",
            Self::NotApplicable => "n/a",
        }
    }
}

/// Relocation read-only (RELRO) protection level derived from `PT_GNU_RELRO`
/// and eager-binding dynamic tags (`DT_BIND_NOW`, `DF_BIND_NOW`, `DF_1_NOW`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelroStatus {
    None,
    Partial,
    Full,
}

impl RelroStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Partial => "partial",
            Self::Full => "full",
        }
    }
}

/// Non-executable stack (NX) status derived from `PT_GNU_STACK` (`p_flags & PF_X`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NxStatus {
    Enabled,
    Disabled,
    Missing,
}

impl NxStatus {
    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Missing => "missing",
        }
    }
}

/// Binary security hardening summary extracted from ELF64 headers and symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    pub pie: PieStatus,
    pub relro: RelroStatus,
    pub nx: NxStatus,
    pub stack_canary: bool,
}

/// Complete portability and hardening analysis for an ELF64 binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryAnalysis {
    pub elf_type: String,
    pub machine: String,
    pub endianness: Endianness,
    pub is_dynamic: bool,
    pub interpreter: Option<String>,
    pub soname: Option<String>,
    pub needed: Vec<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub dt_flags: u64,
    pub dt_flags_1: u64,
    pub hardening: HardeningReport,
    pub dynsym_count: usize,
    pub requirements: Vec<VersionRequirement>,
    pub max_versions: BTreeMap<String, Version>,
    pub abi_tags: Vec<AbiTagRequirement>,
}

#[derive(Debug, Default)]
struct ProgramHeaderInfo {
    interpreter: Option<String>,
    has_gnu_relro: bool,
    gnu_stack_flags: Option<u32>,
}

#[derive(Debug, Default)]
struct DynamicInfo {
    soname: Option<String>,
    needed: Vec<String>,
    rpath: Option<String>,
    runpath: Option<String>,
    dt_flags: u64,
    dt_flags_1: u64,
    has_dt_bind_now: bool,
}

#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}

/// Reads and analyzes an ELF64 binary from disk.
pub fn analyze_file(path: &Path) -> Result<BinaryAnalysis> {
    let bytes = fs::read(path).map_err(|source| BincompatError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    analyze_bytes(&bytes)
}

/// Analyzes an ELF64 binary from an in-memory byte slice.
pub fn analyze_bytes(bytes: &[u8]) -> Result<BinaryAnalysis> {
    if bytes.len() < ELF64_EHDR_SIZE {
        return Err(BincompatError::InvalidElf(format!(
            "file is {} bytes, smaller than 64-byte ELF64 header",
            bytes.len()
        )));
    }
    if bytes[0..4] != ELF_MAGIC {
        return Err(BincompatError::InvalidElf(
            "missing 0x7F 'E' 'L' 'F' magic header".to_string(),
        ));
    }

    let ei_class = bytes[4];
    if ei_class != ELFCLASS64 {
        return Err(BincompatError::UnsupportedClass(ei_class));
    }
    let endian = match bytes[5] {
        ELFDATA2LSB => Endianness::Little,
        ELFDATA2MSB => Endianness::Big,
        other => return Err(BincompatError::UnsupportedEndianness(other)),
    };

    let e_type = read_u16_or(endian, bytes, 16, "e_type")?;
    let e_machine = read_u16_or(endian, bytes, 18, "e_machine")?;
    let e_phoff = read_u64_or(endian, bytes, 32, "e_phoff")?;
    let e_shoff = read_u64_or(endian, bytes, 40, "e_shoff")?;
    let e_phentsize = read_u16_or(endian, bytes, 54, "e_phentsize")?;
    let e_phnum = read_u16_or(endian, bytes, 56, "e_phnum")?;
    let e_shentsize = read_u16_or(endian, bytes, 58, "e_shentsize")?;
    let e_shnum_raw = read_u16_or(endian, bytes, 60, "e_shnum")?;

    let phdrs = parse_program_headers(bytes, endian, e_phoff, e_phentsize, e_phnum)?;
    let sections = parse_section_headers(bytes, endian, e_shoff, e_shentsize, e_shnum_raw)?;

    let mut is_dynamic = false;
    let mut dynamic_info = DynamicInfo::default();

    if let Some(dyn_shdr) = sections.iter().find(|s| s.sh_type == SHT_DYNAMIC) {
        is_dynamic = true;
        let dyn_bytes = section_slice(bytes, dyn_shdr, "SHT_DYNAMIC")?;
        let strtab = linked_strtab(bytes, &sections, dyn_shdr.sh_link, "SHT_DYNAMIC")?;
        dynamic_info = parse_dynamic_section(dyn_bytes, strtab, endian)?;
    }

    let mut requirements = Vec::new();
    let mut idx_to_req: BTreeMap<u16, usize> = BTreeMap::new();

    if let Some(verneed_shdr) = sections.iter().find(|s| s.sh_type == SHT_GNU_VERNEED) {
        let verneed_bytes = section_slice(bytes, verneed_shdr, "SHT_GNU_VERNEED")?;
        let strtab = linked_strtab(bytes, &sections, verneed_shdr.sh_link, "SHT_GNU_VERNEED")?;
        parse_verneed_section(
            verneed_bytes,
            strtab,
            endian,
            &mut requirements,
            &mut idx_to_req,
        )?;
    }

    let mut dynsym_count = 0usize;
    let mut stack_canary = false;
    if let Some(dynsym_shdr) = sections.iter().find(|s| s.sh_type == SHT_DYNSYM) {
        let dynsym_bytes = section_slice(bytes, dynsym_shdr, "SHT_DYNSYM")?;
        let stride = checked_sym_stride(dynsym_shdr.sh_entsize, "SHT_DYNSYM")?;
        if dynsym_bytes.len() % stride != 0 {
            return Err(BincompatError::CorruptSection(format!(
                "SHT_DYNSYM size {} is not a multiple of entry size {}",
                dynsym_bytes.len(),
                stride
            )));
        }
        dynsym_count = dynsym_bytes.len() / stride;
        let strtab = linked_strtab(bytes, &sections, dynsym_shdr.sh_link, "SHT_DYNSYM")?;

        if has_canary_symbol(dynsym_bytes, stride, dynsym_count, strtab, endian, true)? {
            stack_canary = true;
        }

        if let Some(versym_shdr) = sections.iter().find(|s| s.sh_type == SHT_GNU_VERSYM) {
            let versym_bytes = section_slice(bytes, versym_shdr, "SHT_GNU_VERSYM")?;
            attribute_dynsym_versions(
                dynsym_bytes,
                stride,
                dynsym_count,
                strtab,
                versym_bytes,
                endian,
                &idx_to_req,
                &mut requirements,
            )?;
        }
    }

    if !stack_canary {
        if let Some(symtab_shdr) = sections.iter().find(|s| s.sh_type == SHT_SYMTAB) {
            let symtab_bytes = section_slice(bytes, symtab_shdr, "SHT_SYMTAB")?;
            let stride = checked_sym_stride(symtab_shdr.sh_entsize, "SHT_SYMTAB")?;
            if symtab_bytes.len() % stride != 0 {
                return Err(BincompatError::CorruptSection(format!(
                    "SHT_SYMTAB size {} is not a multiple of entry size {}",
                    symtab_bytes.len(),
                    stride
                )));
            }
            let sym_count = symtab_bytes.len() / stride;
            let strtab = linked_strtab(bytes, &sections, symtab_shdr.sh_link, "SHT_SYMTAB")?;
            if has_canary_symbol(symtab_bytes, stride, sym_count, strtab, endian, false)? {
                stack_canary = true;
            }
        }
    }

    let hardening = HardeningReport {
        pie: compute_pie_status(
            e_type,
            phdrs.interpreter.as_deref(),
            dynamic_info.soname.as_deref(),
            dynamic_info.dt_flags_1,
        ),
        relro: compute_relro_status(
            phdrs.has_gnu_relro,
            dynamic_info.has_dt_bind_now,
            dynamic_info.dt_flags,
            dynamic_info.dt_flags_1,
        ),
        nx: compute_nx_status(phdrs.gnu_stack_flags),
        stack_canary,
    };

    for req in &mut requirements {
        req.symbols.sort();
        req.symbols.dedup();
    }

    requirements.sort_by(|a, b| {
        a.library
            .cmp(&b.library)
            .then_with(|| match (&a.parsed, &b.parsed) {
                (
                    VersionTag::Versioned {
                        family: fa,
                        version: va,
                    },
                    VersionTag::Versioned {
                        family: fb,
                        version: vb,
                    },
                ) => fa.cmp(fb).then_with(|| vb.cmp(va)),
                (VersionTag::Versioned { .. }, VersionTag::AbiTag { .. }) => {
                    std::cmp::Ordering::Less
                }
                (VersionTag::AbiTag { .. }, VersionTag::Versioned { .. }) => {
                    std::cmp::Ordering::Greater
                }
                (VersionTag::AbiTag { raw: ra }, VersionTag::AbiTag { raw: rb }) => ra.cmp(rb),
            })
            .then_with(|| a.raw_tag.cmp(&b.raw_tag))
    });

    let mut max_versions: BTreeMap<String, Version> = BTreeMap::new();
    let mut abi_tags: Vec<AbiTagRequirement> = Vec::new();
    for req in &requirements {
        match &req.parsed {
            VersionTag::Versioned { family, version } => {
                max_versions
                    .entry(family.clone())
                    .and_modify(|cur| {
                        if version > cur {
                            *cur = version.clone();
                        }
                    })
                    .or_insert_with(|| version.clone());
            }
            VersionTag::AbiTag { raw } => {
                abi_tags.push(AbiTagRequirement {
                    library: req.library.clone(),
                    tag: raw.clone(),
                    symbol_count: req.symbols.len(),
                });
            }
        }
    }
    abi_tags.sort();
    abi_tags.dedup();

    Ok(BinaryAnalysis {
        elf_type: format_elf_type(e_type),
        machine: format_machine(e_machine),
        endianness: endian,
        is_dynamic,
        interpreter: phdrs.interpreter,
        soname: dynamic_info.soname,
        needed: dynamic_info.needed,
        rpath: dynamic_info.rpath,
        runpath: dynamic_info.runpath,
        dt_flags: dynamic_info.dt_flags,
        dt_flags_1: dynamic_info.dt_flags_1,
        hardening,
        dynsym_count,
        requirements,
        max_versions,
        abi_tags,
    })
}

fn checked_sym_stride(sh_entsize: u64, label: &str) -> Result<usize> {
    let entsize = usize::try_from(sh_entsize).map_err(|_| {
        BincompatError::CorruptSection(format!("{label} sh_entsize overflows usize"))
    })?;
    if entsize == 0 {
        Ok(ELF64_SYM_SIZE)
    } else if entsize < ELF64_SYM_SIZE {
        Err(BincompatError::CorruptSection(format!(
            "{label} sh_entsize {entsize} is smaller than {ELF64_SYM_SIZE}"
        )))
    } else {
        Ok(entsize)
    }
}

fn is_stack_canary_symbol(name: &str) -> bool {
    matches!(
        name,
        "__stack_chk_fail"
            | "__stack_chk_fail_local"
            | "__stack_chk_guard"
            | "__intel_security_cookie"
    )
}

fn has_canary_symbol(
    sym_bytes: &[u8],
    stride: usize,
    sym_count: usize,
    strtab: &[u8],
    endian: Endianness,
    undef_only: bool,
) -> Result<bool> {
    for i in 1..sym_count {
        let sym_off = i * stride;
        let st_name = endian.read_u32(sym_bytes, sym_off).ok_or_else(|| {
            BincompatError::CorruptSection("truncated Elf64_Sym.st_name".to_string())
        })?;
        let st_shndx = endian.read_u16(sym_bytes, sym_off + 6).ok_or_else(|| {
            BincompatError::CorruptSection("truncated Elf64_Sym.st_shndx".to_string())
        })?;
        if undef_only && st_shndx != SHN_UNDEF {
            continue;
        }
        if st_name == 0 {
            continue;
        }
        let name = read_cstr(strtab, u64::from(st_name), "Elf64_Sym.st_name")?;
        if is_stack_canary_symbol(&name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn compute_pie_status(
    e_type: u16,
    interpreter: Option<&str>,
    soname: Option<&str>,
    dt_flags_1: u64,
) -> PieStatus {
    match e_type {
        ET_DYN => {
            if (dt_flags_1 & DF_1_PIE) != 0 || (interpreter.is_some() && soname.is_none()) {
                PieStatus::Pie
            } else {
                PieStatus::Dso
            }
        }
        ET_EXEC => PieStatus::NoPie,
        _ => PieStatus::NotApplicable,
    }
}

fn compute_relro_status(
    has_gnu_relro: bool,
    has_dt_bind_now: bool,
    dt_flags: u64,
    dt_flags_1: u64,
) -> RelroStatus {
    if !has_gnu_relro {
        RelroStatus::None
    } else if has_dt_bind_now || (dt_flags & DF_BIND_NOW) != 0 || (dt_flags_1 & DF_1_NOW) != 0 {
        RelroStatus::Full
    } else {
        RelroStatus::Partial
    }
}

fn compute_nx_status(gnu_stack_flags: Option<u32>) -> NxStatus {
    match gnu_stack_flags {
        Some(flags) if (flags & PF_X) == 0 => NxStatus::Enabled,
        Some(_) => NxStatus::Disabled,
        None => NxStatus::Missing,
    }
}

fn read_u16_or(endian: Endianness, bytes: &[u8], off: usize, field: &str) -> Result<u16> {
    endian
        .read_u16(bytes, off)
        .ok_or_else(|| BincompatError::InvalidElf(format!("truncated header field {field}")))
}

fn read_u64_or(endian: Endianness, bytes: &[u8], off: usize, field: &str) -> Result<u64> {
    endian
        .read_u64(bytes, off)
        .ok_or_else(|| BincompatError::InvalidElf(format!("truncated header field {field}")))
}

fn parse_program_headers(
    bytes: &[u8],
    endian: Endianness,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
) -> Result<ProgramHeaderInfo> {
    let mut info = ProgramHeaderInfo::default();
    if e_phnum == 0 || e_phoff == 0 {
        return Ok(info);
    }
    let entsize = usize::from(e_phentsize);
    if entsize < ELF64_PHDR_MIN_SIZE {
        return Err(BincompatError::InvalidElf(format!(
            "program header entry size {entsize} is smaller than {ELF64_PHDR_MIN_SIZE}"
        )));
    }
    let phoff = usize::try_from(e_phoff)
        .map_err(|_| BincompatError::InvalidElf("e_phoff overflows usize".to_string()))?;
    let phnum = usize::from(e_phnum);
    let total = phnum
        .checked_mul(entsize)
        .and_then(|sz| phoff.checked_add(sz))
        .ok_or_else(|| BincompatError::InvalidElf("program header table overflows".to_string()))?;
    if total > bytes.len() {
        return Err(BincompatError::InvalidElf(format!(
            "program header table end {total} exceeds file size {}",
            bytes.len()
        )));
    }

    for i in 0..phnum {
        let base = phoff + i * entsize;
        let p_type = endian
            .read_u32(bytes, base)
            .ok_or_else(|| BincompatError::InvalidElf("truncated program header".to_string()))?;
        let p_flags = endian.read_u32(bytes, base + 4).ok_or_else(|| {
            BincompatError::InvalidElf("truncated program header p_flags".to_string())
        })?;

        match p_type {
            PT_INTERP => {
                let p_offset = endian.read_u64(bytes, base + 8).ok_or_else(|| {
                    BincompatError::InvalidElf("truncated PT_INTERP p_offset".to_string())
                })?;
                let p_filesz = endian.read_u64(bytes, base + 32).ok_or_else(|| {
                    BincompatError::InvalidElf("truncated PT_INTERP p_filesz".to_string())
                })?;
                let start = usize::try_from(p_offset).map_err(|_| {
                    BincompatError::InvalidElf("PT_INTERP offset overflows usize".to_string())
                })?;
                let len = usize::try_from(p_filesz).map_err(|_| {
                    BincompatError::InvalidElf("PT_INTERP size overflows usize".to_string())
                })?;
                let end = start.checked_add(len).ok_or_else(|| {
                    BincompatError::InvalidElf("PT_INTERP range overflows".to_string())
                })?;
                let slice = bytes.get(start..end).ok_or_else(|| {
                    BincompatError::InvalidElf("PT_INTERP exceeds file bounds".to_string())
                })?;
                let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                if info.interpreter.is_none() {
                    info.interpreter =
                        Some(String::from_utf8_lossy(&slice[..nul_pos]).into_owned());
                }
            }
            PT_GNU_RELRO => {
                info.has_gnu_relro = true;
            }
            PT_GNU_STACK => {
                info.gnu_stack_flags = Some(p_flags);
            }
            _ => {}
        }
    }
    Ok(info)
}

fn parse_section_headers(
    bytes: &[u8],
    endian: Endianness,
    e_shoff: u64,
    e_shentsize: u16,
    e_shnum_raw: u16,
) -> Result<Vec<SectionHeader>> {
    if e_shoff == 0 {
        return Ok(Vec::new());
    }
    let entsize = usize::from(e_shentsize);
    if entsize < ELF64_SHDR_MIN_SIZE {
        return Err(BincompatError::CorruptSection(format!(
            "section header entry size {entsize} is smaller than {ELF64_SHDR_MIN_SIZE}"
        )));
    }
    let shoff = usize::try_from(e_shoff)
        .map_err(|_| BincompatError::CorruptSection("e_shoff overflows usize".to_string()))?;

    let shnum = if e_shnum_raw == 0 {
        let first_end = shoff.checked_add(entsize).ok_or_else(|| {
            BincompatError::CorruptSection("section 0 header overflows".to_string())
        })?;
        if first_end > bytes.len() {
            return Err(BincompatError::CorruptSection(
                "truncated section 0 header for extended section count".to_string(),
            ));
        }
        let ext_shnum = endian.read_u64(bytes, shoff + 32).ok_or_else(|| {
            BincompatError::CorruptSection("truncated section 0 sh_size".to_string())
        })?;
        usize::try_from(ext_shnum).map_err(|_| {
            BincompatError::CorruptSection("extended shnum overflows usize".to_string())
        })?
    } else if e_shnum_raw == SHN_XINDEX {
        return Err(BincompatError::CorruptSection(
            "unexpected SHN_XINDEX in e_shnum".to_string(),
        ));
    } else {
        usize::from(e_shnum_raw)
    };

    let total = shnum
        .checked_mul(entsize)
        .and_then(|sz| shoff.checked_add(sz))
        .ok_or_else(|| BincompatError::CorruptSection("section table overflows".to_string()))?;
    if total > bytes.len() {
        return Err(BincompatError::CorruptSection(format!(
            "section header table end {total} exceeds file size {}",
            bytes.len()
        )));
    }

    let mut sections = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let base = shoff + i * entsize;
        let sh_type = endian
            .read_u32(bytes, base + 4)
            .ok_or_else(|| BincompatError::CorruptSection("truncated sh_type".to_string()))?;
        let sh_offset = endian
            .read_u64(bytes, base + 24)
            .ok_or_else(|| BincompatError::CorruptSection("truncated sh_offset".to_string()))?;
        let sh_size = endian
            .read_u64(bytes, base + 32)
            .ok_or_else(|| BincompatError::CorruptSection("truncated sh_size".to_string()))?;
        let sh_link = endian
            .read_u32(bytes, base + 40)
            .ok_or_else(|| BincompatError::CorruptSection("truncated sh_link".to_string()))?;
        let sh_entsize = endian
            .read_u64(bytes, base + 56)
            .ok_or_else(|| BincompatError::CorruptSection("truncated sh_entsize".to_string()))?;
        sections.push(SectionHeader {
            sh_type,
            sh_offset,
            sh_size,
            sh_link,
            sh_entsize,
        });
    }
    Ok(sections)
}

fn section_slice<'a>(bytes: &'a [u8], shdr: &SectionHeader, label: &str) -> Result<&'a [u8]> {
    if shdr.sh_type == SHT_NOBITS {
        return Err(BincompatError::CorruptSection(format!(
            "{label} unexpectedly has type SHT_NOBITS"
        )));
    }
    let start = usize::try_from(shdr.sh_offset)
        .map_err(|_| BincompatError::CorruptSection(format!("{label} offset overflows usize")))?;
    let len = usize::try_from(shdr.sh_size)
        .map_err(|_| BincompatError::CorruptSection(format!("{label} size overflows usize")))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| BincompatError::CorruptSection(format!("{label} range overflows")))?;
    bytes.get(start..end).ok_or_else(|| {
        BincompatError::CorruptSection(format!(
            "{label} range {start}..{end} exceeds file size {}",
            bytes.len()
        ))
    })
}

fn linked_strtab<'a>(
    bytes: &'a [u8],
    sections: &[SectionHeader],
    sh_link: u32,
    owner: &str,
) -> Result<&'a [u8]> {
    let link_idx = usize::try_from(sh_link)
        .map_err(|_| BincompatError::CorruptSection(format!("{owner} sh_link overflows usize")))?;
    let shdr = sections.get(link_idx).ok_or_else(|| {
        BincompatError::CorruptSection(format!(
            "{owner} sh_link {link_idx} out of range (sections: {})",
            sections.len()
        ))
    })?;
    if shdr.sh_type != SHT_STRTAB {
        return Err(BincompatError::CorruptSection(format!(
            "{owner} linked section {link_idx} is not SHT_STRTAB (type {})",
            shdr.sh_type
        )));
    }
    section_slice(bytes, shdr, "SHT_STRTAB")
}

fn read_cstr(strtab: &[u8], offset: u64, context: &str) -> Result<String> {
    let start = usize::try_from(offset)
        .map_err(|_| BincompatError::CorruptSection(format!("{context} string offset overflow")))?;
    let tail = strtab.get(start..).ok_or_else(|| {
        BincompatError::CorruptSection(format!(
            "{context} string offset {start} exceeds string table size {}",
            strtab.len()
        ))
    })?;
    let nul_pos = tail.iter().position(|&b| b == 0).ok_or_else(|| {
        BincompatError::CorruptSection(format!(
            "{context} string at offset {start} is unterminated"
        ))
    })?;
    Ok(String::from_utf8_lossy(&tail[..nul_pos]).into_owned())
}

fn parse_dynamic_section(
    dyn_bytes: &[u8],
    strtab: &[u8],
    endian: Endianness,
) -> Result<DynamicInfo> {
    if dyn_bytes.len() % ELF64_DYN_SIZE != 0 {
        return Err(BincompatError::CorruptDynamic(format!(
            "SHT_DYNAMIC size {} is not a multiple of {ELF64_DYN_SIZE}",
            dyn_bytes.len()
        )));
    }
    let mut info = DynamicInfo::default();
    let mut off = 0usize;
    while off < dyn_bytes.len() {
        let d_tag = endian
            .read_i64(dyn_bytes, off)
            .ok_or_else(|| BincompatError::CorruptDynamic("truncated d_tag".to_string()))?;
        let d_val = endian
            .read_u64(dyn_bytes, off + 8)
            .ok_or_else(|| BincompatError::CorruptDynamic("truncated d_val".to_string()))?;
        off += ELF64_DYN_SIZE;

        match d_tag {
            DT_NULL => break,
            DT_NEEDED => {
                let lib = read_cstr(strtab, d_val, "DT_NEEDED")?;
                if !info.needed.contains(&lib) {
                    info.needed.push(lib);
                }
            }
            DT_SONAME => info.soname = Some(read_cstr(strtab, d_val, "DT_SONAME")?),
            DT_RPATH => info.rpath = Some(read_cstr(strtab, d_val, "DT_RPATH")?),
            DT_BIND_NOW => info.has_dt_bind_now = true,
            DT_RUNPATH => info.runpath = Some(read_cstr(strtab, d_val, "DT_RUNPATH")?),
            DT_FLAGS => info.dt_flags |= d_val,
            DT_FLAGS_1 => info.dt_flags_1 |= d_val,
            _ => {}
        }
    }
    Ok(info)
}

fn parse_verneed_section(
    verneed_bytes: &[u8],
    strtab: &[u8],
    endian: Endianness,
    requirements: &mut Vec<VersionRequirement>,
    idx_to_req: &mut BTreeMap<u16, usize>,
) -> Result<()> {
    if verneed_bytes.is_empty() {
        return Ok(());
    }

    let mut visited_verneed = BTreeSet::new();
    let mut visited_aux = BTreeSet::new();
    let mut vn_off = 0usize;

    loop {
        if !visited_verneed.insert(vn_off) {
            return Err(BincompatError::CorruptVerneed(format!(
                "cycle detected in Elf64_Verneed chain at offset {vn_off}"
            )));
        }
        let vn_end = vn_off.checked_add(ELF64_VERNEED_SIZE).ok_or_else(|| {
            BincompatError::CorruptVerneed("Elf64_Verneed offset overflow".to_string())
        })?;
        if vn_end > verneed_bytes.len() {
            return Err(BincompatError::CorruptVerneed(format!(
                "Elf64_Verneed at offset {vn_off} exceeds section size {}",
                verneed_bytes.len()
            )));
        }

        let vn_version = endian.read_u16(verneed_bytes, vn_off).unwrap();
        let vn_cnt = endian.read_u16(verneed_bytes, vn_off + 2).unwrap();
        let vn_file = endian.read_u32(verneed_bytes, vn_off + 4).unwrap();
        let vn_aux = endian.read_u32(verneed_bytes, vn_off + 8).unwrap();
        let vn_next = endian.read_u32(verneed_bytes, vn_off + 12).unwrap();

        if vn_version != 1 {
            return Err(BincompatError::CorruptVerneed(format!(
                "unsupported Elf64_Verneed version {vn_version} at offset {vn_off}"
            )));
        }

        let library = read_cstr(strtab, u64::from(vn_file), "Elf64_Verneed.vn_file")?;

        if vn_cnt > 0 {
            let mut aux_off = vn_off.checked_add(vn_aux as usize).ok_or_else(|| {
                BincompatError::CorruptVerneed("Elf64_Verneed.vn_aux overflow".to_string())
            })?;
            for aux_idx in 0..vn_cnt {
                if !visited_aux.insert(aux_off) {
                    return Err(BincompatError::CorruptVerneed(format!(
                        "cycle detected in Elf64_Vernaux chain at offset {aux_off}"
                    )));
                }
                let aux_end = aux_off.checked_add(ELF64_VERNAUX_SIZE).ok_or_else(|| {
                    BincompatError::CorruptVerneed("Elf64_Vernaux offset overflow".to_string())
                })?;
                if aux_end > verneed_bytes.len() {
                    return Err(BincompatError::CorruptVerneed(format!(
                        "Elf64_Vernaux at offset {aux_off} exceeds section size {}",
                        verneed_bytes.len()
                    )));
                }

                let vna_other = endian.read_u16(verneed_bytes, aux_off + 6).unwrap();
                let vna_name = endian.read_u32(verneed_bytes, aux_off + 8).unwrap();
                let vna_next = endian.read_u32(verneed_bytes, aux_off + 12).unwrap();

                let version_index = vna_other & VERSYM_VERSION_MASK;
                let raw_tag = read_cstr(strtab, u64::from(vna_name), "Elf64_Vernaux.vna_name")?;
                let parsed = VersionTag::parse(&raw_tag);

                let pos = requirements.len();
                requirements.push(VersionRequirement {
                    library: library.clone(),
                    raw_tag,
                    parsed,
                    version_index,
                    symbols: Vec::new(),
                });
                if version_index >= 2 {
                    idx_to_req.insert(version_index, pos);
                }

                if aux_idx + 1 < vn_cnt {
                    if vna_next == 0 {
                        return Err(BincompatError::CorruptVerneed(format!(
                            "Elf64_Vernaux terminated early at entry {} of {}",
                            aux_idx + 1,
                            vn_cnt
                        )));
                    }
                    aux_off = aux_off.checked_add(vna_next as usize).ok_or_else(|| {
                        BincompatError::CorruptVerneed(
                            "Elf64_Vernaux.vna_next overflow".to_string(),
                        )
                    })?;
                }
            }
        }

        if vn_next == 0 {
            break;
        }
        vn_off = vn_off.checked_add(vn_next as usize).ok_or_else(|| {
            BincompatError::CorruptVerneed("Elf64_Verneed.vn_next overflow".to_string())
        })?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn attribute_dynsym_versions(
    dynsym_bytes: &[u8],
    stride: usize,
    dynsym_count: usize,
    strtab: &[u8],
    versym_bytes: &[u8],
    endian: Endianness,
    idx_to_req: &BTreeMap<u16, usize>,
    requirements: &mut [VersionRequirement],
) -> Result<()> {
    let expected_versym_bytes = dynsym_count.checked_mul(2).ok_or_else(|| {
        BincompatError::CorruptSection("SHT_GNU_VERSYM byte size overflow".to_string())
    })?;
    if versym_bytes.len() < expected_versym_bytes {
        return Err(BincompatError::CorruptSection(format!(
            "SHT_GNU_VERSYM has {} bytes, expected at least {} for {} dynsym entries",
            versym_bytes.len(),
            expected_versym_bytes,
            dynsym_count
        )));
    }

    for i in 1..dynsym_count {
        let sym_off = i * stride;
        let st_name = endian.read_u32(dynsym_bytes, sym_off).ok_or_else(|| {
            BincompatError::CorruptSection("truncated Elf64_Sym.st_name".to_string())
        })?;
        let st_info = dynsym_bytes[sym_off + 4];
        let st_shndx = endian.read_u16(dynsym_bytes, sym_off + 6).ok_or_else(|| {
            BincompatError::CorruptSection("truncated Elf64_Sym.st_shndx".to_string())
        })?;

        if st_shndx != SHN_UNDEF {
            continue;
        }

        let raw_vs = endian.read_u16(versym_bytes, i * 2).ok_or_else(|| {
            BincompatError::CorruptSection("truncated SHT_GNU_VERSYM entry".to_string())
        })?;
        let ver_index = raw_vs & VERSYM_VERSION_MASK;
        let is_hidden = (raw_vs & VERSYM_HIDDEN_MASK) != 0;

        if ver_index < 2 {
            continue;
        }
        if let Some(&req_pos) = idx_to_req.get(&ver_index) {
            let name = read_cstr(strtab, u64::from(st_name), "Elf64_Sym.st_name")?;
            if name.is_empty() {
                continue;
            }
            let bind = st_info >> 4;
            requirements[req_pos].symbols.push(AttributedSymbol {
                name,
                is_weak: bind == STB_WEAK,
                is_hidden,
            });
        }
    }

    Ok(())
}

fn format_elf_type(e_type: u16) -> String {
    match e_type {
        ET_REL => "ET_REL".to_string(),
        ET_EXEC => "ET_EXEC".to_string(),
        ET_DYN => "ET_DYN".to_string(),
        ET_CORE => "ET_CORE".to_string(),
        other => format!("ET_UNKNOWN({other})"),
    }
}

fn format_machine(e_machine: u16) -> String {
    match e_machine {
        3 => "x86".to_string(),
        20 => "powerpc".to_string(),
        21 => "powerpc64".to_string(),
        22 => "s390x".to_string(),
        40 => "arm".to_string(),
        62 => "x86-64".to_string(),
        183 => "aarch64".to_string(),
        243 => "riscv".to_string(),
        258 => "loongarch".to_string(),
        other => format!("EM_UNKNOWN({other})"),
    }
}
