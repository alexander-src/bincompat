use std::fmt::Write;

use crate::elf::{AttributedSymbol, BinaryAnalysis, Endianness};
use crate::policy::{Policy, PolicyEvaluation, Violation};

const SAMPLE_SYMBOL_LIMIT: usize = 6;

/// Renders a deterministic archival terminal summary for `bincompat scan`.
pub fn render_scan_text(path_label: &str, analysis: &BinaryAnalysis) -> String {
    let mut out = String::new();
    let endian = match analysis.endianness {
        Endianness::Little => "LE",
        Endianness::Big => "BE",
    };

    let _ = writeln!(out, "bincompat scan: {path_label}");
    let _ = writeln!(
        out,
        "  elf           : {} ({}, ELF64-{})",
        analysis.elf_type, analysis.machine, endian
    );
    let _ = writeln!(
        out,
        "  linking       : {}",
        if analysis.is_dynamic {
            "dynamic"
        } else {
            "static"
        }
    );
    if let Some(interp) = &analysis.interpreter {
        let _ = writeln!(out, "  interpreter   : {interp}");
    }
    if let Some(soname) = &analysis.soname {
        let _ = writeln!(out, "  soname        : {soname}");
    }
    if let Some(rpath) = &analysis.rpath {
        let _ = writeln!(out, "  rpath         : {rpath}");
    }
    if let Some(runpath) = &analysis.runpath {
        let _ = writeln!(out, "  runpath       : {runpath}");
    }
    let _ = writeln!(
        out,
        "  needed        : {}",
        if analysis.needed.is_empty() {
            "(none)".to_string()
        } else {
            analysis.needed.join(", ")
        }
    );

    if analysis.max_versions.is_empty() {
        let _ = writeln!(out, "  max-versions  : (none)");
    } else {
        let summary = analysis
            .max_versions
            .iter()
            .map(|(k, v)| format!("{k}_{v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "  max-versions  : {summary}");
    }

    if !analysis.abi_tags.is_empty() {
        let tags = analysis
            .abi_tags
            .iter()
            .map(|t| format!("{} ({})", t.tag, t.library))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "  abi-tags      : {tags}");
    }

    if !analysis.requirements.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Symbol Version Requirements:");
        let _ = writeln!(
            out,
            "  {:<24} {:<24} {:>7}  SYMBOLS",
            "LIBRARY", "VERSION", "COUNT"
        );
        let _ = writeln!(out, "  {}", "-".repeat(78));
        for req in &analysis.requirements {
            let preview = format_symbol_preview(&req.symbols, SAMPLE_SYMBOL_LIMIT);
            let _ = writeln!(
                out,
                "  {:<24} {:<24} {:>7}  {}",
                req.library,
                req.raw_tag,
                req.symbols.len(),
                preview
            );
        }
    }

    out
}

/// Renders a deterministic CI gate report for `bincompat check`.
pub fn render_check_text(
    path_label: &str,
    analysis: &BinaryAnalysis,
    policy: &Policy,
    eval: &PolicyEvaluation,
) -> String {
    let mut out = render_scan_text(path_label, analysis);
    let _ = writeln!(out);

    let mut rules = Vec::new();
    for (family, max_ver) in &policy.max_versions {
        rules.push(format!("{family}<={max_ver}"));
    }
    for tag in &policy.forbid_abi_tags {
        rules.push(format!("forbid-abi-tag={tag}"));
    }
    if policy.forbid_rpath {
        rules.push("forbid-rpath".to_string());
    }
    let rules_str = if rules.is_empty() {
        "(none)".to_string()
    } else {
        rules.join(", ")
    };

    if eval.passed {
        let _ = writeln!(out, "Policy Status: PASS (rules: {rules_str})");
        return out;
    }

    let _ = writeln!(
        out,
        "Policy Status: FAIL (rules: {rules_str}, violations: {})",
        eval.violations.len()
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Violations:");
    for violation in &eval.violations {
        match violation {
            Violation::VersionExceeded {
                library,
                family,
                raw_tag,
                required,
                max_allowed,
                symbols,
            } => {
                let _ = writeln!(
                    out,
                    "  [VERSION] {raw_tag} ({library}) exceeds max {family} {max_allowed} (found {required}, {} symbol(s)):",
                    symbols.len()
                );
                if symbols.is_empty() {
                    let _ = writeln!(
                        out,
                        "    - (referenced in .gnu.version_r with no undefined .dynsym symbols)"
                    );
                } else {
                    for sym in symbols {
                        let _ = writeln!(out, "    - {}", format_symbol_entry(sym, raw_tag));
                    }
                }
            }
            Violation::ForbiddenAbiTag {
                library,
                tag,
                symbols,
            } => {
                let _ = writeln!(
                    out,
                    "  [ABI-TAG] forbidden tag {tag} required by {library} ({} symbol(s))",
                    symbols.len()
                );
                for sym in symbols {
                    let _ = writeln!(out, "    - {}", format_symbol_entry(sym, tag));
                }
            }
            Violation::ForbiddenRpath { kind, value } => {
                let _ = writeln!(out, "  [RPATH] forbidden {kind} entry present: {value}");
            }
        }
    }

    out
}

fn format_symbol_entry(sym: &AttributedSymbol, tag: &str) -> String {
    let mut flags = Vec::new();
    if sym.is_weak {
        flags.push("weak");
    }
    if sym.is_hidden {
        flags.push("hidden");
    }
    if flags.is_empty() {
        format!("{}@{tag}", sym.name)
    } else {
        format!("{}@{tag} [{}]", sym.name, flags.join(", "))
    }
}

fn format_symbol_preview(symbols: &[AttributedSymbol], limit: usize) -> String {
    if symbols.is_empty() {
        return "(tag-only)".to_string();
    }
    let shown: Vec<String> = symbols
        .iter()
        .take(limit)
        .map(|s| {
            if s.is_weak {
                format!("{} (weak)", s.name)
            } else {
                s.name.clone()
            }
        })
        .collect();
    if symbols.len() > limit {
        format!("{}, +{} more", shown.join(", "), symbols.len() - limit)
    } else {
        shown.join(", ")
    }
}
