use std::fmt::Write;

use crate::diff::{BinaryDiff, DiffRegression};
use crate::distro::{evaluate_distro_matrix, DistroCompatibility, DISTRO_BASELINES};
use crate::elf::{AttributedSymbol, BinaryAnalysis, Endianness, RelroStatus};
use crate::error::{BincompatError, Result};
use crate::policy::{Policy, PolicyEvaluation, Violation};

const SAMPLE_SYMBOL_LIMIT: usize = 6;
const VERSION_STR: &str = env!("CARGO_PKG_VERSION");
const TOOL_INFO_URI: &str = "https://github.com/alexander-src/bincompat";
const SARIF_SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// Output format supported across `scan`, `check`, and `diff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Markdown,
    Sarif,
}

impl OutputFormat {
    pub fn parse(spec: &str) -> Result<Self> {
        match spec.trim().to_ascii_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "markdown" | "md" => Ok(Self::Markdown),
            "sarif" => Ok(Self::Sarif),
            _ => Err(BincompatError::InvalidArgument(format!(
                "unknown --format '{spec}' (expected text, json, markdown, or sarif)"
            ))),
        }
    }
}

/// Renders `bincompat scan` output in the requested format.
pub fn render_scan(format: OutputFormat, path_label: &str, analysis: &BinaryAnalysis) -> String {
    match format {
        OutputFormat::Text => render_scan_text(path_label, analysis),
        OutputFormat::Json => render_scan_json(path_label, analysis),
        OutputFormat::Markdown => render_scan_markdown(path_label, analysis),
        OutputFormat::Sarif => render_scan_sarif(path_label, analysis),
    }
}

/// Renders `bincompat check` output in the requested format.
pub fn render_check(
    format: OutputFormat,
    path_label: &str,
    analysis: &BinaryAnalysis,
    policy: &Policy,
    eval: &PolicyEvaluation,
) -> String {
    match format {
        OutputFormat::Text => render_check_text(path_label, analysis, policy, eval),
        OutputFormat::Json => render_check_json(path_label, analysis, policy, eval),
        OutputFormat::Markdown => render_check_markdown(path_label, analysis, policy, eval),
        OutputFormat::Sarif => render_check_sarif(path_label, eval),
    }
}

/// Renders `bincompat diff` output in the requested format.
pub fn render_diff(
    format: OutputFormat,
    baseline_label: &str,
    candidate_label: &str,
    diff: &BinaryDiff,
) -> String {
    match format {
        OutputFormat::Text => render_diff_text(baseline_label, candidate_label, diff),
        OutputFormat::Json => render_diff_json(baseline_label, candidate_label, diff),
        OutputFormat::Markdown => render_diff_markdown(baseline_label, candidate_label, diff),
        OutputFormat::Sarif => render_diff_sarif(baseline_label, candidate_label, diff),
    }
}

/// Renders `bincompat targets` output in the requested format (`text`, `json`, or `markdown`).
pub fn render_targets(format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => {
            let mut out = String::new();
            let _ = writeln!(out, "bincompat targets (built-in Linux distro baselines)");
            let _ = writeln!(
                out,
                "  {:<14} {:<32} {:<8} {:<9} DT_RELR",
                "TARGET", "DISTRO", "GLIBC", "GLIBCXX"
            );
            for d in DISTRO_BASELINES {
                let _ = writeln!(
                    out,
                    "  {:<14} {:<32} {:<8} {:<9} {}",
                    d.id,
                    d.display_name,
                    d.glibc,
                    d.glibcxx,
                    if d.supports_dt_relr { "yes" } else { "no" }
                );
            }
            out
        }
        OutputFormat::Json => {
            let mut out = String::new();
            let _ = writeln!(out, "{{");
            let _ = writeln!(out, "  \"tool\": \"bincompat\",");
            let _ = writeln!(out, "  \"version\": {},", json_str(VERSION_STR));
            let _ = writeln!(out, "  \"targets\": [");
            for (idx, d) in DISTRO_BASELINES.iter().enumerate() {
                let comma = if idx + 1 < DISTRO_BASELINES.len() {
                    ","
                } else {
                    ""
                };
                let _ = writeln!(out, "    {{");
                let _ = writeln!(out, "      \"id\": {},", json_str(d.id));
                let _ = writeln!(out, "      \"display_name\": {},", json_str(d.display_name));
                let _ = writeln!(out, "      \"glibc\": {},", json_str(d.glibc));
                let _ = writeln!(out, "      \"glibcxx\": {},", json_str(d.glibcxx));
                let _ = writeln!(out, "      \"supports_dt_relr\": {}", d.supports_dt_relr);
                let _ = writeln!(out, "    }}{comma}");
            }
            let _ = writeln!(out, "  ]");
            let _ = writeln!(out, "}}");
            out
        }
        OutputFormat::Markdown | OutputFormat::Sarif => {
            let mut out = String::new();
            let _ = writeln!(out, "## bincompat targets\n");
            let _ = writeln!(out, "| Target | Distro | GLIBC | GLIBCXX | DT_RELR |");
            let _ = writeln!(out, "| :--- | :--- | :--- | :--- | :--- |");
            for d in DISTRO_BASELINES {
                let _ = writeln!(
                    out,
                    "| `{}` | {} | `{}` | `{}` | {} |",
                    d.id,
                    d.display_name,
                    d.glibc,
                    d.glibcxx,
                    if d.supports_dt_relr { "yes" } else { "no" }
                );
            }
            out
        }
    }
}

/// Renders a deterministic archival terminal summary for `bincompat scan`.
pub fn render_scan_text(path_label: &str, analysis: &BinaryAnalysis) -> String {
    let mut out = String::new();
    let endian = endian_label(analysis.endianness);

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
    let _ = writeln!(
        out,
        "  hardening     : PIE={}, RELRO={}, NX={}, canary={}",
        analysis.hardening.pie.as_str(),
        analysis.hardening.relro.as_str(),
        analysis.hardening.nx.as_str(),
        canary_label(analysis.hardening.stack_canary)
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

    let matrix = evaluate_distro_matrix(analysis);
    let _ = writeln!(out);
    let _ = writeln!(out, "Distro Compatibility:");
    let _ = writeln!(
        out,
        "  {:<18} {:<10} {:<12} STATUS",
        "TARGET", "GLIBC", "GLIBCXX"
    );
    let _ = writeln!(out, "  {}", "-".repeat(78));
    for entry in &matrix {
        let status = if entry.compatible {
            "OK".to_string()
        } else {
            format!("FAIL ({})", entry.reasons.join("; "))
        };
        let _ = writeln!(
            out,
            "  {:<18} {:<10} {:<12} {}",
            entry.baseline.display_name, entry.baseline.glibc, entry.baseline.glibcxx, status
        );
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

    let rules = policy_rule_labels(policy);
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
        write_violation_text(&mut out, violation);
    }

    out
}

fn write_violation_text(out: &mut String, violation: &Violation) {
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
        Violation::MissingPie { actual } => {
            let _ = writeln!(
                out,
                "  [HARDENING] PIE required, found {} (compile with -fPIE -pie)",
                actual.as_str()
            );
        }
        Violation::InsufficientRelro { actual, required } => {
            let hint = relro_hint(*required);
            let _ = writeln!(
                out,
                "  [HARDENING] RELRO={} required, found {} (link with {hint})",
                required.as_str(),
                actual.as_str()
            );
        }
        Violation::MissingNx { actual } => {
            let _ = writeln!(
                out,
                "  [HARDENING] NX stack required, found {} (link with -Wl,-z,noexecstack)",
                actual.as_str()
            );
        }
        Violation::MissingStackCanary => {
            let _ = writeln!(
                out,
                "  [HARDENING] stack canary required, no __stack_chk_fail/__stack_chk_guard reference found (compile with -fstack-protector-strong)"
            );
        }
    }
}

fn render_diff_text(baseline_label: &str, candidate_label: &str, diff: &BinaryDiff) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "bincompat diff: {baseline_label} -> {candidate_label}");

    if diff.passed {
        let _ = writeln!(out, "Diff Status: PASS (regressions: 0)");
    } else {
        let _ = writeln!(
            out,
            "Diff Status: FAIL (regressions: {})",
            diff.regressions.len()
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "Regressions:");
        for reg in &diff.regressions {
            match reg {
                DiffRegression::AddedNeeded { library } => {
                    let _ = writeln!(out, "  [NEEDED] added DT_NEEDED library: {library}");
                }
                DiffRegression::VersionBumped {
                    family,
                    baseline_max,
                    candidate_max,
                    library,
                    raw_tag,
                    symbols,
                } => {
                    let prev = baseline_max
                        .as_ref()
                        .map_or_else(|| "none".to_string(), ToString::to_string);
                    let _ = writeln!(
                        out,
                        "  [VERSION] {family} floor increased ({prev} -> {candidate_max}): {raw_tag} ({library}, {} symbol(s)):",
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
                DiffRegression::AddedAbiTag {
                    library,
                    tag,
                    symbols,
                } => {
                    let _ = writeln!(
                        out,
                        "  [ABI-TAG] added ABI tag {tag} ({library}, {} symbol(s))",
                        symbols.len()
                    );
                    for sym in symbols {
                        let _ = writeln!(out, "    - {}", format_symbol_entry(sym, tag));
                    }
                }
                DiffRegression::AddedRpath { kind, value } => {
                    let _ = writeln!(out, "  [RPATH] added {kind}: {value}");
                }
                DiffRegression::HardeningRegressed {
                    control,
                    baseline,
                    candidate,
                } => {
                    let _ = writeln!(
                        out,
                        "  [HARDENING] {control} regressed ({baseline} -> {candidate})"
                    );
                }
            }
        }
    }

    if !diff.improvements.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Improvements:");
        for lib in &diff.improvements.removed_needed {
            let _ = writeln!(out, "  [NEEDED] removed DT_NEEDED library: {lib}");
        }
        for (family, old_v, new_v) in &diff.improvements.lowered_versions {
            let next = new_v
                .as_ref()
                .map_or_else(|| "none".to_string(), ToString::to_string);
            let _ = writeln!(
                out,
                "  [VERSION] {family} floor lowered ({old_v} -> {next})"
            );
        }
        for (library, tag) in &diff.improvements.removed_abi_tags {
            let _ = writeln!(out, "  [ABI-TAG] removed ABI tag {tag} ({library})");
        }
        for (kind, value) in &diff.improvements.removed_rpath {
            let _ = writeln!(out, "  [RPATH] removed {kind}: {value}");
        }
        for (control, before, after) in &diff.improvements.hardening_improved {
            let _ = writeln!(
                out,
                "  [HARDENING] {control} improved ({before} -> {after})"
            );
        }
    }

    out
}

fn render_scan_markdown(path_label: &str, analysis: &BinaryAnalysis) -> String {
    let mut out = String::new();
    let endian = endian_label(analysis.endianness);
    let _ = writeln!(out, "## bincompat scan: `{}`", md_escape(path_label));
    let _ = writeln!(out);
    let _ = writeln!(out, "| Property | Value |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(
        out,
        "| ELF | {} ({}, ELF64-{}) |",
        analysis.elf_type, analysis.machine, endian
    );
    let _ = writeln!(
        out,
        "| Linking | {} |",
        if analysis.is_dynamic {
            "dynamic"
        } else {
            "static"
        }
    );
    let _ = writeln!(
        out,
        "| Hardening | PIE=`{}`, RELRO=`{}`, NX=`{}`, canary=`{}` |",
        analysis.hardening.pie.as_str(),
        analysis.hardening.relro.as_str(),
        analysis.hardening.nx.as_str(),
        canary_label(analysis.hardening.stack_canary)
    );
    if let Some(interp) = &analysis.interpreter {
        let _ = writeln!(out, "| Interpreter | `{}` |", md_escape(interp));
    }
    if let Some(soname) = &analysis.soname {
        let _ = writeln!(out, "| SONAME | `{}` |", md_escape(soname));
    }
    if let Some(rpath) = &analysis.rpath {
        let _ = writeln!(out, "| DT_RPATH | `{}` |", md_escape(rpath));
    }
    if let Some(runpath) = &analysis.runpath {
        let _ = writeln!(out, "| DT_RUNPATH | `{}` |", md_escape(runpath));
    }
    let needed = if analysis.needed.is_empty() {
        "(none)".to_string()
    } else {
        analysis
            .needed
            .iter()
            .map(|n| format!("`{}`", md_escape(n)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = writeln!(out, "| DT_NEEDED | {needed} |");

    let max_vers = if analysis.max_versions.is_empty() {
        "(none)".to_string()
    } else {
        analysis
            .max_versions
            .iter()
            .map(|(k, v)| format!("`{k}_{v}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = writeln!(out, "| Max Versions | {max_vers} |");

    if !analysis.abi_tags.is_empty() {
        let tags = analysis
            .abi_tags
            .iter()
            .map(|t| format!("`{}` (`{}`)", md_escape(&t.tag), md_escape(&t.library)))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "| ABI Tags | {tags} |");
    }

    let matrix = evaluate_distro_matrix(analysis);
    let _ = writeln!(out);
    let _ = writeln!(out, "### Distro Compatibility");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Target | glibc | libstdc++ | Status |");
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for entry in &matrix {
        let status = if entry.compatible {
            "OK".to_string()
        } else {
            format!("FAIL ({})", md_escape(&entry.reasons.join("; ")))
        };
        let _ = writeln!(
            out,
            "| {} (`{}`) | {} | {} | {} |",
            entry.baseline.display_name,
            entry.baseline.id,
            entry.baseline.glibc,
            entry.baseline.glibcxx,
            status
        );
    }

    if !analysis.requirements.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "### Symbol Version Requirements");
        let _ = writeln!(out);
        let _ = writeln!(out, "| Library | Version | Count | Symbols |");
        let _ = writeln!(out, "| --- | --- | ---: | --- |");
        for req in &analysis.requirements {
            let preview = format_symbol_preview(&req.symbols, SAMPLE_SYMBOL_LIMIT);
            let _ = writeln!(
                out,
                "| `{}` | `{}` | {} | `{}` |",
                md_escape(&req.library),
                md_escape(&req.raw_tag),
                req.symbols.len(),
                md_escape(&preview)
            );
        }
    }

    out
}

fn render_check_markdown(
    path_label: &str,
    analysis: &BinaryAnalysis,
    policy: &Policy,
    eval: &PolicyEvaluation,
) -> String {
    let mut out = render_scan_markdown(path_label, analysis);
    let rules = policy_rule_labels(policy);
    let rules_str = if rules.is_empty() {
        "(none)".to_string()
    } else {
        rules
            .iter()
            .map(|r| format!("`{}`", md_escape(r)))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let _ = writeln!(out);
    if eval.passed {
        let _ = writeln!(out, "### Policy Status: PASS");
        let _ = writeln!(out);
        let _ = writeln!(out, "Rules: {rules_str}");
        return out;
    }

    let _ = writeln!(
        out,
        "### Policy Status: FAIL ({} violation(s))",
        eval.violations.len()
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Rules: {rules_str}");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Rule | Detail |");
    let _ = writeln!(out, "| --- | --- |");
    for violation in &eval.violations {
        let (rule_id, msg) = violation_summary(violation);
        let _ = writeln!(out, "| `{rule_id}` | {} |", md_escape(&msg));
    }
    out
}

fn render_diff_markdown(baseline_label: &str, candidate_label: &str, diff: &BinaryDiff) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "## bincompat diff: `{}` -> `{}`",
        md_escape(baseline_label),
        md_escape(candidate_label)
    );
    let _ = writeln!(out);
    if diff.passed {
        let _ = writeln!(out, "Status: **PASS** (0 regressions)");
    } else {
        let _ = writeln!(
            out,
            "Status: **FAIL** ({} regression(s))",
            diff.regressions.len()
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "### Regressions");
        let _ = writeln!(out);
        let _ = writeln!(out, "| Rule | Detail |");
        let _ = writeln!(out, "| --- | --- |");
        for reg in &diff.regressions {
            let (rule_id, msg) = regression_summary(reg);
            let _ = writeln!(out, "| `{rule_id}` | {} |", md_escape(&msg));
        }
    }

    if !diff.improvements.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "### Improvements");
        let _ = writeln!(out);
        for lib in &diff.improvements.removed_needed {
            let _ = writeln!(out, "- Removed `DT_NEEDED`: `{}`", md_escape(lib));
        }
        for (family, old_v, new_v) in &diff.improvements.lowered_versions {
            let next = new_v
                .as_ref()
                .map_or_else(|| "none".to_string(), ToString::to_string);
            let _ = writeln!(
                out,
                "- Lowered `{}` floor: `{old_v}` -> `{next}`",
                md_escape(family)
            );
        }
        for (library, tag) in &diff.improvements.removed_abi_tags {
            let _ = writeln!(
                out,
                "- Removed ABI tag `{}` (`{}`)",
                md_escape(tag),
                md_escape(library)
            );
        }
        for (kind, value) in &diff.improvements.removed_rpath {
            let _ = writeln!(
                out,
                "- Removed `{}`: `{}`",
                md_escape(kind),
                md_escape(value)
            );
        }
        for (control, before, after) in &diff.improvements.hardening_improved {
            let _ = writeln!(
                out,
                "- Hardening `{}` improved: `{}` -> `{}`",
                md_escape(control),
                md_escape(before),
                md_escape(after)
            );
        }
    }

    out
}

fn render_scan_json(path_label: &str, analysis: &BinaryAnalysis) -> String {
    let matrix = evaluate_distro_matrix(analysis);
    let mut out = String::new();
    out.push_str("{\n");
    push_json_kv_str(&mut out, 2, "schema_version", "1", true);
    push_json_kv_str(&mut out, 2, "tool_version", VERSION_STR, true);
    push_json_kv_str(&mut out, 2, "command", "scan", true);
    push_json_kv_str(&mut out, 2, "path", path_label, true);
    push_json_analysis_fields(&mut out, 2, analysis, &matrix, false);
    out.push_str("}\n");
    out
}

fn render_check_json(
    path_label: &str,
    analysis: &BinaryAnalysis,
    policy: &Policy,
    eval: &PolicyEvaluation,
) -> String {
    let matrix = evaluate_distro_matrix(analysis);
    let rules = policy_rule_labels(policy);
    let mut out = String::new();
    out.push_str("{\n");
    push_json_kv_str(&mut out, 2, "schema_version", "1", true);
    push_json_kv_str(&mut out, 2, "tool_version", VERSION_STR, true);
    push_json_kv_str(&mut out, 2, "command", "check", true);
    push_json_kv_str(&mut out, 2, "path", path_label, true);
    let _ = writeln!(out, "  \"passed\": {},", eval.passed);
    push_json_str_array_field(&mut out, 2, "rules", &rules, true);

    out.push_str("  \"violations\": [");
    if eval.violations.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (i, violation) in eval.violations.iter().enumerate() {
            let comma = if i + 1 < eval.violations.len() {
                ","
            } else {
                ""
            };
            push_json_violation(&mut out, 4, violation, comma);
        }
        out.push_str("  ],\n");
    }

    push_json_analysis_fields(&mut out, 2, analysis, &matrix, false);
    out.push_str("}\n");
    out
}

fn render_diff_json(baseline_label: &str, candidate_label: &str, diff: &BinaryDiff) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    push_json_kv_str(&mut out, 2, "schema_version", "1", true);
    push_json_kv_str(&mut out, 2, "tool_version", VERSION_STR, true);
    push_json_kv_str(&mut out, 2, "command", "diff", true);
    push_json_kv_str(&mut out, 2, "baseline", baseline_label, true);
    push_json_kv_str(&mut out, 2, "candidate", candidate_label, true);
    let _ = writeln!(out, "  \"passed\": {},", diff.passed);

    out.push_str("  \"regressions\": [");
    if diff.regressions.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (i, reg) in diff.regressions.iter().enumerate() {
            let comma = if i + 1 < diff.regressions.len() {
                ","
            } else {
                ""
            };
            push_json_regression(&mut out, 4, reg, comma);
        }
        out.push_str("  ],\n");
    }

    out.push_str("  \"improvements\": {\n");
    push_json_str_array_field(
        &mut out,
        4,
        "removed_needed",
        &diff.improvements.removed_needed,
        true,
    );

    out.push_str("    \"lowered_versions\": [");
    if diff.improvements.lowered_versions.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (i, (fam, old_v, new_v)) in diff.improvements.lowered_versions.iter().enumerate() {
            let comma = if i + 1 < diff.improvements.lowered_versions.len() {
                ","
            } else {
                ""
            };
            let next = new_v
                .as_ref()
                .map_or_else(|| "null".to_string(), |v| json_str(&v.to_string()));
            let _ = writeln!(
                out,
                "      {{\"family\": {}, \"baseline\": {}, \"candidate\": {}}}{comma}",
                json_str(fam),
                json_str(&old_v.to_string()),
                next
            );
        }
        out.push_str("    ],\n");
    }

    out.push_str("    \"removed_abi_tags\": [");
    if diff.improvements.removed_abi_tags.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (i, (lib, tag)) in diff.improvements.removed_abi_tags.iter().enumerate() {
            let comma = if i + 1 < diff.improvements.removed_abi_tags.len() {
                ","
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "      {{\"library\": {}, \"tag\": {}}}{comma}",
                json_str(lib),
                json_str(tag)
            );
        }
        out.push_str("    ],\n");
    }

    out.push_str("    \"removed_rpath\": [");
    if diff.improvements.removed_rpath.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (i, (kind, val)) in diff.improvements.removed_rpath.iter().enumerate() {
            let comma = if i + 1 < diff.improvements.removed_rpath.len() {
                ","
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "      {{\"kind\": {}, \"value\": {}}}{comma}",
                json_str(kind),
                json_str(val)
            );
        }
        out.push_str("    ],\n");
    }

    out.push_str("    \"hardening_improved\": [");
    if diff.improvements.hardening_improved.is_empty() {
        out.push_str("]\n");
    } else {
        out.push('\n');
        for (i, (ctrl, before, after)) in diff.improvements.hardening_improved.iter().enumerate() {
            let comma = if i + 1 < diff.improvements.hardening_improved.len() {
                ","
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "      {{\"control\": {}, \"baseline\": {}, \"candidate\": {}}}{comma}",
                json_str(ctrl),
                json_str(before),
                json_str(after)
            );
        }
        out.push_str("    ]\n");
    }

    out.push_str("  }\n");
    out.push_str("}\n");
    out
}

fn push_json_analysis_fields(
    out: &mut String,
    indent: usize,
    analysis: &BinaryAnalysis,
    matrix: &[DistroCompatibility],
    trailing_comma: bool,
) {
    let pad = " ".repeat(indent);
    push_json_kv_str(out, indent, "elf_type", &analysis.elf_type, true);
    push_json_kv_str(out, indent, "machine", &analysis.machine, true);
    push_json_kv_str(
        out,
        indent,
        "endianness",
        endian_label(analysis.endianness),
        true,
    );
    let _ = writeln!(out, "{pad}\"is_dynamic\": {},", analysis.is_dynamic);
    push_json_kv_opt_str(
        out,
        indent,
        "interpreter",
        analysis.interpreter.as_deref(),
        true,
    );
    push_json_kv_opt_str(out, indent, "soname", analysis.soname.as_deref(), true);
    push_json_kv_opt_str(out, indent, "rpath", analysis.rpath.as_deref(), true);
    push_json_kv_opt_str(out, indent, "runpath", analysis.runpath.as_deref(), true);
    push_json_str_array_field(out, indent, "needed", &analysis.needed, true);

    let _ = writeln!(
        out,
        "{pad}\"hardening\": {{\"pie\": {}, \"relro\": {}, \"nx\": {}, \"stack_canary\": {}}},",
        json_str(analysis.hardening.pie.as_str()),
        json_str(analysis.hardening.relro.as_str()),
        json_str(analysis.hardening.nx.as_str()),
        analysis.hardening.stack_canary
    );

    let _ = write!(out, "{pad}\"max_versions\": {{");
    for (i, (fam, ver)) in analysis.max_versions.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{}: {}", json_str(fam), json_str(&ver.to_string()));
    }
    out.push_str("},\n");

    let _ = write!(out, "{pad}\"abi_tags\": [");
    if analysis.abi_tags.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (i, tag) in analysis.abi_tags.iter().enumerate() {
            let comma = if i + 1 < analysis.abi_tags.len() {
                ","
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "{pad}  {{\"library\": {}, \"tag\": {}, \"symbol_count\": {}}}{comma}",
                json_str(&tag.library),
                json_str(&tag.tag),
                tag.symbol_count
            );
        }
        let _ = writeln!(out, "{pad}],");
    }

    let _ = write!(out, "{pad}\"requirements\": [");
    if analysis.requirements.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (i, req) in analysis.requirements.iter().enumerate() {
            let comma = if i + 1 < analysis.requirements.len() {
                ","
            } else {
                ""
            };
            let _ = write!(
                out,
                "{pad}  {{\"library\": {}, \"raw_tag\": {}, \"symbols\": [",
                json_str(&req.library),
                json_str(&req.raw_tag)
            );
            push_json_symbols_inline(out, &req.symbols);
            let _ = writeln!(out, "]}}{comma}");
        }
        let _ = writeln!(out, "{pad}],");
    }

    let _ = write!(out, "{pad}\"distro_compatibility\": [");
    if matrix.is_empty() {
        let _ = writeln!(out, "]{}", if trailing_comma { "," } else { "" });
    } else {
        out.push('\n');
        for (i, entry) in matrix.iter().enumerate() {
            let comma = if i + 1 < matrix.len() { "," } else { "" };
            let reasons_json = entry
                .reasons
                .iter()
                .map(|r| json_str(r))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                out,
                "{pad}  {{\"id\": {}, \"name\": {}, \"glibc\": {}, \"glibcxx\": {}, \"compatible\": {}, \"reasons\": [{}]}}{comma}",
                json_str(entry.baseline.id),
                json_str(entry.baseline.display_name),
                json_str(entry.baseline.glibc),
                json_str(entry.baseline.glibcxx),
                entry.compatible,
                reasons_json
            );
        }
        let _ = writeln!(out, "{pad}]{}", if trailing_comma { "," } else { "" });
    }
}

fn push_json_violation(out: &mut String, indent: usize, violation: &Violation, comma: &str) {
    let pad = " ".repeat(indent);
    let (rule_id, message) = violation_summary(violation);
    match violation {
        Violation::VersionExceeded {
            library,
            family,
            raw_tag,
            required,
            max_allowed,
            symbols,
        } => {
            let _ = write!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"version_exceeded\", \"library\": {}, \"family\": {}, \"raw_tag\": {}, \"required\": {}, \"max_allowed\": {}, \"message\": {}, \"symbols\": [",
                json_str(rule_id),
                json_str(library),
                json_str(family),
                json_str(raw_tag),
                json_str(&required.to_string()),
                json_str(&max_allowed.to_string()),
                json_str(&message)
            );
            push_json_symbols_inline(out, symbols);
            let _ = writeln!(out, "]}}{comma}");
        }
        Violation::ForbiddenAbiTag {
            library,
            tag,
            symbols,
        } => {
            let _ = write!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"forbidden_abi_tag\", \"library\": {}, \"tag\": {}, \"message\": {}, \"symbols\": [",
                json_str(rule_id),
                json_str(library),
                json_str(tag),
                json_str(&message)
            );
            push_json_symbols_inline(out, symbols);
            let _ = writeln!(out, "]}}{comma}");
        }
        Violation::ForbiddenRpath { kind, value } => {
            let _ = writeln!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"forbidden_rpath\", \"entry\": {}, \"value\": {}, \"message\": {}}}{comma}",
                json_str(rule_id),
                json_str(kind),
                json_str(value),
                json_str(&message)
            );
        }
        Violation::MissingPie { actual } => {
            let _ = writeln!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"missing_pie\", \"actual\": {}, \"message\": {}}}{comma}",
                json_str(rule_id),
                json_str(actual.as_str()),
                json_str(&message)
            );
        }
        Violation::InsufficientRelro { actual, required } => {
            let _ = writeln!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"insufficient_relro\", \"actual\": {}, \"required\": {}, \"message\": {}}}{comma}",
                json_str(rule_id),
                json_str(actual.as_str()),
                json_str(required.as_str()),
                json_str(&message)
            );
        }
        Violation::MissingNx { actual } => {
            let _ = writeln!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"missing_nx\", \"actual\": {}, \"message\": {}}}{comma}",
                json_str(rule_id),
                json_str(actual.as_str()),
                json_str(&message)
            );
        }
        Violation::MissingStackCanary => {
            let _ = writeln!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"missing_stack_canary\", \"message\": {}}}{comma}",
                json_str(rule_id),
                json_str(&message)
            );
        }
    }
}

fn push_json_regression(out: &mut String, indent: usize, reg: &DiffRegression, comma: &str) {
    let pad = " ".repeat(indent);
    let (rule_id, message) = regression_summary(reg);
    match reg {
        DiffRegression::AddedNeeded { library } => {
            let _ = writeln!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"added_needed\", \"library\": {}, \"message\": {}}}{comma}",
                json_str(rule_id),
                json_str(library),
                json_str(&message)
            );
        }
        DiffRegression::VersionBumped {
            family,
            baseline_max,
            candidate_max,
            library,
            raw_tag,
            symbols,
        } => {
            let base_json = baseline_max
                .as_ref()
                .map_or_else(|| "null".to_string(), |v| json_str(&v.to_string()));
            let _ = write!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"version_bumped\", \"family\": {}, \"baseline_max\": {}, \"candidate_max\": {}, \"library\": {}, \"raw_tag\": {}, \"message\": {}, \"symbols\": [",
                json_str(rule_id),
                json_str(family),
                base_json,
                json_str(&candidate_max.to_string()),
                json_str(library),
                json_str(raw_tag),
                json_str(&message)
            );
            push_json_symbols_inline(out, symbols);
            let _ = writeln!(out, "]}}{comma}");
        }
        DiffRegression::AddedAbiTag {
            library,
            tag,
            symbols,
        } => {
            let _ = write!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"added_abi_tag\", \"library\": {}, \"tag\": {}, \"message\": {}, \"symbols\": [",
                json_str(rule_id),
                json_str(library),
                json_str(tag),
                json_str(&message)
            );
            push_json_symbols_inline(out, symbols);
            let _ = writeln!(out, "]}}{comma}");
        }
        DiffRegression::AddedRpath { kind, value } => {
            let _ = writeln!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"added_rpath\", \"entry\": {}, \"value\": {}, \"message\": {}}}{comma}",
                json_str(rule_id),
                json_str(kind),
                json_str(value),
                json_str(&message)
            );
        }
        DiffRegression::HardeningRegressed {
            control,
            baseline,
            candidate,
        } => {
            let _ = writeln!(
                out,
                "{pad}{{\"rule_id\": {}, \"kind\": \"hardening_regressed\", \"control\": {}, \"baseline\": {}, \"candidate\": {}, \"message\": {}}}{comma}",
                json_str(rule_id),
                json_str(control),
                json_str(baseline),
                json_str(candidate),
                json_str(&message)
            );
        }
    }
}

fn push_json_symbols_inline(out: &mut String, symbols: &[AttributedSymbol]) {
    for (i, sym) in symbols.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(
            out,
            "{{\"name\": {}, \"weak\": {}, \"hidden\": {}}}",
            json_str(&sym.name),
            sym.is_weak,
            sym.is_hidden
        );
    }
}

struct SarifRule {
    id: &'static str,
    name: &'static str,
    short_description: &'static str,
}

const CHECK_SARIF_RULES: &[SarifRule] = &[
    SarifRule {
        id: "BC001",
        name: "SymbolVersionExceeded",
        short_description: "Binary imports a versioned symbol newer than the configured floor.",
    },
    SarifRule {
        id: "BC002",
        name: "ForbiddenAbiTag",
        short_description: "Binary requires a forbidden linker ABI tag in .gnu.version_r.",
    },
    SarifRule {
        id: "BC003",
        name: "ForbiddenRpath",
        short_description: "Binary contains a forbidden DT_RPATH or DT_RUNPATH entry.",
    },
    SarifRule {
        id: "BC004",
        name: "MissingPie",
        short_description: "Binary is not compiled as a position-independent executable or DSO.",
    },
    SarifRule {
        id: "BC005",
        name: "InsufficientRelro",
        short_description: "Binary does not meet the required RELRO protection level.",
    },
    SarifRule {
        id: "BC006",
        name: "MissingNx",
        short_description: "Binary lacks a non-executable PT_GNU_STACK segment.",
    },
    SarifRule {
        id: "BC007",
        name: "MissingStackCanary",
        short_description: "Binary has no stack canary symbol reference.",
    },
];

const DIFF_SARIF_RULES: &[SarifRule] = &[
    SarifRule {
        id: "BC101",
        name: "AddedNeededLibrary",
        short_description: "Candidate binary introduced a new DT_NEEDED shared library dependency.",
    },
    SarifRule {
        id: "BC102",
        name: "SymbolVersionBumped",
        short_description: "Candidate binary raised a required symbol version floor.",
    },
    SarifRule {
        id: "BC103",
        name: "AddedAbiTag",
        short_description: "Candidate binary introduced a new non-numeric ABI tag.",
    },
    SarifRule {
        id: "BC104",
        name: "AddedRpath",
        short_description: "Candidate binary introduced a DT_RPATH or DT_RUNPATH entry.",
    },
    SarifRule {
        id: "BC105",
        name: "HardeningRegressed",
        short_description: "Candidate binary weakened a binary hardening control.",
    },
];

fn render_scan_sarif(path_label: &str, analysis: &BinaryAnalysis) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    push_json_kv_str(&mut out, 2, "$schema", SARIF_SCHEMA_URI, true);
    push_json_kv_str(&mut out, 2, "version", "2.1.0", true);
    out.push_str("  \"runs\": [\n");
    out.push_str("    {\n");
    push_sarif_tool(&mut out, 6, &[]);
    let _ = writeln!(
        out,
        "      \"results\": [],\n      \"properties\": {{\"command\": \"scan\", \"path\": {}, \"elf_type\": {}, \"machine\": {}, \"pie\": {}, \"relro\": {}, \"nx\": {}, \"stack_canary\": {}}}",
        json_str(path_label),
        json_str(&analysis.elf_type),
        json_str(&analysis.machine),
        json_str(analysis.hardening.pie.as_str()),
        json_str(analysis.hardening.relro.as_str()),
        json_str(analysis.hardening.nx.as_str()),
        analysis.hardening.stack_canary
    );
    out.push_str("    }\n");
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

fn render_check_sarif(path_label: &str, eval: &PolicyEvaluation) -> String {
    let items: Vec<(&'static str, String)> =
        eval.violations.iter().map(violation_summary).collect();
    render_sarif_envelope(path_label, CHECK_SARIF_RULES, &items)
}

fn render_diff_sarif(_baseline_label: &str, candidate_label: &str, diff: &BinaryDiff) -> String {
    let items: Vec<(&'static str, String)> =
        diff.regressions.iter().map(regression_summary).collect();
    render_sarif_envelope(candidate_label, DIFF_SARIF_RULES, &items)
}

fn render_sarif_envelope(
    artifact_uri: &str,
    rules: &[SarifRule],
    results: &[(&'static str, String)],
) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    push_json_kv_str(&mut out, 2, "$schema", SARIF_SCHEMA_URI, true);
    push_json_kv_str(&mut out, 2, "version", "2.1.0", true);
    out.push_str("  \"runs\": [\n");
    out.push_str("    {\n");
    push_sarif_tool(&mut out, 6, rules);
    out.push_str("      \"results\": [");
    if results.is_empty() {
        out.push_str("]\n");
    } else {
        out.push('\n');
        for (i, (rule_id, msg)) in results.iter().enumerate() {
            let comma = if i + 1 < results.len() { "," } else { "" };
            let _ = writeln!(
                out,
                "        {{\"ruleId\": {}, \"level\": \"error\", \"message\": {{\"text\": {}}}, \"locations\": [{{\"physicalLocation\": {{\"artifactLocation\": {{\"uri\": {}}}}}}}]}}{comma}",
                json_str(rule_id),
                json_str(msg),
                json_str(artifact_uri)
            );
        }
        out.push_str("      ]\n");
    }
    out.push_str("    }\n");
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

fn push_sarif_tool(out: &mut String, indent: usize, rules: &[SarifRule]) {
    let pad = " ".repeat(indent);
    let _ = writeln!(out, "{pad}\"tool\": {{");
    let _ = writeln!(out, "{pad}  \"driver\": {{");
    push_json_kv_str(out, indent + 4, "name", "bincompat", true);
    push_json_kv_str(out, indent + 4, "version", VERSION_STR, true);
    push_json_kv_str(out, indent + 4, "informationUri", TOOL_INFO_URI, true);
    let _ = write!(out, "{pad}    \"rules\": [");
    if rules.is_empty() {
        out.push_str("]\n");
    } else {
        out.push('\n');
        for (i, rule) in rules.iter().enumerate() {
            let comma = if i + 1 < rules.len() { "," } else { "" };
            let _ = writeln!(
                out,
                "{pad}      {{\"id\": {}, \"name\": {}, \"shortDescription\": {{\"text\": {}}}}}{comma}",
                json_str(rule.id),
                json_str(rule.name),
                json_str(rule.short_description)
            );
        }
        let _ = writeln!(out, "{pad}    ]");
    }
    let _ = writeln!(out, "{pad}  }}");
    let _ = writeln!(out, "{pad}}},");
}

fn violation_summary(violation: &Violation) -> (&'static str, String) {
    match violation {
        Violation::VersionExceeded {
            library,
            family,
            raw_tag,
            required,
            max_allowed,
            symbols,
        } => {
            let preview = format_symbol_preview(symbols, SAMPLE_SYMBOL_LIMIT);
            (
                "BC001",
                format!(
                    "{raw_tag} ({library}) exceeds max {family} {max_allowed} (found {required}; symbols: {preview})"
                ),
            )
        }
        Violation::ForbiddenAbiTag {
            library,
            tag,
            symbols,
        } => {
            let preview = format_symbol_preview(symbols, SAMPLE_SYMBOL_LIMIT);
            (
                "BC002",
                format!("forbidden ABI tag {tag} required by {library} ({preview})"),
            )
        }
        Violation::ForbiddenRpath { kind, value } => (
            "BC003",
            format!("forbidden {kind} entry present: {value}"),
        ),
        Violation::MissingPie { actual } => (
            "BC004",
            format!(
                "PIE required, found {} (compile with -fPIE -pie)",
                actual.as_str()
            ),
        ),
        Violation::InsufficientRelro { actual, required } => (
            "BC005",
            format!(
                "RELRO={} required, found {} (link with {})",
                required.as_str(),
                actual.as_str(),
                relro_hint(*required)
            ),
        ),
        Violation::MissingNx { actual } => (
            "BC006",
            format!(
                "NX stack required, found {} (link with -Wl,-z,noexecstack)",
                actual.as_str()
            ),
        ),
        Violation::MissingStackCanary => (
            "BC007",
            "stack canary required, no __stack_chk_fail/__stack_chk_guard reference found (compile with -fstack-protector-strong)".to_string(),
        ),
    }
}

fn regression_summary(reg: &DiffRegression) -> (&'static str, String) {
    match reg {
        DiffRegression::AddedNeeded { library } => {
            ("BC101", format!("added DT_NEEDED library: {library}"))
        }
        DiffRegression::VersionBumped {
            family,
            baseline_max,
            candidate_max,
            library,
            raw_tag,
            symbols,
        } => {
            let prev = baseline_max
                .as_ref()
                .map_or_else(|| "none".to_string(), ToString::to_string);
            let preview = format_symbol_preview(symbols, SAMPLE_SYMBOL_LIMIT);
            (
                "BC102",
                format!(
                    "{family} floor increased ({prev} -> {candidate_max}) via {raw_tag} ({library}; symbols: {preview})"
                ),
            )
        }
        DiffRegression::AddedAbiTag {
            library,
            tag,
            symbols,
        } => {
            let preview = format_symbol_preview(symbols, SAMPLE_SYMBOL_LIMIT);
            (
                "BC103",
                format!("added ABI tag {tag} ({library}; {preview})"),
            )
        }
        DiffRegression::AddedRpath { kind, value } => ("BC104", format!("added {kind}: {value}")),
        DiffRegression::HardeningRegressed {
            control,
            baseline,
            candidate,
        } => (
            "BC105",
            format!("hardening {control} regressed ({baseline} -> {candidate})"),
        ),
    }
}

fn policy_rule_labels(policy: &Policy) -> Vec<String> {
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
    if policy.require_pie {
        rules.push("require-pie".to_string());
    }
    if let Some(relro) = policy.min_relro {
        rules.push(format!("require-relro={}", relro.as_str()));
    }
    if policy.require_nx {
        rules.push("require-nx".to_string());
    }
    if policy.require_canary {
        rules.push("require-canary".to_string());
    }
    rules
}

fn endian_label(e: Endianness) -> &'static str {
    match e {
        Endianness::Little => "LE",
        Endianness::Big => "BE",
    }
}

fn canary_label(present: bool) -> &'static str {
    if present {
        "present"
    } else {
        "absent"
    }
}

fn relro_hint(required: RelroStatus) -> &'static str {
    match required {
        RelroStatus::Full => "-Wl,-z,relro,-z,now",
        RelroStatus::Partial => "-Wl,-z,relro",
        RelroStatus::None => "",
    }
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

fn md_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', " ")
}

fn json_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn push_json_kv_str(out: &mut String, indent: usize, key: &str, val: &str, comma: bool) {
    let pad = " ".repeat(indent);
    let _ = writeln!(
        out,
        "{pad}{}: {}{}",
        json_str(key),
        json_str(val),
        if comma { "," } else { "" }
    );
}

fn push_json_kv_opt_str(
    out: &mut String,
    indent: usize,
    key: &str,
    val: Option<&str>,
    comma: bool,
) {
    let pad = " ".repeat(indent);
    let val_str = val.map_or_else(|| "null".to_string(), json_str);
    let _ = writeln!(
        out,
        "{pad}{}: {val_str}{}",
        json_str(key),
        if comma { "," } else { "" }
    );
}

fn push_json_str_array_field(
    out: &mut String,
    indent: usize,
    key: &str,
    items: &[String],
    comma: bool,
) {
    let pad = " ".repeat(indent);
    let body = items
        .iter()
        .map(|s| json_str(s))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        out,
        "{pad}{}: [{body}]{}",
        json_str(key),
        if comma { "," } else { "" }
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_rfc8259_json_control_and_quote_chars() {
        assert_eq!(
            json_str("a\"b\\c\n\r\t\u{0001}"),
            "\"a\\\"b\\\\c\\n\\r\\t\\u0001\""
        );
    }

    #[test]
    fn parses_output_formats() {
        assert_eq!(OutputFormat::parse("text").unwrap(), OutputFormat::Text);
        assert_eq!(OutputFormat::parse("JSON").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("md").unwrap(), OutputFormat::Markdown);
        assert_eq!(
            OutputFormat::parse("markdown").unwrap(),
            OutputFormat::Markdown
        );
        assert_eq!(OutputFormat::parse("sarif").unwrap(), OutputFormat::Sarif);
        assert!(OutputFormat::parse("yaml").is_err());
    }
}
