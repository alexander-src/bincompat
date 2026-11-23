use std::collections::{BTreeMap, BTreeSet};

use crate::elf::{AttributedSymbol, BinaryAnalysis};
use crate::version::{Version, VersionTag};

/// Single portability or hardening regression between baseline and candidate binaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffRegression {
    AddedNeeded {
        library: String,
    },
    VersionBumped {
        family: String,
        baseline_max: Option<Version>,
        candidate_max: Version,
        library: String,
        raw_tag: String,
        symbols: Vec<AttributedSymbol>,
    },
    AddedAbiTag {
        library: String,
        tag: String,
        symbols: Vec<AttributedSymbol>,
    },
    AddedRpath {
        kind: String,
        value: String,
    },
    HardeningRegressed {
        control: String,
        baseline: String,
        candidate: String,
    },
}

/// Non-failing improvements or dependency removals observed between baseline and candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffImprovements {
    pub removed_needed: Vec<String>,
    pub lowered_versions: Vec<(String, Version, Option<Version>)>,
    pub removed_abi_tags: Vec<(String, String)>,
    pub removed_rpath: Vec<(String, String)>,
    pub hardening_improved: Vec<(String, String, String)>,
}

impl DiffImprovements {
    pub fn is_empty(&self) -> bool {
        self.removed_needed.is_empty()
            && self.lowered_versions.is_empty()
            && self.removed_abi_tags.is_empty()
            && self.removed_rpath.is_empty()
            && self.hardening_improved.is_empty()
    }
}

/// Full comparison result produced by `bincompat diff <baseline> <candidate>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryDiff {
    pub passed: bool,
    pub regressions: Vec<DiffRegression>,
    pub improvements: DiffImprovements,
}

/// Compares `baseline` and `candidate` ELF64 analyses and reports regressions and improvements.
pub fn diff_analyses(baseline: &BinaryAnalysis, candidate: &BinaryAnalysis) -> BinaryDiff {
    let mut regressions = Vec::new();
    let mut improvements = DiffImprovements::default();

    // 1. DT_NEEDED library additions and removals
    let base_needed: BTreeSet<&str> = baseline.needed.iter().map(String::as_str).collect();
    let cand_needed: BTreeSet<&str> = candidate.needed.iter().map(String::as_str).collect();
    for lib in cand_needed.difference(&base_needed) {
        regressions.push(DiffRegression::AddedNeeded {
            library: (*lib).to_string(),
        });
    }
    for lib in base_needed.difference(&cand_needed) {
        improvements.removed_needed.push((*lib).to_string());
    }

    // 2. Symbol version bumps and newly introduced families
    let mut all_families: BTreeSet<&str> = BTreeSet::new();
    all_families.extend(baseline.max_versions.keys().map(String::as_str));
    all_families.extend(candidate.max_versions.keys().map(String::as_str));

    for family in all_families {
        let old_max = baseline.max_versions.get(family);
        let new_max = candidate.max_versions.get(family);
        match (old_max, new_max) {
            (Some(old_v), Some(new_v)) if new_v > old_v => {
                let entries = candidate_reqs_above(candidate, family, Some(old_v));
                for (library, raw_tag, symbols) in entries {
                    regressions.push(DiffRegression::VersionBumped {
                        family: family.to_string(),
                        baseline_max: Some(old_v.clone()),
                        candidate_max: new_v.clone(),
                        library,
                        raw_tag,
                        symbols,
                    });
                }
            }
            (None, Some(new_v)) => {
                let entries = candidate_reqs_above(candidate, family, None);
                for (library, raw_tag, symbols) in entries {
                    regressions.push(DiffRegression::VersionBumped {
                        family: family.to_string(),
                        baseline_max: None,
                        candidate_max: new_v.clone(),
                        library,
                        raw_tag,
                        symbols,
                    });
                }
            }
            (Some(old_v), Some(new_v)) if new_v < old_v => {
                improvements.lowered_versions.push((
                    family.to_string(),
                    old_v.clone(),
                    Some(new_v.clone()),
                ));
            }
            (Some(old_v), None) => {
                improvements
                    .lowered_versions
                    .push((family.to_string(), old_v.clone(), None));
            }
            _ => {}
        }
    }

    // 3. Non-numeric ABI tags in .gnu.version_r (e.g. GLIBC_ABI_DT_RELR)
    let base_tags: BTreeSet<(&str, &str)> = baseline
        .abi_tags
        .iter()
        .map(|t| (t.library.as_str(), t.tag.as_str()))
        .collect();
    let cand_tags: BTreeMap<(&str, &str), Vec<AttributedSymbol>> = candidate
        .requirements
        .iter()
        .filter_map(|req| match &req.parsed {
            VersionTag::AbiTag { raw } => {
                Some(((req.library.as_str(), raw.as_str()), req.symbols.clone()))
            }
            VersionTag::Versioned { .. } => None,
        })
        .collect();

    for ((library, tag), symbols) in &cand_tags {
        if !base_tags.contains(&(*library, *tag)) {
            regressions.push(DiffRegression::AddedAbiTag {
                library: (*library).to_string(),
                tag: (*tag).to_string(),
                symbols: symbols.clone(),
            });
        }
    }
    for (library, tag) in &base_tags {
        if !cand_tags.contains_key(&(*library, *tag)) {
            improvements
                .removed_abi_tags
                .push(((*library).to_string(), (*tag).to_string()));
        }
    }

    // 4. DT_RPATH / DT_RUNPATH additions and removals
    compare_search_path(
        "DT_RPATH",
        baseline.rpath.as_deref(),
        candidate.rpath.as_deref(),
        &mut regressions,
        &mut improvements,
    );
    compare_search_path(
        "DT_RUNPATH",
        baseline.runpath.as_deref(),
        candidate.runpath.as_deref(),
        &mut regressions,
        &mut improvements,
    );

    // 5. Hardening posture comparisons
    let bh = baseline.hardening;
    let ch = candidate.hardening;
    if bh.pie.is_position_independent() && !ch.pie.is_position_independent() {
        regressions.push(DiffRegression::HardeningRegressed {
            control: "PIE".to_string(),
            baseline: bh.pie.as_str().to_string(),
            candidate: ch.pie.as_str().to_string(),
        });
    } else if !bh.pie.is_position_independent() && ch.pie.is_position_independent() {
        improvements.hardening_improved.push((
            "PIE".to_string(),
            bh.pie.as_str().to_string(),
            ch.pie.as_str().to_string(),
        ));
    }

    if ch.relro < bh.relro {
        regressions.push(DiffRegression::HardeningRegressed {
            control: "RELRO".to_string(),
            baseline: bh.relro.as_str().to_string(),
            candidate: ch.relro.as_str().to_string(),
        });
    } else if ch.relro > bh.relro {
        improvements.hardening_improved.push((
            "RELRO".to_string(),
            bh.relro.as_str().to_string(),
            ch.relro.as_str().to_string(),
        ));
    }

    if bh.nx.is_enabled() && !ch.nx.is_enabled() {
        regressions.push(DiffRegression::HardeningRegressed {
            control: "NX".to_string(),
            baseline: bh.nx.as_str().to_string(),
            candidate: ch.nx.as_str().to_string(),
        });
    } else if !bh.nx.is_enabled() && ch.nx.is_enabled() {
        improvements.hardening_improved.push((
            "NX".to_string(),
            bh.nx.as_str().to_string(),
            ch.nx.as_str().to_string(),
        ));
    }

    if bh.stack_canary && !ch.stack_canary {
        regressions.push(DiffRegression::HardeningRegressed {
            control: "stack-canary".to_string(),
            baseline: "present".to_string(),
            candidate: "absent".to_string(),
        });
    } else if !bh.stack_canary && ch.stack_canary {
        improvements.hardening_improved.push((
            "stack-canary".to_string(),
            "absent".to_string(),
            "present".to_string(),
        ));
    }

    BinaryDiff {
        passed: regressions.is_empty(),
        regressions,
        improvements,
    }
}

fn candidate_reqs_above(
    candidate: &BinaryAnalysis,
    family: &str,
    threshold: Option<&Version>,
) -> Vec<(String, String, Vec<AttributedSymbol>)> {
    let mut out = Vec::new();
    for req in &candidate.requirements {
        if let VersionTag::Versioned {
            family: req_family,
            version,
        } = &req.parsed
        {
            if req_family == family && threshold.map_or(true, |t| version > t) {
                out.push((
                    req.library.clone(),
                    req.raw_tag.clone(),
                    req.symbols.clone(),
                ));
            }
        }
    }
    out
}

fn compare_search_path(
    kind: &str,
    baseline: Option<&str>,
    candidate: Option<&str>,
    regressions: &mut Vec<DiffRegression>,
    improvements: &mut DiffImprovements,
) {
    match (baseline, candidate) {
        (None, Some(val)) => regressions.push(DiffRegression::AddedRpath {
            kind: kind.to_string(),
            value: val.to_string(),
        }),
        (Some(val), None) => improvements
            .removed_rpath
            .push((kind.to_string(), val.to_string())),
        _ => {}
    }
}
