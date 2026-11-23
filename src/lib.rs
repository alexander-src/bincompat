#![forbid(unsafe_code)]

pub mod diff;
pub mod distro;
pub mod elf;
pub mod error;
pub mod policy;
pub mod report;
pub mod version;

pub use diff::{diff_analyses, BinaryDiff, DiffImprovements, DiffRegression};
pub use distro::{
    evaluate_distro_matrix, lookup_distro, supported_target_ids, DistroBaseline,
    DistroCompatibility, DISTRO_BASELINES,
};
pub use elf::{
    analyze_bytes, analyze_file, AbiTagRequirement, AttributedSymbol, BinaryAnalysis, Endianness,
    HardeningReport, NxStatus, PieStatus, RelroStatus, VersionRequirement,
};
pub use error::{BincompatError, Result};
pub use policy::{Policy, PolicyEvaluation, Violation};
pub use report::{
    render_check, render_check_text, render_diff, render_scan, render_scan_text, OutputFormat,
};
pub use version::{Version, VersionTag};
