#![forbid(unsafe_code)]

pub mod elf;
pub mod error;
pub mod policy;
pub mod report;
pub mod version;

pub use elf::{
    analyze_bytes, analyze_file, AbiTagRequirement, AttributedSymbol, BinaryAnalysis, Endianness,
    VersionRequirement,
};
pub use error::{BincompatError, Result};
pub use policy::{Policy, PolicyEvaluation, Violation};
pub use report::{render_check_text, render_scan_text};
pub use version::{Version, VersionTag};
