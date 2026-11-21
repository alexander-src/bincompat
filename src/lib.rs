#![forbid(unsafe_code)]

pub mod elf;
pub mod error;
pub mod version;

pub use elf::{
    analyze_bytes, analyze_file, AbiTagRequirement, AttributedSymbol, BinaryAnalysis, Endianness,
    VersionRequirement,
};
pub use error::{BincompatError, Result};
pub use version::{Version, VersionTag};
