#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bincompat::{
    analyze_file, diff_analyses, render_check, render_diff, render_scan, render_targets,
    BincompatError, OutputFormat, Policy, Result, Version,
};

const VERSION_STR: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
bincompat - Zero-dependency ELF64 Linux binary portability and hardening CI gate

USAGE:
  bincompat scan <path> [--format text|json|markdown|sarif] [--out <FILE>]
  bincompat check <path> [options] [--out <FILE>]
  bincompat diff <baseline> <candidate> [--format text|json|markdown|sarif] [--out <FILE>]
  bincompat targets [--format text|json|markdown] [--out <FILE>]
  bincompat --help | --version

GLOBAL OPTIONS:
  --format <FMT>               Output format: text (default), json, markdown, sarif
  -o, --out <FILE>             Write report to FILE instead of stdout

CHECK OPTIONS:
  --target <DISTRO>            Apply distro preset (centos-7, rhel-8, ubuntu-20.04, debian-11,
                               rhel-9, ubuntu-22.04, debian-12, ubuntu-24.04, rhel-10, debian-13)
  --max-glibc <VER>            Fail if any symbol requires GLIBC > VER (e.g. 2.28)
  --max-glibcxx <VER>          Fail if any symbol requires GLIBCXX > VER (e.g. 3.4.28)
  --max-version <PREFIX=VER>   Fail if PREFIX version exceeds VER (repeatable)
  --forbid-abi-tag <TAG>       Fail if ABI tag appears in .gnu.version_r (repeatable)
  --forbid-rpath               Fail if DT_RPATH or DT_RUNPATH is present
  --require-pie                Fail if binary is not position-independent (PIE/DSO)
  --require-relro <LEVEL>      Fail if RELRO is below LEVEL (partial or full)
  --require-nx                 Fail if PT_GNU_STACK is missing or executable
  --require-canary             Fail if no stack canary symbol reference is found
  --require-hardening          Enable PIE, full RELRO, NX stack, and stack canary

EXIT CODES:
  0  Scan succeeded, policy check passed, or diff found no regressions
  1  Policy check failed or diff detected portability/hardening regressions
  2  Usage, I/O, or ELF parsing error
";

enum Command {
    Help,
    Version,
    Targets {
        format: OutputFormat,
        out: Option<PathBuf>,
    },
    Scan {
        path: PathBuf,
        format: OutputFormat,
        out: Option<PathBuf>,
    },
    Check {
        path: PathBuf,
        policy: Policy,
        format: OutputFormat,
        out: Option<PathBuf>,
    },
    Diff {
        baseline: PathBuf,
        candidate: PathBuf,
        format: OutputFormat,
        out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}

fn emit_output(rendered: &str, out: Option<&Path>) -> Result<()> {
    match out {
        Some(path) => fs::write(path, rendered).map_err(|source| BincompatError::WriteIo {
            path: path.to_path_buf(),
            source,
        }),
        None => {
            print!("{rendered}");
            Ok(())
        }
    }
}

fn run(args: &[String]) -> Result<u8> {
    match parse_args(args)? {
        Command::Help => {
            print!("{USAGE}");
            Ok(0)
        }
        Command::Version => {
            println!("bincompat {VERSION_STR}");
            Ok(0)
        }
        Command::Targets { format, out } => {
            let rendered = render_targets(format);
            emit_output(&rendered, out.as_deref())?;
            Ok(0)
        }
        Command::Scan { path, format, out } => {
            let analysis = analyze_file(&path)?;
            let label = path.display().to_string();
            let rendered = render_scan(format, &label, &analysis);
            emit_output(&rendered, out.as_deref())?;
            Ok(0)
        }
        Command::Check {
            path,
            policy,
            format,
            out,
        } => {
            let analysis = analyze_file(&path)?;
            let eval = policy.evaluate(&analysis);
            let label = path.display().to_string();
            let rendered = render_check(format, &label, &analysis, &policy, &eval);
            emit_output(&rendered, out.as_deref())?;
            Ok(if eval.passed { 0 } else { 1 })
        }
        Command::Diff {
            baseline,
            candidate,
            format,
            out,
        } => {
            let base_analysis = analyze_file(&baseline)?;
            let cand_analysis = analyze_file(&candidate)?;
            let diff = diff_analyses(&base_analysis, &cand_analysis);
            let base_label = baseline.display().to_string();
            let cand_label = candidate.display().to_string();
            let rendered = render_diff(format, &base_label, &cand_label, &diff);
            emit_output(&rendered, out.as_deref())?;
            Ok(if diff.passed { 0 } else { 1 })
        }
    }
}

fn parse_args(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(BincompatError::InvalidArgument(
            "missing subcommand (expected 'scan', 'check', 'diff', or 'targets'; run --help for usage)"
                .to_string(),
        ));
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "-V" | "--version" => Ok(Command::Version),
        "targets" => parse_targets_args(&args[1..]),
        "scan" => parse_scan_args(&args[1..]),
        "check" => parse_check_args(&args[1..]),
        "diff" => parse_diff_args(&args[1..]),
        other => Err(BincompatError::InvalidArgument(format!(
            "unknown subcommand '{other}' (expected 'scan', 'check', 'diff', or 'targets')"
        ))),
    }
}

fn parse_targets_args(args: &[String]) -> Result<Command> {
    let mut format = OutputFormat::Text;
    let mut out: Option<PathBuf> = None;
    let mut idx = 0usize;

    while idx < args.len() {
        match args[idx].as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--format" => {
                let raw = next_value(args, &mut idx, "--format")?;
                format = OutputFormat::parse(raw)?;
                if format == OutputFormat::Sarif {
                    return Err(BincompatError::InvalidArgument(
                        "targets does not support --format sarif (expected text, json, or markdown)"
                            .to_string(),
                    ));
                }
            }
            flag @ ("-o" | "--out") => {
                let raw = next_value(args, &mut idx, flag)?;
                out = Some(PathBuf::from(raw));
            }
            flag if flag.starts_with('-') => {
                return Err(BincompatError::InvalidArgument(format!(
                    "unknown option '{flag}'"
                )));
            }
            positional => {
                return Err(BincompatError::InvalidArgument(format!(
                    "unexpected positional argument '{positional}' for targets"
                )));
            }
        }
        idx += 1;
    }

    Ok(Command::Targets { format, out })
}

fn parse_scan_args(args: &[String]) -> Result<Command> {
    let mut path: Option<PathBuf> = None;
    let mut format = OutputFormat::Text;
    let mut out: Option<PathBuf> = None;
    let mut idx = 0usize;

    while idx < args.len() {
        match args[idx].as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--format" => {
                let raw = next_value(args, &mut idx, "--format")?;
                format = OutputFormat::parse(raw)?;
            }
            flag @ ("-o" | "--out") => {
                let raw = next_value(args, &mut idx, flag)?;
                out = Some(PathBuf::from(raw));
            }
            flag if flag.starts_with('-') => {
                return Err(BincompatError::InvalidArgument(format!(
                    "unknown option '{flag}'"
                )));
            }
            positional => {
                if path.is_some() {
                    return Err(BincompatError::InvalidArgument(format!(
                        "unexpected extra positional argument '{positional}'"
                    )));
                }
                path = Some(PathBuf::from(positional));
            }
        }
        idx += 1;
    }

    let path = path.ok_or_else(|| {
        BincompatError::InvalidArgument(
            "usage: bincompat scan <path> [--format text|json|markdown|sarif] [--out <FILE>]"
                .to_string(),
        )
    })?;
    Ok(Command::Scan { path, format, out })
}

fn parse_diff_args(args: &[String]) -> Result<Command> {
    let mut baseline: Option<PathBuf> = None;
    let mut candidate: Option<PathBuf> = None;
    let mut format = OutputFormat::Text;
    let mut out: Option<PathBuf> = None;
    let mut idx = 0usize;

    while idx < args.len() {
        match args[idx].as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--format" => {
                let raw = next_value(args, &mut idx, "--format")?;
                format = OutputFormat::parse(raw)?;
            }
            flag @ ("-o" | "--out") => {
                let raw = next_value(args, &mut idx, flag)?;
                out = Some(PathBuf::from(raw));
            }
            flag if flag.starts_with('-') => {
                return Err(BincompatError::InvalidArgument(format!(
                    "unknown option '{flag}'"
                )));
            }
            positional => {
                if baseline.is_none() {
                    baseline = Some(PathBuf::from(positional));
                } else if candidate.is_none() {
                    candidate = Some(PathBuf::from(positional));
                } else {
                    return Err(BincompatError::InvalidArgument(format!(
                        "unexpected extra positional argument '{positional}'"
                    )));
                }
            }
        }
        idx += 1;
    }

    let (Some(baseline), Some(candidate)) = (baseline, candidate) else {
        return Err(BincompatError::InvalidArgument(
            "usage: bincompat diff <baseline> <candidate> [--format text|json|markdown|sarif] [--out <FILE>]"
                .to_string(),
        ));
    };
    Ok(Command::Diff {
        baseline,
        candidate,
        format,
        out,
    })
}

fn parse_check_args(args: &[String]) -> Result<Command> {
    let mut path: Option<PathBuf> = None;
    let mut policy = Policy::default();
    let mut format = OutputFormat::Text;
    let mut out: Option<PathBuf> = None;
    let mut idx = 0usize;

    while idx < args.len() {
        match args[idx].as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--format" => {
                let raw = next_value(args, &mut idx, "--format")?;
                format = OutputFormat::parse(raw)?;
            }
            flag @ ("-o" | "--out") => {
                let raw = next_value(args, &mut idx, flag)?;
                out = Some(PathBuf::from(raw));
            }
            "--target" => {
                let raw = next_value(args, &mut idx, "--target")?;
                policy.apply_distro_target(raw)?;
            }
            "--max-glibc" => {
                let raw = next_value(args, &mut idx, "--max-glibc")?;
                let ver = Version::parse(raw).ok_or_else(|| {
                    BincompatError::InvalidArgument(format!("invalid GLIBC version '{raw}'"))
                })?;
                policy.set_max_version("GLIBC", ver);
            }
            "--max-glibcxx" => {
                let raw = next_value(args, &mut idx, "--max-glibcxx")?;
                let ver = Version::parse(raw).ok_or_else(|| {
                    BincompatError::InvalidArgument(format!("invalid GLIBCXX version '{raw}'"))
                })?;
                policy.set_max_version("GLIBCXX", ver);
            }
            "--max-version" => {
                let raw = next_value(args, &mut idx, "--max-version")?;
                let (family, ver) = Policy::parse_max_version_spec(raw)?;
                policy.set_max_version(family, ver);
            }
            "--forbid-abi-tag" => {
                let raw = next_value(args, &mut idx, "--forbid-abi-tag")?;
                if raw.is_empty() {
                    return Err(BincompatError::InvalidArgument(
                        "--forbid-abi-tag requires a non-empty tag".to_string(),
                    ));
                }
                policy.forbid_abi_tags.insert(raw.to_string());
            }
            "--forbid-rpath" => {
                policy.forbid_rpath = true;
            }
            "--require-pie" => {
                policy.require_pie = true;
            }
            "--require-relro" => {
                let raw = next_value(args, &mut idx, "--require-relro")?;
                let level = Policy::parse_relro_level(raw)?;
                policy.min_relro = Some(match policy.min_relro {
                    Some(existing) if existing > level => existing,
                    _ => level,
                });
            }
            "--require-nx" => {
                policy.require_nx = true;
            }
            "--require-canary" => {
                policy.require_canary = true;
            }
            "--require-hardening" => {
                policy.enable_standard_hardening();
            }
            flag if flag.starts_with('-') => {
                return Err(BincompatError::InvalidArgument(format!(
                    "unknown option '{flag}'"
                )));
            }
            positional => {
                if path.is_some() {
                    return Err(BincompatError::InvalidArgument(format!(
                        "unexpected extra positional argument '{positional}'"
                    )));
                }
                path = Some(PathBuf::from(positional));
            }
        }
        idx += 1;
    }

    let path = path.ok_or_else(|| {
        BincompatError::InvalidArgument("usage: bincompat check <path> [options]".to_string())
    })?;
    if policy.is_empty() {
        return Err(BincompatError::InvalidArgument(
            "check requires at least one constraint (--target, --max-glibc, --max-glibcxx, --max-version, --forbid-abi-tag, --forbid-rpath, --require-pie, --require-relro, --require-nx, --require-canary, or --require-hardening)"
                .to_string(),
        ));
    }
    Ok(Command::Check {
        path,
        policy,
        format,
        out,
    })
}

fn next_value<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Result<&'a str> {
    *idx += 1;
    args.get(*idx)
        .map(String::as_str)
        .ok_or_else(|| BincompatError::InvalidArgument(format!("option '{flag}' requires a value")))
}
