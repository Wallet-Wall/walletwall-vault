//! Copies the guest programs' sources into OUT_DIR so src/lib.rs can `include!` them.
//!
//! The programs are the bin targets Cargo reports for ../guest (`cargo metadata --no-deps`), so the
//! tests always compile exactly the source files an SP1 build turns into program ELFs. Exactly one
//! transformation is applied to each source: the crate-level `#![no_main]` on its first line is
//! dropped, because an inner crate attribute is not valid inside an included module. Every other
//! byte is compiled as written.
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Bin target name in zkvm/guest, and the stem of the files and env vars generated for it.
const PROGRAMS: [(&str, &str); 2] = [
    ("mldsa65-withdrawal", "WITHDRAWAL"),
    ("mldsa65-acvp", "ACVP"),
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let guest_dir =
        fs::canonicalize(manifest_dir.join("..").join("guest")).expect("zkvm/guest exists");
    let guest_manifest = guest_dir.join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", guest_manifest.display());

    let targets = guest_bin_targets(&guest_manifest);
    let mut names: Vec<&str> = targets.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    println!("cargo:rustc-env=GUEST_BIN_TARGETS={}", names.join(","));

    for (bin, stem) in PROGRAMS {
        let source_path = targets
            .iter()
            .find(|(name, _)| name == bin)
            .map(|(_, path)| path.clone())
            .unwrap_or_else(|| panic!("zkvm/guest has no bin target named `{bin}`"));
        println!("cargo:rerun-if-changed={}", source_path.display());
        let source = fs::read_to_string(&source_path)
            .unwrap_or_else(|error| panic!("{} is not readable: {error}", source_path.display()));
        let first_line_end = source.find('\n').map_or(source.len(), |index| index + 1);
        let (first_line, body) = source.split_at(first_line_end);
        assert_eq!(
            first_line.trim_end(),
            "#![no_main]",
            "{} must begin with `#![no_main]`",
            source_path.display()
        );
        let relative = source_path
            .strip_prefix(&guest_dir)
            .unwrap_or_else(|_| panic!("{} is outside zkvm/guest", source_path.display()))
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let lower = stem.to_lowercase();
        fs::write(out_dir.join(format!("{lower}_source.rs")), &source)
            .expect("write the source copy");
        fs::write(out_dir.join(format!("{lower}_body.rs")), body).expect("write the body copy");
        println!("cargo:rustc-env={stem}_SOURCE_PATH={relative}");
    }
}

/// (name, canonical source path) for every bin target Cargo reports for the guest package.
fn guest_bin_targets(guest_manifest: &Path) -> Vec<(String, PathBuf)> {
    let cargo = env::var("CARGO").expect("CARGO");
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(guest_manifest)
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed for {}: {}",
        guest_manifest.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata prints JSON");
    let packages = metadata["packages"].as_array().expect("a packages array");
    assert_eq!(packages.len(), 1, "zkvm/guest is a single package");
    packages[0]["targets"]
        .as_array()
        .expect("a targets array")
        .iter()
        .filter(|target| {
            target["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
        })
        .map(|target| {
            let name = target["name"].as_str().expect("a target name").to_string();
            let path = PathBuf::from(target["src_path"].as_str().expect("a target src_path"));
            let path = fs::canonicalize(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            (name, path)
        })
        .collect()
}
