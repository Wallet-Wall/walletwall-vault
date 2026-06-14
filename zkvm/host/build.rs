// Compiles the ML-DSA-65 guest ELF so `include_elf!("mldsa65-guest")` can embed
// it. Requires the SP1 toolchain (`sp1up`). Builds the sibling guest crate at
// ../guest relative to this host crate.
fn main() {
    sp1_build::build_program("../guest");
}
