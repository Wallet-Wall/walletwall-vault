// Compiles the guest crate's SP1 programs, one ELF per bin target (`mldsa65-withdrawal` and
// `mldsa65-acvp`), so `include_elf!` can embed each. Requires the SP1 toolchain (`sp1up`).
// Builds the sibling guest crate at ../guest relative to this host crate.
fn main() {
    sp1_build::build_program("../guest");
}
