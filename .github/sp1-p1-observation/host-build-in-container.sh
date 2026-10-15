#!/usr/bin/env bash
# Environment B (vendor container): runs inside a FRESH container of the pinned vendor image
# ghcr.io/succinctlabs/sp1@sha256:0942a27d... The repository's own host flow
# (`cargo build --release --locked` in zkvm/host; build.rs -> sp1_build::build_program("../guest")),
# then the host's own `vkey` / `acvp-vkey`. Outputs under /root/out for `docker cp`.
set -euo pipefail
OUT=/root/out
mkdir -p "$OUT/elf" "$OUT/build-script"
cd /root/program/zkvm/host
{
  echo "env=B-vendor-container-host-flow"
  echo "container_hostname=$(hostname)"
  echo "uname=$(uname -a)"
  echo "os=$(. /etc/os-release; echo "$PRETTY_NAME")"
  echo "uid=$(id -u) HOME=$HOME CARGO_HOME=${CARGO_HOME-unset} RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN-unset} CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS-unset}"
  echo "SP1_SKIP_PROGRAM_BUILD=${SP1_SKIP_PROGRAM_BUILD-unset} CARGO_TARGET_DIR=${CARGO_TARGET_DIR-unset} RUSTC_WRAPPER=${RUSTC_WRAPPER-unset} RUSTFLAGS=${RUSTFLAGS-unset}"
  rustc -vV
  cargo -vV
  echo "succinct: $(RUSTUP_TOOLCHAIN=succinct rustc -vV | tr '\n' ' ')"
  echo "cargo-prove: $(cargo prove --version 2>&1 || true)"
  echo "succinct_toolchain_dirs: $(ls /root/.sp1/toolchains 2>/dev/null | tr '\n' ' ')"
  echo "target_entries_before=$(find /root/program/zkvm/host/target /root/program/zkvm/guest/target -mindepth 1 2>/dev/null | wc -l)"
  echo "registry_src_entries_before=$(ls -1 /root/.cargo/registry/src/*/ 2>/dev/null | wc -l)"
} > "$OUT/env.txt" 2>&1
( cd /root/program && find zkvm -type f | LC_ALL=C sort | xargs sha256sum ) > "$OUT/source-sha256.txt"
start_stamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"; start=$(date +%s)
set +e
cargo build --release --locked > "$OUT/host-build.log" 2>&1
rc=$?
set -e
echo "build_exit=$rc build_seconds=$(( $(date +%s) - start )) started_utc=$start_stamp" >> "$OUT/env.txt"
if [ "$rc" -ne 0 ]; then tail -60 "$OUT/host-build.log"; exit "$rc"; fi
T=/root/program/zkvm/host/target
cp "$T/release/mldsa65-host" "$OUT/"
for d in "$T"/release/build/mldsa65-host-*/; do
  [ -f "$d/output" ] && cp "$d/output" "$OUT/build-script/$(basename "$d").output"
done
elf_path() { sed -n "s/^cargo:rustc-env=SP1_ELF_$1=//p" "$OUT"/build-script/*.output; }
W_ELF="$(elf_path mldsa65-withdrawal)"; C_ELF="$(elf_path mldsa65-acvp)"
echo "SP1_ELF_mldsa65-withdrawal=$W_ELF" >> "$OUT/env.txt"
echo "SP1_ELF_mldsa65-acvp=$C_ELF" >> "$OUT/env.txt"
[ -f "$W_ELF" ] && [ -f "$C_ELF" ] || { echo "COLLECT FAILED"; exit 5; }
cp "$W_ELF" "$C_ELF" "$OUT/elf/"
( cd "$OUT/elf" && sha256sum mldsa65-withdrawal mldsa65-acvp ) > "$OUT/elf-sha256.txt"
( cd "$OUT/elf" && stat -c '%n %s' mldsa65-withdrawal mldsa65-acvp ) > "$OUT/elf-size.txt"
sha256sum "$OUT/mldsa65-host" > "$OUT/host-bin-sha256.txt"
grep -h 'built at' "$OUT/host-build.log" > "$OUT/guest-built-at.txt" || true
for sub in vkey acvp-vkey; do
  s=$(date +%s)
  "$OUT/mldsa65-host" "$sub" > "$OUT/$sub.stdout" 2> "$OUT/$sub.stderr"
  echo "$sub exit=$? seconds=$(( $(date +%s) - s ))" >> "$OUT/vkey-runs.txt"
done
cat "$OUT/elf-sha256.txt" "$OUT/elf-size.txt" "$OUT/vkey.stdout" "$OUT/acvp-vkey.stdout" "$OUT/vkey-runs.txt"
