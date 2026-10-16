#!/usr/bin/env bash
# SP1-TD1 Candidate B probe (WSL). Builds the withdrawal/ACVP guest ELFs twice from the same extracted
# subject in fresh work and target directories: P-local (sp1-build local mode, default flags) and P-remap
# (the same plus the vendor-supported BuildArgs.rustflags --remap-path-prefix=$HOME/.cargo=/root/.cargo).
# Records ELF sha256/size and each ELF's vkey via the released cargo-prove. Usage: remap-build.sh OUT SRC_TAR
set -euo pipefail
OUT="$1"
SRC_TAR="$2"
export PATH="$HOME/.sp1/bin:$HOME/.cargo/bin:$PATH"
mkdir -p "$OUT"
{
  echo "uname=$(uname -a)"
  echo "os=$(. /etc/os-release; echo "$PRETTY_NAME")"
  echo "HOME=$HOME CARGO_HOME=${CARGO_HOME-unset} RUSTFLAGS=${RUSTFLAGS-unset} CARGO_TARGET_DIR=${CARGO_TARGET_DIR-unset}"
  rustc -vV
  cargo -vV
  echo "succinct: $(RUSTUP_TOOLCHAIN=succinct rustc -vV | tr '\n' ' ')"
  echo "cargo-prove: $(cargo prove --version 2>&1 | head -1)"
  echo "succinct_toolchain_dirs: $(ls "$HOME/.sp1/toolchains" | tr '\n' ' ')"
  echo "cpu=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
} > "$OUT/env.txt" 2>&1

run() {
  local label="$1"
  shift
  local W
  W="$(mktemp -d "$HOME/td1-remap-$label-XXXXXX")"
  mkdir -p "$W/src"
  tar -xf "$SRC_TAR" -C "$W/src"
  ( cd "$W/src" && find zkvm -type f | LC_ALL=C sort | xargs sha256sum ) > "$OUT/$label.source-sha256.txt"
  echo "$label workdir=$W args=$*" >> "$OUT/env.txt"
  local start
  start=$(date +%s)
  ( cd "$W/src/zkvm/guest" && CARGO_TARGET_DIR="$W/target" cargo prove build --locked "$@" ) > "$OUT/$label.build.log" 2>&1
  echo "$label build_seconds=$(( $(date +%s) - start ))" >> "$OUT/env.txt"
  mkdir -p "$OUT/$label-elf"
  for p in mldsa65-withdrawal mldsa65-acvp; do
    local f
    f="$(find "$W/target" -type f -path "*riscv64im-succinct-zkvm-elf/release/$p" | head -1)"
    [ -n "$f" ] || { echo "$label: $p ELF not found"; exit 5; }
    cp "$f" "$OUT/$label-elf/$p"
    echo "$label $p elf_path=$f" >> "$OUT/env.txt"
  done
  ( cd "$OUT/$label-elf" && sha256sum mldsa65-withdrawal mldsa65-acvp && stat -c '%n %s' mldsa65-withdrawal mldsa65-acvp ) > "$OUT/$label.elf.txt"
  for p in mldsa65-withdrawal mldsa65-acvp; do
    echo "$p $(cargo prove vkey --elf "$OUT/$label-elf/$p" 2>&1 | tail -1)" >> "$OUT/$label.vkey.txt"
  done
  LC_ALL=C grep -aoE '(/home/|/root/)[[:print:]]{3,160}' "$OUT/$label-elf/mldsa65-withdrawal" | sort | uniq -c > "$OUT/$label.embedded-paths.txt" || true
}

run local
run remap "--rustflags=--remap-path-prefix=$HOME/.cargo=/root/.cargo"
cat "$OUT/local.elf.txt" "$OUT/local.vkey.txt" "$OUT/remap.elf.txt" "$OUT/remap.vkey.txt"
