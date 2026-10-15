#!/usr/bin/env bash
# SP1-P1 independent-host observation (non-claiming).
#
# Runs the pinned vendor SP1 build procedure for zkvm/guest on a GitHub-hosted runner and records
# what it produced: ELF sha256 + size and the program vkeys of mldsa65-withdrawal / mldsa65-acvp.
# It compares nothing and gates nothing; the comparison against earlier observations is done
# elsewhere. Mirrors the local Environment B driver container-for-container:
#   host  : a fresh container of the vendor image runs the repository's own host flow
#           (`cargo build --release --locked` in zkvm/host, build.rs -> sp1_build::build_program),
#           then the host's `vkey` / `acvp-vkey` (host-build-in-container.sh, byte-identical copy).
#   guest : a fresh container replays sp1-build 6.3.1 build_docker_args() argument for argument
#           (`cargo prove build --docker --tag v6.3.1 --locked --no-docker-cache`).
# No bind mounts and no cache volumes: sources go in with `docker cp`.
set -euo pipefail
OUT="$1"
HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="ghcr.io/succinctlabs/sp1@sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400"
mkdir -p "$OUT/src" "$OUT/host" "$OUT/guest-docker/elf"

git rev-parse HEAD 'HEAD^{tree}' HEAD:zkvm HEAD:zkvm/guest HEAD:zkvm/host > "$OUT/src/git-ids.txt"
git archive --format=tar -o "$OUT/src/zkvm-src.tar" HEAD zkvm/guest zkvm/host
sha256sum "$HERE/host-build-in-container.sh" "$HERE/observe.sh" > "$OUT/src/observation-scripts.sha256"
{
  echo "runner_name=${RUNNER_NAME-unset} runner_os=${RUNNER_OS-unset} runner_arch=${RUNNER_ARCH-unset}"
  echo "image_os=${ImageOS-unset} image_version=${ImageVersion-unset}"
  echo "github_run_id=${GITHUB_RUN_ID-unset} attempt=${GITHUB_RUN_ATTEMPT-unset} sha=${GITHUB_SHA-unset}"
  uname -a
  . /etc/os-release; echo "os=$PRETTY_NAME"
  echo "nproc=$(nproc)"
  grep -m1 'model name' /proc/cpuinfo || true
  free -g | sed -n 2p
  df -h / | tail -1
} > "$OUT/host-identity.txt" 2>&1

docker pull "$IMAGE" > "$OUT/pull.log" 2>&1
docker image inspect "$IMAGE" --format '{{.Id}} {{json .RepoDigests}} {{.Os}}/{{.Architecture}} created={{.Created}}' > "$OUT/image.txt"
docker info --format 'server={{.ServerVersion}} kernel={{.KernelVersion}} os={{.OperatingSystem}} ncpu={{.NCPU}} mem={{.MemTotal}}' > "$OUT/docker-info.txt"

# ---------- host flow ----------
HC="sp1p1-obs-host"
docker create --name "$HC" --platform linux/amd64 -w /root \
  "$IMAGE" bash -c 'mkdir -p /root/program && tar -xf /root/zkvm-src.tar -C /root/program && bash /root/host-build-in-container.sh' > "$OUT/host/container-id.txt"
docker cp "$OUT/src/zkvm-src.tar" "$HC:/root/zkvm-src.tar"
docker cp "$HERE/host-build-in-container.sh" "$HC:/root/host-build-in-container.sh"
set +e
docker start -a "$HC" > "$OUT/host/run.log" 2>&1
rc=$?
set -e
echo "host_container_exit=$rc" >> "$OUT/host/run.log"
docker cp "$HC:/root/out/." "$OUT/host/"
rm -f "$OUT/host/mldsa65-host"   # keep its sha256 (host-bin-sha256.txt), not the binary

# ---------- docker-mode guest build ----------
SYSROOT="$(docker run --rm --platform linux/amd64 --entrypoint '' -e RUSTUP_TOOLCHAIN=succinct "$IMAGE" rustc --print sysroot | tr -d '\r')"
RUSTC_VERSION="$(docker run --rm --platform linux/amd64 --entrypoint '' -e RUSTUP_TOOLCHAIN=succinct "$IMAGE" rustc --version | tr -d '\r')"
echo "sysroot=$SYSROOT" > "$OUT/guest-docker/env.txt"
echo "rustc_version=$RUSTC_VERSION" >> "$OUT/guest-docker/env.txt"
FLAGS="$(printf -- '-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=--image-base=2013265920\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"\x1f-C\x1fllvm-args=-misched-prera-direction=bottomup\x1f-C\x1fllvm-args=-misched-postra-direction=bottomup')"
GC="sp1p1-obs-guest-docker"
docker create --name "$GC" --platform linux/amd64 -w /root/program \
  -e CARGO_TARGET_DIR=/root/program/target/elf-compilation/docker \
  -e RUSTUP_TOOLCHAIN=succinct \
  -e RUSTC_BOOTSTRAP=1 \
  -e "CARGO_ENCODED_RUSTFLAGS=$FLAGS" \
  -e "RUSTC=$SYSROOT/bin/rustc" \
  -e CFLAGS_riscv32im_succinct_zkvm_elf=-D__ILP32__ \
  --entrypoint '' "$IMAGE" \
  bash -c 'mkdir -p /root/program && tar -xf /root/zkvm-src.tar -C /root/stage && cp -a /root/stage/zkvm/guest/. /root/program/ && cd /root/program && cargo build --release --target riscv64im-succinct-zkvm-elf --locked' > "$OUT/guest-docker/container-id.txt"
docker cp "$OUT/src/zkvm-src.tar" "$GC:/root/zkvm-src.tar"
STAGE="$(mktemp -d)"
mkdir -p "$STAGE/stage" && tar -C "$STAGE" -cf "$STAGE/stage-empty.tar" stage
docker cp - "$GC:/root" < "$STAGE/stage-empty.tar"
docker container inspect "$GC" --format '{{json .Config.Env}} {{json .Config.Cmd}} wd={{.Config.WorkingDir}} mounts={{json .Mounts}}' >> "$OUT/guest-docker/env.txt"
set +e
docker start -a "$GC" > "$OUT/guest-docker/build.log" 2>&1
grc=$?
set -e
echo "guest_container_exit=$grc" >> "$OUT/guest-docker/build.log"
docker cp "$GC:/root/program/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/mldsa65-withdrawal" "$OUT/guest-docker/elf/"
docker cp "$GC:/root/program/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/mldsa65-acvp" "$OUT/guest-docker/elf/"
( cd "$OUT/guest-docker/elf" && sha256sum mldsa65-withdrawal mldsa65-acvp && stat -c '%n %s' mldsa65-withdrawal mldsa65-acvp ) > "$OUT/guest-docker/elf-sha256-size.txt"

{
  echo "### SP1-P1 independent-host observation (non-claiming)"
  echo
  echo '```'
  cat "$OUT/src/git-ids.txt"
  echo "--- host flow (vendor image, repository host build)"
  cat "$OUT/host/elf-sha256.txt" "$OUT/host/elf-size.txt" "$OUT/host/vkey.stdout" "$OUT/host/acvp-vkey.stdout" "$OUT/host/vkey-runs.txt" 2>&1 || true
  echo "--- docker-mode guest build"
  cat "$OUT/guest-docker/elf-sha256-size.txt"
  echo "--- image"
  cat "$OUT/image.txt"
  echo '```'
} > "$OUT/summary.md"
cat "$OUT/summary.md"
