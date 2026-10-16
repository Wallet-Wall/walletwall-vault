#!/usr/bin/env bash
# Environment B driver (Git Bash on the Windows host, Docker Desktop engine).
# Two FRESH containers from the vendor image pinned by digest, no bind mounts, no cache volumes:
#   B-host : the repository's own host flow inside the vendor image (sp1-build local path, CARGO_HOME=/root/.cargo)
#   B-guest: the vendor docker-mode guest build, argument-for-argument what sp1-build 6.3.1
#            build_docker_args() runs for `cargo prove build --docker --tag v6.3.1 --locked --no-docker-cache`
set -euo pipefail
export MSYS_NO_PATHCONV=1
SP="$(cygpath -m "$1")"   # C:/... form: docker.exe needs Windows paths; MSYS_NO_PATHCONV keeps container paths literal
IMAGE="ghcr.io/succinctlabs/sp1@sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUTB="$SP/envB/out-$TS"
mkdir -p "$OUTB/host" "$OUTB/guest-docker"
docker image inspect "$IMAGE" --format '{{.Id}} {{json .RepoDigests}} {{.Os}}/{{.Architecture}} created={{.Created}}' > "$OUTB/image.txt"
docker info --format 'server={{.ServerVersion}} kernel={{.KernelVersion}} os={{.OperatingSystem}} ncpu={{.NCPU}} mem={{.MemTotal}}' > "$OUTB/docker-info.txt"

# ---------- B-host ----------
HC="sp1p1-b-host-$TS"
docker create --name "$HC" --platform linux/amd64 -w /root \
  "$IMAGE" bash -c 'mkdir -p /root/program && tar -xf /root/zkvm-src.tar -C /root/program && bash /root/host-build-in-container.sh' > "$OUTB/host/container-id.txt"
docker cp "$SP/src/zkvm-src.tar" "$HC:/root/zkvm-src.tar"
docker cp "$SP/envB/host-build-in-container.sh" "$HC:/root/host-build-in-container.sh"
set +e
docker start -a "$HC" > "$OUTB/host/run.log" 2>&1
rc=$?
set -e
echo "host_container_exit=$rc" >> "$OUTB/host/run.log"
docker cp "$HC:/root/out/." "$OUTB/host/"

# ---------- B-guest (docker mode) ----------
SYSROOT="$(docker run --rm --platform linux/amd64 --entrypoint '' -e RUSTUP_TOOLCHAIN=succinct "$IMAGE" rustc --print sysroot | tr -d '\r')"
RUSTC_VERSION="$(docker run --rm --platform linux/amd64 --entrypoint '' -e RUSTUP_TOOLCHAIN=succinct "$IMAGE" rustc --version | tr -d '\r')"
echo "sysroot=$SYSROOT" > "$OUTB/guest-docker/env.txt"
echo "rustc_version=$RUSTC_VERSION" >> "$OUTB/guest-docker/env.txt"
FLAGS="$(printf -- '-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=--image-base=2013265920\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"\x1f-C\x1fllvm-args=-misched-prera-direction=bottomup\x1f-C\x1fllvm-args=-misched-postra-direction=bottomup')"
GC="sp1p1-b-guest-docker-$TS"
docker create --name "$GC" --platform linux/amd64 -w /root/program \
  -e CARGO_TARGET_DIR=/root/program/target/elf-compilation/docker \
  -e RUSTUP_TOOLCHAIN=succinct \
  -e RUSTC_BOOTSTRAP=1 \
  -e "CARGO_ENCODED_RUSTFLAGS=$FLAGS" \
  -e "RUSTC=$SYSROOT/bin/rustc" \
  -e CFLAGS_riscv32im_succinct_zkvm_elf=-D__ILP32__ \
  --entrypoint '' "$IMAGE" \
  bash -c 'mkdir -p /root/program && tar -xf /root/zkvm-src.tar -C /root/stage && cp -a /root/stage/zkvm/guest/. /root/program/ && cd /root/program && cargo build --release --target riscv64im-succinct-zkvm-elf --locked' > "$OUTB/guest-docker/container-id.txt"
docker cp "$SP/src/zkvm-src.tar" "$GC:/root/zkvm-src.tar"
# /root/stage must exist before tar -x; create it via a tiny tar of an empty dir
mkdir -p "$SP/envB/stage-empty/stage" && tar --force-local -C "$SP/envB/stage-empty" -cf "$SP/envB/stage-empty.tar" stage
docker cp - "$GC:/root" < "$SP/envB/stage-empty.tar"
docker container inspect "$GC" --format '{{json .Config.Env}} {{json .Config.Cmd}} wd={{.Config.WorkingDir}} mounts={{json .Mounts}}' >> "$OUTB/guest-docker/env.txt"
set +e
docker start -a "$GC" > "$OUTB/guest-docker/build.log" 2>&1
grc=$?
set -e
echo "guest_container_exit=$grc" >> "$OUTB/guest-docker/build.log"
mkdir -p "$OUTB/guest-docker/elf"
docker cp "$GC:/root/program/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/mldsa65-withdrawal" "$OUTB/guest-docker/elf/"
docker cp "$GC:/root/program/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/mldsa65-acvp" "$OUTB/guest-docker/elf/"
( cd "$OUTB/guest-docker/elf" && sha256sum mldsa65-withdrawal mldsa65-acvp && stat -c '%n %s' mldsa65-withdrawal mldsa65-acvp ) > "$OUTB/guest-docker/elf-sha256-size.txt"
echo "OUTB=$OUTB"
echo "--- host flow"; cat "$OUTB/host/elf-sha256.txt" "$OUTB/host/elf-size.txt" "$OUTB/host/vkey.stdout" "$OUTB/host/acvp-vkey.stdout" "$OUTB/host/vkey-runs.txt" 2>&1 || true
echo "--- docker mode"; cat "$OUTB/guest-docker/elf-sha256-size.txt"
