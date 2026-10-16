#!/usr/bin/env bash
# SP1 canonical build driver (the SP1 implementation lane; docs/SP1_Implementation_Pin_Designation_Registry.md).
#
# Runs SP1-TD1's canonical procedure (vendor-image-host-flow) for the repository's zkvm subject at HEAD, in a FRESH
# container of the vendor image referenced BY DIGEST, with no bind mounts and no cache volumes, and records what it
# produced. Everything it needs comes from the designation file — the image digest, and the in-container entrypoint
# with its sha256 (SP1-TD1's preserved host-build-in-container.sh, run unchanged) — never from a mutable tag or from
# this script. It records the guest lockfile before and after the build (SP1-TD1 finding TD1-N7: sp1-build builds
# the guest unlocked, so a changed lockfile is a drift). It compares nothing and decides nothing:
# scripts/check-sp1-canonical-build.ts compares the observation with the designation.
#
# Usage: canonical-build.sh <out-dir> <host-id> [designation-file]
#   Linux (CI) and Git Bash on Windows (Docker Desktop). Needs git, docker, node, sha256sum.
set -euo pipefail
OUT="$1"
HOST_ID="$2"
ROOT="$(git rev-parse --show-toplevel)"
# By default the latest designation (the highest sequence): the one whose subject CI holds HEAD to.
latest_designation() {
  node -e 'const fs=require("fs"),p=require("path");const dir=process.argv[1];const ds=fs.readdirSync(dir).filter((f)=>f.endsWith(".json")).map((f)=>JSON.parse(fs.readFileSync(p.join(dir,f),"utf8")));ds.sort((a,b)=>a.sequence-b.sequence);if(ds.length===0)process.exit(4);process.stdout.write(p.join(dir,ds[ds.length-1].id+".json"))' "$1"
}
DESIGNATION="${3:-$(latest_designation "$ROOT/evidence/zk/sp1/designations")}"
field() { node -e 'const d=require(process.argv[1]); console.log(process.argv[2].split(".").reduce((o,k)=>o[k],d))' "$DESIGNATION" "$1"; }
IMAGE="$(field procedure.image)"
ENTRYPOINT_REL="$(field procedure.entrypoint.path)"
ENTRYPOINT_SHA="$(field procedure.entrypoint.sha256)"
case "$IMAGE" in *@sha256:*) ;; *) echo "the designation's image is not pinned by digest: $IMAGE" >&2; exit 3 ;; esac

# Docker Desktop on Windows needs Windows paths for docker cp; container paths stay literal.
if command -v cygpath > /dev/null 2>&1; then export MSYS_NO_PATHCONV=1; HOSTPATH() { cygpath -m "$1"; }; else HOSTPATH() { echo "$1"; }; fi

mkdir -p "$OUT/src" "$OUT/host"
OUT="$(cd "$OUT" && pwd)"
ACTUAL_SHA="$(sha256sum "$ROOT/$ENTRYPOINT_REL" | cut -d' ' -f1)"
if [ "$ACTUAL_SHA" != "$ENTRYPOINT_SHA" ]; then
  echo "the entrypoint $ENTRYPOINT_REL is $ACTUAL_SHA, not the designated $ENTRYPOINT_SHA" >&2
  exit 3
fi

git -C "$ROOT" rev-parse HEAD 'HEAD:zkvm/guest' 'HEAD:zkvm/host' > "$OUT/src/git-ids.txt"
git -C "$ROOT" archive --format=tar -o "$(HOSTPATH "$OUT/src/zkvm-src.tar")" HEAD zkvm/guest zkvm/host
git -C "$ROOT" show 'HEAD:zkvm/guest/Cargo.lock' | sha256sum | cut -d' ' -f1 > "$OUT/src/guest-lock-at-head.txt"
cp "$ROOT/$ENTRYPOINT_REL" "$OUT/src/entrypoint.sh"

if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then docker pull "$IMAGE" > "$OUT/pull.log" 2>&1; fi
docker image inspect "$IMAGE" --format '{{.Id}} {{json .RepoDigests}} {{.Os}}/{{.Architecture}}' > "$OUT/image.txt"
docker info --format 'server={{.ServerVersion}} kernel={{.KernelVersion}} os={{.OperatingSystem}} ncpu={{.NCPU}}' > "$OUT/docker-info.txt"
{
  echo "host_id=$HOST_ID"
  echo "runner=${RUNNER_NAME-local} runner_os=${RUNNER_OS-$(uname -s)} image_os=${ImageOS-unset} image_version=${ImageVersion-unset}"
  echo "run=${GITHUB_RUN_ID-unset}.${GITHUB_RUN_ATTEMPT-unset} sha=${GITHUB_SHA-unset}"
  uname -srm
  grep -m1 'model name' /proc/cpuinfo 2> /dev/null || echo "cpu=unknown"
} > "$OUT/host-identity.txt"

C="sp1-canonical-$(date -u +%Y%m%dT%H%M%SZ)-$$"
docker create --name "$C" --platform linux/amd64 -w /root "$IMAGE" bash -c '
  mkdir -p /root/program && tar -xf /root/zkvm-src.tar -C /root/program
  sha256sum /root/program/zkvm/guest/Cargo.lock | cut -d" " -f1 > /root/lock-before.txt
  bash /root/host-build-in-container.sh; rc=$?
  sha256sum /root/program/zkvm/guest/Cargo.lock | cut -d" " -f1 > /root/lock-after.txt
  exit $rc' > "$OUT/host/container-id.txt"
docker cp "$(HOSTPATH "$OUT/src/zkvm-src.tar")" "$C:/root/zkvm-src.tar"
docker cp "$(HOSTPATH "$OUT/src/entrypoint.sh")" "$C:/root/host-build-in-container.sh"
set +e
docker start -a "$C" > "$OUT/host/run.log" 2>&1
RC=$?
set -e
echo "container_exit=$RC" >> "$OUT/host/run.log"
docker cp "$C:/root/out/." "$(HOSTPATH "$OUT/host")" || true
docker cp "$C:/root/lock-before.txt" "$(HOSTPATH "$OUT/host/lock-before.txt")" || true
docker cp "$C:/root/lock-after.txt" "$(HOSTPATH "$OUT/host/lock-after.txt")" || true
docker rm "$C" > /dev/null
rm -f "$OUT/host/mldsa65-host" # keep its sha256 (host-bin-sha256.txt), not the binary
mkdir -p "$OUT/elf"
cp "$OUT/host/elf/mldsa65-withdrawal" "$OUT/host/elf/mldsa65-acvp" "$OUT/elf/" 2> /dev/null || true
echo "canonical build on $HOST_ID: container exit $RC; outputs in $OUT"
exit "$RC"
