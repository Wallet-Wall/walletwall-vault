#!/usr/bin/env bash
# SP1-PA3C-Q1: the clean-container derivation of raw observer captures (docs/SP1_Circuit_Install_And_Archive_Only_
# Prove_Gate.md, "SP1-PA3C-Q1"). One `docker run` per capture, from an explicit base image named by digest, with no
# network, a read-only root, every capability dropped, no new privileges, an unprivileged user, a pid limit, and
# read-only mounts of the source export, the raw captures and the inputs; only /out is writable. Nothing is installed:
# the image's Node strips the types itself and the repository's hook resolves the two extensionless imports. It
# generates no proof, pulls no image (the image must already be in the engine, by digest) and reaches no host.
#
#   container-derive.sh <image@sha256:digest> <src-export> <raw-parent> <in-dir> <out-dir> <registry-verification>
#                       <source-commit> fixture|<raw-name> [<raw-name>...]
#
# <src-export> is `git archive` of the exact commit, extracted (never the working tree; node_modules must not be in it);
# <raw-parent> holds the soak's raw directories (<raw-name> each); <in-dir> receives host-executable.json (made on the
# host by `sp1-observer-qualification.ts host-executable`) and environment.json (written here); <out-dir> receives
# derivation-<name>.json, write-once. Research prototype. Not audited.
set -euo pipefail

if [ "$#" -lt 8 ]; then
  echo "usage: $0 <image@sha256:digest> <src-export> <raw-parent> <in-dir> <out-dir> <registry-verification> <source-commit> fixture|<raw-name>..." >&2
  exit 2
fi
IMAGE="$1"; SRC="$2"; RAW="$3"; IN="$4"; OUT="$5"; REGISTRY_VERIFICATION="$6"; SOURCE_COMMIT="$7"; shift 7

case "$IMAGE" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "the image must be named by digest (<repository>@sha256:<64 hex>), not a tag: $IMAGE" >&2; exit 2 ;;
esac
case "$SOURCE_COMMIT" in
  ????????????????????????????????????????) ;;
  *) echo "the source commit must be 40 hex digits: $SOURCE_COMMIT" >&2; exit 2 ;;
esac
for d in "$SRC" "$RAW" "$IN" "$OUT"; do
  [ -d "$d" ] || { echo "$d is not a directory" >&2; exit 2; }
done
[ -f "$SRC/scripts/sp1-observer-qualification.ts" ] || { echo "$SRC is not a source export of the repository" >&2; exit 2; }
[ ! -e "$SRC/node_modules" ] || { echo "$SRC holds node_modules: export the commit, not a working tree" >&2; exit 2; }
[ -f "$IN/host-executable.json" ] || { echo "$IN/host-executable.json is missing" >&2; exit 2; }

# The image must already be in the engine (SP1-PA3B moved it there; this lane pulls nothing): its identity is read, never fetched.
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE")
NODE_VERSION=$(docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE" | sed -n 's/^NODE_VERSION=//p' | head -n 1)
# The container runs as the unprivileged operator who owns <out-dir> and may read the raw captures (root:<group> 0750):
# never root, inside or outside.
[ "$(id -u)" != "0" ] || { echo "run this as the unprivileged operator, not root" >&2; exit 2; }
RUN_USER="$(id -u):$(id -g)"
PIDS=64
MEMORY=1g

# The exact argv, as JSON too, so the derivation inside records what ran it (one token per line; tokens hold no quotes).
run_prefix=(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges
  --user "$RUN_USER" --pids-limit "$PIDS" --memory "$MEMORY"
  -v "$SRC:/src:ro" -v "$RAW:/raw:ro" -v "$IN:/in:ro" -v "$OUT:/out"
  "$IMAGE" node --import /src/scripts/sp1-observer-qualification/node-ts-loader.mjs /src/scripts/sp1-observer-qualification.ts derive)
json_array() {
  local sep="" t
  printf '['
  for t in "$@"; do
    case "$t" in *'"'*|*'\'*) echo "a token holds a quote or backslash: $t" >&2; exit 2 ;; esac
    printf '%s"%s"' "$sep" "$t"; sep=","
  done
  printf ']'
}
{
  printf '{\n  "image": {\n    "reference": "%s",\n    "digest": "%s",\n    "id": "%s",\n    "nodeVersion": "%s",\n    "registryVerification": "%s"\n  },\n' \
    "${IMAGE%@*}" "sha256:${IMAGE#*@sha256:}" "$IMAGE_ID" "$NODE_VERSION" "$REGISTRY_VERIFICATION"
  printf '  "runOptions": %s,\n' "$(json_array "${run_prefix[@]}")"
  printf '  "sourceCommit": "%s",\n  "label": "clean-container"\n}\n' "$SOURCE_COMMIT"
} > "$IN/environment.json"

status=0
for name in "$@"; do
  out="/out/derivation-$name.json"
  if [ "$name" = "fixture" ]; then
    args=(--fixture)
  else
    [ -d "$RAW/$name" ] || { echo "$RAW/$name is not a directory" >&2; status=1; continue; }
    args=(--raw "/raw/$name" --host-executable /in/host-executable.json)
  fi
  if "${run_prefix[@]}" "${args[@]}" --environment-file /in/environment.json --execution node-type-stripping --out "$out"; then
    echo "derived $name -> $OUT/derivation-$name.json"
  else
    echo "FAILED $name (exit $?)" >&2; status=1
  fi
done
exit "$status"
