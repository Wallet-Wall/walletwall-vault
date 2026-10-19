# SP1 circuit install and archive-only prove gate (SP1-PA2A, SP1-PA2B, SP1-PA2C, SP1-PA3A)

**Status:** `ARCHIVED_VERIFIED_UNEXERCISED`: SP1-PA2C committed two WalletWall-controlled mirror observations (Google
Cloud Storage and Cloudflare R2, each re-read byte for byte from its provider) and derived the production archive record
from them and SP1-PA2B's two acquisition observations; `PROVING_AVAILABILITY = ARCHIVED_VERIFIED_UNEXERCISED` and
`SELF_HOSTED_PATH_EXERCISED = false`: no real WalletWall Groth16 proof has been produced. The state is derived from the
committed evidence by `validate:sp1-circuit-tooling`, never set
([SP1-PA2C](#sp1-pa2c-two-walletwall-controlled-mirrors-the-record-admitted)). SP1-PA3A then built the evidence path
and the derivation by which a later, owner-authorized lane (SP1-PA3B) can move the state to
`SELF_HOSTED_PATH_EXERCISED` from committed facts alone; it generated no proof, and the state has not moved
([SP1-PA3A](#sp1-pa3a-the-proof-exercise-evidence-path-no-proof-generated)).

> Tooling is not an artifact, and an artifact is not proving. SP1-PA2A built the WalletWall-controlled path that
> installs SP1's Groth16 circuit v6.1.0 from a verified archive and proves from it; it downloaded nothing, pulled no
> image, generated no proof, deployed nothing and wrote to no chain.
>
> **Amended** ([AppleDouble metadata and binary provenance](#appledouble-metadata-and-binary-provenance-amendment)):
> the real archive, once acquired, held two kinds of macOS metadata the parser refused. The amendment characterized it
> read-only on both acquired copies and accepts exactly what was observed as ignored metadata, nothing wider.
>
> **SP1-PA2B** (owner-authorized acquisition): the real `v6.1.0-groth16.tar.gz` was acquired on two independent hosts,
> measured by three digest implementations each, accepted unchanged by the merged inspector on both, censused to the
> committed census on both, and the gnark image tag was resolved on both to one immutable digest. The production
> record is derived from those observations and from two mirror observations, never written by hand; it is admitted
> only when every fact holds, and then the tooling state, proving availability, the host-advisory assumption and the
> implementation receipt's binding follow from it. Archive provenance does not establish Groth16 soundness, no real
> proof has been produced, and nothing here is production readiness.
>
> **SP1-PA2C** (owner-authorized mirrors): the authenticated archive was written once to a dedicated Google Cloud
> Storage bucket and once to a Cloudflare R2 bucket, each object was re-read byte for byte from its provider by the
> committed measurement tool, and the record was derived from the four observations; proving availability, the tooling
> state, the host-advisory assumption and the receipt supersession followed from it by their own generators. Mirror
> ownership is not artifact identity, artifact identity is not proving, and proving is not production readiness.
>
> **SP1-PA3A** (no proof): the repository now knows how to recognize authoritative proof-exercise evidence. One real
> run through the archive-only gate, measured, and the designated verifier's acceptance of its proof are two
> committed observations; a record is derived from them, never written; and `SELF_HOSTED_PATH_EXERCISED` follows from
> exactly one accepted record on the accepted archive record, or not at all. No real proof exists, no image was
> pulled, nothing was downloaded, deployed or written to a chain, and `selfHostedPath.exercised` is still `false`.
> SP1-PA3B, under its own owner authorization, supplies the evidence; production binding is later still.

Research prototype. Not audited. Testnet/local only. Do not use real funds.

| | |
|---|---|
| Archive record, inspection, tar parser | [`scripts/lib/sp1-circuit-archive.ts`](../scripts/lib/sp1-circuit-archive.ts) (`walletwall.sp1-proving-archive.v2`; shape: [`evidence/zk/schema/sp1-proving-archive.v2.schema.json`](../evidence/zk/schema/sp1-proving-archive.v2.schema.json)) |
| Archive census (read-only, every entry) | [`scripts/lib/sp1-circuit-archive-census.ts`](../scripts/lib/sp1-circuit-archive-census.ts) (`sp1:circuit-archive:census`); the upstream archive's census on both hosts: [`circuit-archive-census-developer-workstation.raw.json`](../evidence/zk/sp1-impl/observations/circuit-archive-census-developer-workstation.raw.json), [`circuit-archive-census-github-hosted-runner.raw.json`](../evidence/zk/sp1-impl/observations/circuit-archive-census-github-hosted-runner.raw.json) |
| Installer, installed-tree verification | [`scripts/lib/sp1-circuit-install.ts`](../scripts/lib/sp1-circuit-install.ts) |
| Archive-only prove gate | [`scripts/lib/sp1-prove-gate.ts`](../scripts/lib/sp1-prove-gate.ts) |
| Tooling contract (generated, never hand-edited) | [`evidence/zk/sp1-impl/circuit-tooling.json`](../evidence/zk/sp1-impl/circuit-tooling.json), from [`scripts/lib/sp1-circuit-tooling.ts`](../scripts/lib/sp1-circuit-tooling.ts) |
| Upstream observation (measured from the pinned crates) | [`evidence/zk/sp1-impl/observations/circuit-upstream-developer-workstation.raw.json`](../evidence/zk/sp1-impl/observations/circuit-upstream-developer-workstation.raw.json) |
| Synthetic fixtures (test data only) | [`test/fixtures/sp1-proving-archives/`](../test/fixtures/sp1-proving-archives/), generated by [`scripts/lib/sp1-circuit-fixtures.ts`](../scripts/lib/sp1-circuit-fixtures.ts) |
| Acquisition observations, record derivation, state from facts (SP1-PA2B) | [`scripts/lib/sp1-circuit-acquisition.ts`](../scripts/lib/sp1-circuit-acquisition.ts); the two hosts' observations: [`circuit-acquisition-developer-workstation.raw.json`](../evidence/zk/sp1-impl/observations/circuit-acquisition-developer-workstation.raw.json), [`circuit-acquisition-github-hosted-runner.raw.json`](../evidence/zk/sp1-impl/observations/circuit-acquisition-github-hosted-runner.raw.json) |
| Proof-exercise observations, record derivation, state from facts (SP1-PA3A) | [`scripts/lib/sp1-proof-exercise.ts`](../scripts/lib/sp1-proof-exercise.ts) (`walletwall.sp1-proof-exercise.v1`; shape: [`evidence/zk/schema/sp1-proof-exercise.v1.schema.json`](../evidence/zk/schema/sp1-proof-exercise.v1.schema.json)); the authoritative directory `evidence/zk/sp1-impl/proof-exercises` holds nothing |
| Blocking, offline check | `npm run validate:sp1-circuit-tooling` in CI's `Build, lint & test` (it judges the archive evidence and the proof-exercise evidence too; `validate:sp1-proving-archive-record` and `validate:sp1-proof-exercise-record` are the same judgements on their own); `test/Sp1ProofExerciseVerifier.test.ts` re-executes a committed proof against the authenticated verifier runtime |
| Commands for the later lanes | `sp1:circuit-archive:inspect`, `sp1:circuit-install`, `sp1:prove:archive-only`; SP1-PA2B's `sp1:measure-circuit-acquisition`, `sp1:measure-circuit-mirror`, `sp1:proving-archive-record`; SP1-PA3A's `sp1:measure-proof-exercise`, `sp1:verify-proof-exercise`, `sp1:proof-exercise-record` (for SP1-PA3B; none has run a proof) |

## Four states, not interchangeable

| State | Means | Reached |
|---|---|---|
| 1. Tooling exists (`TOOLING_READY_NO_ARTIFACT`) | the inspection, installer and archive-only gate exist and pass their self-test; no WalletWall archive record exists | **SP1-PA2A** |
| 2. Verified archive exists (`ARCHIVED_VERIFIED_UNEXERCISED`) | an owner-authorized acquisition produced a record in `evidence/zk/sp1-impl/proving-archives`: two hosts agreeing on the archive's sha256, two WalletWall mirrors, the gnark image by digest | **SP1-PA2C** (the two mirror observations committed and the record derived; the acquisitions are SP1-PA2B's) |
| 3. Self-hosted proving path exercised (`SELF_HOSTED_PATH_EXERCISED`) | a real Groth16 proof of the designated program made through this gate from the archive, egress off, accepted by the designated verifier: exactly one committed proof-exercise record derived from the run and verification observations | not reached: **SP1-PA3A** built the derivation; the evidence is SP1-PA3B's, under its own owner authorization |
| 4. Production binding established | the implementation receipt's `PRODUCTION_SP1_BINDING`; needs, among other things, state 3 | not reachable here |

Before SP1-PA2A, main was `TOOLING_NOT_PRESENT`: no WalletWall inspection, installer or gate existed. The tooling
record's vocabulary is that state and the first three rows'; production binding is the implementation receipt's.

`validate:sp1-circuit-tooling` derives the state from facts, never from a string anyone sets: state 1 while
`evidence/zk/sp1-impl/proving-archives` holds nothing; state 2 only while it holds exactly the one record the
committed acquisition and mirror observations derive, accepted for designation d1 and committed with them
(`scripts/lib/sp1-circuit-acquisition.ts`, [below](#state-derived-from-facts)); state 3 only while, on top of state 2,
`evidence/zk/sp1-impl/proof-exercises` holds exactly the one record the committed run and verification observations
derive for that archive record (`scripts/lib/sp1-proof-exercise.ts`,
[below](#sp1-pa3a-the-proof-exercise-evidence-path-no-proof-generated)); anything else in either directory, or
proof-exercise evidence without an accepted archive record, derives no state and fails the validator. Proving
availability must name a status consistent with that state (the two pre-archive statuses for state 1,
`ARCHIVED_VERIFIED_UNEXERCISED` for state 2, `SELF_HOSTED_PATH_EXERCISED` for state 3), else the validator refuses the
pair as stale. The tooling record names each state and whether it is reached.

## What SP1 does on its own

Re-read for this lane from the `.crate` bytes `zkvm/host/Cargo.lock` pins (sp1-prover, sp1-recursion-gnark-ffi and
sp1-sdk 6.3.1, each checksum-verified), and recorded in the upstream observation:

- the circuit directory is `$SP1_GROTH16_CIRCUIT_PATH/v6.1.0`, the variable's value used verbatim (empty or relative
  resolves against SP1's working directory), else `~/.sp1/circuits/groth16/v6.1.0`;
- an existing directory is used as it is; an absent one makes SP1 download
  `https://sp1-circuits.s3-us-east-2.amazonaws.com/v6.1.0-groth16.tar.gz`, check **no** digest, and extract it with
  `tar -Pxzf`, which keeps absolute member names;
- `SP1_CIRCUIT_MODE=dev` selects development artifacts from another source (an S3 copy via the `aws` CLI, or a local
  build);
- `SP1_PROVER` picks the prover (`cpu`, `cuda`, `mock`, `light`, `network`), `cpu` when unset;
- the gnark prover runs as `docker run --rm -v <circuit dir>:/circuit <image>`: a read-write mount, no `--pull` flag
  (an absent image is pulled), and the image is `$SP1_GNARK_IMAGE` or the **mutable tag**
  `ghcr.io/succinctlabs/sp1-gnark:v6.1.0`.

That is why SP1's native downloader is outside WalletWall's accepted path: it would give SP1 custody of bytes nobody
authenticated, unpacked by a tool that writes wherever the archive's names say. On WalletWall's path SP1 never gets
custody of an unverified archive: WalletWall verifies and installs the circuit bytes before SP1 sees their directory.

## The archive record

`walletwall.sp1-proving-archive.v2` binds, for one archive, the **subject** (Groth16, circuit `v6.1.0`, designation
`mldsa65-withdrawal-d1`, its `PROGRAM_VKEY`, the designated verifier's version, runtime code hash and
`VERIFIER_HASH`, and `groth16_vk.bin` = sha256 `0x4388a21c…e696`, 492 bytes); the **archive** (file name, length,
sha256, acquisition time, source URL); **two acquisitions** from distinct hosts that agree on length and sha256; every
**member** (canonical path, length, sha256, sorted; never an AppleDouble name); every **metadata** entry (an
AppleDouble path, length, sha256 and the disposition `IGNORED_APPLEDOUBLE_METADATA`, sorted; an empty list when there
is none); the **gnark image** (repository, tag, immutable digest, how it was observed); and **two mirrors** WalletWall
controls, each naming the archive's sha256. v2 is v1 plus `metadata`: no v1 record was ever made, and a v1 record is
refused rather than read as one that declares no metadata.

The source URL and the image tag are recorded as `PROVENANCE_ONLY`, never authority. The members SP1 is known to read
(`constraints.json`, `groth16_circuit.bin`, `groth16_pk.bin`, `groth16_vk.bin`) are a floor, not the archive's
member set: that set is whatever the measured archive holds. A record counts only as a regular `.json` file directly
in `evidence/zk/sp1-impl/proving-archives`, and `sp1:circuit-install` and `sp1:prove:archive-only` refuse any other
location, and any record or anchor evidence (`evidence/zk/sp1/designations`, `proving-availability.json`) that is not
exactly what HEAD commits (`EVIDENCE_NOT_COMMITTED`). The commands read that evidence from the checkout they live in,
never from the working directory, so a crafted directory with its own evidence cannot make a fixture "production".
That directory holds none, and must not until the acquisition lane admits a record: the existing proving-availability
generator refuses any file there.

The record's acquisitions, mirrors and gnark observation are recorded assertions: the validator checks their form and
agreement (two distinct host labels agreeing on length and sha256, two distinct locations naming the archive's
sha256), not that those hosts or mirrors exist. Producing that evidence is the acquisition lane's job. The JSON Schema
documents the shape and is weaker than the validator (it does not reject `..` or device names, for example): validate
with `archiveRecordErrors`, never with the schema alone.

The `groth16_vk.bin` check is an **integrity and compatibility** check: the key a proof is made under must be the key
the designated verifier embeds, so a mismatched archive is refused whatever its own hash. It is not evidence that the
Groth16 trusted setup behind that key is sound; that is an upstream assumption the designated verifier inherits, and
archiving changes nothing about it. Likewise archive provenance (where it came from, who downloaded it) is not
cryptographic soundness: soundness is the verifier's. A wrong `groth16_pk.bin` or circuit yields proofs the verifier
refuses, a liveness failure, never a forged proof.

## Inspection

`inspectArchive` reads an archive offline, never through `tar(1)`, a listing, or SP1:

1. with a record: the record must be accepted for the designation, and the archive's length and sha256 must be the
   record's **before any byte is parsed**;
2. a structured push parser (ustar and GNU headers, checksums verified) accepts only regular files and directories,
   and refuses: absolute, drive-qualified (`C:/`), UNC and backslash paths; `..`, `.` and empty components (repeated
   or mixed separators); NUL in a name field; any character outside POSIX's portable set; trailing dots and Windows
   device names; names over 100 bytes; symlinks, hard links, character and block devices, FIFOs and every other entry
   type (tar has no socket type: any unlisted type is refused); setuid, setgid and sticky modes (never applied here,
  but an accepted archive must be benign under `tar(1)` too); PAX global headers, GNU long names and links, PAX keys
   other than `path`, `size` and inert metadata (so `linkpath`, `hdrcharset` and sparse maps are refused), a PAX path
   that differs from the header name, and a PAX size that disagrees with one the header can carry; a PAX value that is
   not UTF-8 (one closed exception, below); duplicate paths, aliases (`./a` and `a`), case-fold collisions, a file
   that is another entry's parent, file/directory collisions and directories with no member beneath them; every
   AppleDouble-shaped entry outside the closed policy (below); data after the end-of-archive block; and archives past
   the entry, byte, PAX and decompression bounds;
3. with a record, an entry the record does not name, or names at another length, is refused **at its header**,
   before its bytes are read, and so is an AppleDouble entry its metadata does not name or names with another body;
4. the bytes parsed must be the bytes authenticated (the second pass re-hashes the raw archive), the members must be
   exactly the record's, with `groth16_vk.bin` the anchor's, and every metadata entry the record names must be there.

Without a record (measuring a candidate for a future record) every entry rule still applies, the four members SP1 reads
must be present, and `groth16_vk.bin` must be the designated key.

## AppleDouble metadata and binary provenance (amendment)

The owner-authorized acquisition (SP1-PA2B) fetched `v6.1.0-groth16.tar.gz` on two hosts. Both measured 6,211,807,514
bytes, sha256 `18beebb6…a9147810`, and both copies were refused by this inspector at byte 0 on `"._."`. The archive was
packed by macOS `bsdtar`, which adds the file's extended attributes twice. The amendment first characterized the
archive read-only, with no policy change. The census (`sp1:circuit-archive:census`, a second tar walker independent of
the parser) ran on the developer workstation's copy and on a GitHub-hosted runner. Host B's first copy was deleted by
its ephemeral runner after measurement, so the runner re-acquired the bytes and stopped unless they were exactly the
agreed sha256 and length. Both census files are byte-identical (sha256 `e39376dd…`) and committed. On each host the
census was also cross-checked, outside the repository, against CPython's `tarfile` (3.13 on the workstation, 3.12 on
the runner): the listings agreed with the census field by field on all 16 entries, and with each other. That check
and its listings are in the pull request, not committed evidence. The archive holds 24 tar headers: 8 PAX headers and 16 entries, which
are the root directory, seven files (`groth16_vk.bin` = the designated key) and eight AppleDouble entries. Two things in
it were refused, and the amendment accepts exactly those two:

| | Observed (both copies) | Accepted as ignored metadata only when |
|---|---|---|
| **AppleDouble entries** (`IGNORED_APPLEDOUBLE_METADATA`) | `._.` before the root directory entry, and `./._<name>` before each of the seven files; each a 163-byte regular file without a PAX header, all one body (an AppleDouble v2 header, an empty Finder Info holding one `com.apple.provenance` attribute, an empty resource fork), sha256 `a8d7edca…0e0` | the path is exactly one of the eight observed (`APPLEDOUBLE_PATHS`); it is a regular file with no PAX header and the observed body; and the **very next entry** (PAX headers aside) is the one it describes: the root directory for `._.`, the regular file `<name>` for `._<name>` |
| **Binary provenance** (`IGNORED_PROVENANCE_METADATA`) | in every PAX header (the root's and the seven files'), `SCHILY.xattr.com.apple.provenance` = the 11 raw bytes `0102002d0e23b75bfde87a` (not UTF-8: it holds a NUL; sha256 `a6373f30…b8d`), beside its base64 twin `LIBARCHIVE.xattr.com.apple.provenance` | the key is exactly that; the raw value is exactly those bytes (compared byte for byte, never decoded, interpreted or applied as an extended attribute); it is on one of those eight entries by path **and** kind, at most once each; and once any entry carries it, all eight do by the end of the archive |

What still fails closed, each pinned by a hostile archive (`M01`–`M40`, `X01`–`X36`), starting with AppleDouble:

- A path with any `._` component is never a circuit member, in the archive or in a record.
- Outside the policy it is refused: an unobserved name (even with its companion), nested, `._._x`, `._`, `._x.`,
  `._..`, a case variant, a directory, a link, an oversized or other body, a PAX header on it, an orphan, an entry
  after its companion, or a duplicate.
- Other dotfiles (`.DS_Store`, `__MACOSX/`) are not AppleDouble and stay ordinary entries, refused unless a record
  names them.

Then provenance:

- The provenance key with any other bytes, even UTF-8 ones, is refused.
- So is the right value on any other entry, a case variant, a directory or AppleDouble entry of the same name, a
  repeated root entry, two PAX headers for one entry, or one or more missing occurrences.
- So is a lookalike key: suffix, prefix, case, a leading space, a leading byte-order mark, or the `LIBARCHIVE.` twin.
- So are the same bytes under `comment`, `mtime`, `path`, `size` or `linkpath`; a key that is not UTF-8; the key twice
  in one header; and a dangling or global PAX header.
- A provenance header that tries to stand in for an AppleDouble entry's companion is refused.

Two older gaps in the PAX and root handling were closed with the amendment:

- **The byte-order mark.** The UTF-8 decoder used to drop a leading byte-order mark (U+FEFF), so a `path` value
  starting with one could read as the header's own name. It now preserves the mark.
- **The root's spelling.** The root directory is now accepted only as `.` or `./`. A root named `/` (the filesystem
  root under `tar -P`), an empty name or `.//` is refused, and none of them can satisfy `._.`'s companion or the root's
  provenance occurrence.

Only `path` and `size` can name a path or a size, and they stay strict UTF-8.

**What is not closed.** Other extended-attribute PAX records keep PA2A's inert-metadata rule. That covers the
provenance record's base64 twin `LIBARCHIVE.xattr.com.apple.provenance`, and any `LIBARCHIVE.xattr.*` or
`SCHILY.xattr.*` record with a UTF-8 value. They are accepted on any entry and never applied: the installer applies no
extended attribute. Closing them as the binary provenance record is closed would be a further owner decision.

The archive's sha256 stays the authority and covers the metadata bytes. The record's `metadata` lists each AppleDouble
entry with its path, length, sha256 and disposition, and the validator holds every entry to the policy, including
that the member it describes is a record member. The provenance occurrences are bound by the constants (the value,
the eight entries) and reported by `inspectArchive` as `provenance`. Metadata never reaches the installer's writer, so
it is never extracted or installed. An AppleDouble file planted in an installation fails re-verification, like any
extra file.

The constants (`APPLEDOUBLE_PATHS`, `APPLEDOUBLE_BODIES`, `PROVENANCE_VALUE`, `PROVENANCE_ENTRIES`) are the census,
not a reading of it. `validate:sp1-circuit-tooling` requires each committed census file to be exactly the census tool's
output (line ends aside), both to be one census, and every constant to be exactly what that census observed. That
covers the AppleDouble paths and bodies, each AppleDouble entry's type, PAX header, companion and absence of
collisions, the provenance value's sha256 and length, and the set of entries carrying it.
Another circuit version, or this one packed another way, needs its own two-host census and a reviewed amendment. These
constants are never widened.

## Installation

`sp1:circuit-install -- --archive <file> --record <record> --destination-root <absolute dir>` installs at
`<root>/v6.1.0`, the directory SP1 reads as `$SP1_GROTH16_CIRCUIT_PATH/v6.1.0`:

- every archive and entry rule runs first, and nothing is written until it passes;
- extraction happens a second time, into a fresh private staging directory beside the target (one filesystem, so the
  last step is one rename), never into an existing circuit directory; every file is created exclusively
  (`O_CREAT|O_EXCL`), every directory once; links and special files cannot be created, because the parser hands only
  regular files to the writer;
- the extracted bytes must be the authenticated bytes, and the staged tree, re-read from disk, must be exactly the
  record (no link, special file, extra file or directory);
- the tree is made read-only and renamed into place. An existing target (file, link, populated or empty directory) is
  refused and left as it was; there is no merge, force or overwrite mode, and any failure removes the staging
  directory. One narrow exception: on POSIX, an empty directory another process creates in the instant between the
  last existence check and the rename is replaced by the rename (`rename(2)` semantics; Node offers no
  `RENAME_NOREPLACE`). It held nothing, so nothing is overwritten.

Use a destination root that holds nothing else: the gate refuses a root with any entry besides `v6.1.0`.

Read-only permissions are a liveness and integrity hardening, **not** the authority. Installation authenticates bytes
when it runs; a privileged local process could change them later. The pre-prove re-hash is the authority.

## The archive-only prove gate

`sp1:prove:archive-only -- --record <record> --circuit-root <absolute dir> --host <mldsa65-host> --inputs <json>` runs
the host's local Groth16 path (`mldsa65-host prove <inputs>`) only after, in this order:

| Check | Refusal |
|---|---|
| the record is a production record, exactly as committed, accepted for the designation read from the committed evidence of the command's own checkout | `RECORD_NOT_AUTHORITATIVE`, `EVIDENCE_NOT_COMMITTED`, `RECORD_INVALID` |
| the circuit root is absolute, normalized, not a UNC share, and safe inside docker's `-v src:dest` | `CIRCUIT_ROOT_INVALID` |
| the caller's environment selects nothing the gate does not freeze (below) | `ENV_REFUSED`, `GNARK_IMAGE_NOT_PINNED`, `GNARK_IMAGE_CONFLICT` |
| the host executable and the inputs are absolute regular files | `PROVE_INPUT_INVALID` |
| the gnark image is in the local docker store by the record's digest (`docker image inspect`: offline, never a pull) | `GNARK_IMAGE_NOT_LOCAL` |
| `<root>` holds `v6.1.0` and nothing else, and `v6.1.0`, re-hashed now, is exactly the record's members, each with one link | `CIRCUIT_ARCHIVE_NOT_INSTALLED`, `CIRCUIT_ROOT_INVALID`, `CIRCUIT_INTEGRITY_FAILED` |
| the host is POSIX, the user is not the superuser, `<root>`'s path can be changed only by its owner (no link on the way; no ancestor writable by others unless sticky), the installation is the owner's alone; then `<root>` is locked read-only for the run | `PROVE_HOST_UNSUPPORTED`, `CIRCUIT_ROOT_INVALID` |
| under the lock: re-hashed again, and its identity (device, inode, links, size, mode, times of every entry) taken; then the host is spawned | `CIRCUIT_INTEGRITY_FAILED` |
| after the host exits, whether or not it succeeded, before the lock is released: the same bytes **and** the same identity; then status 0, and a proof naming `PROGRAM_VKEY` whose first four bytes are the verifying key's selector | `CIRCUIT_INTEGRITY_FAILED_AFTER_PROVE`, `PROVER_FAILED`, `PROVER_SPAWN_FAILED`, `PROOF_OUTPUT_REFUSED` |

Proving through the gate is POSIX-only, as SP1 proving is: on Windows the gate refuses to run the host
(`PROVE_HOST_UNSUPPORTED`), because the lock it depends on is a POSIX permission. Inspection and installation work on
both.

The child gets a constructed environment, never the caller's:

| | |
|---|---|
| Frozen (a caller value must be identical, or is refused) | `SP1_PROVER=cpu`, `SP1_GROTH16_CIRCUIT_PATH=<verified root>`, `SP1_GNARK_IMAGE=<repository>@sha256:<digest>`, `DOCKER_CONTEXT=default` |
| Refused when set | `SP1_CIRCUIT_MODE` (any value), `SP1_PLONK_CIRCUIT_PATH`, `WITHOUT_VK_VERIFICATION`, `SKIP_SIMULATION`, every `NETWORK_*`; a `DOCKER_HOST` that is not an absolute `unix:///` socket (POSIX) or a `npipe:////./pipe/<name>` on this machine (Windows) |
| Passed through | process basics only: `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `TMPDIR`, `TMP`, `TEMP`, `SYSTEMROOT`, `WINDIR`, `PATHEXT`, `USERPROFILE`, `XDG_RUNTIME_DIR`, `DOCKER_HOST`, `DOCKER_CONFIG`, `RUST_LOG`, `RUST_BACKTRACE` |
| Dropped (named on stderr, never their values) | everything else, `LD_PRELOAD`, proxies and SP1's tuning knobs included |

Names are compared case-insensitively for refusal (Windows reads `sp1_circuit_mode` as `SP1_CIRCUIT_MODE`). The
upstream observation lists all 57 variables the pinned sp1/slop crates read; `validate:sp1-circuit-tooling` fails if
the variable that selects the circuit directory, the gnark image or the prover is not frozen, if the development-mode
variable is not refused, or if the gate passes through any variable SP1 reads other than the reviewed `HOME` (which only
locates `~/.sp1`, replaced by the frozen circuit path). On Windows, libuv adds a fixed set of system variables to every
child (`HOMEDRIVE`, `SYSTEMROOT`, `USERPROFILE`, ...); none selects a circuit, prover or image.

**A tag is never sufficient.** `ghcr.io/succinctlabs/sp1-gnark:v6.1.0` names whatever the registry serves today, so the
gate accepts only `registry/repository@sha256:<digest>` (no tag beside it, fully qualified), refuses `:latest`,
`:v6.1.0`, any tag-only or malformed reference, and a local image that matches the repository but not the digest.

### Why SP1 cannot fall back to its downloader through this gate

SP1 downloads only when `$SP1_GROTH16_CIRCUIT_PATH/<the version compiled into the host>` is absent, and pulls only when
the image is absent. The gate always sets `SP1_GROTH16_CIRCUIT_PATH` itself, to a root it has just verified holds the
full installation and nothing else, and refuses before spawning when the root or the circuit directory is missing
(`CIRCUIT_ARCHIVE_NOT_INSTALLED`), when either is not the record's tree, when a caller tries another root, an empty one
or development mode, and when the digest-pinned image is not local. The tests prove each refusal happens with zero
calls to the spawner.

Two ways around that were found by the adversarial review and are closed by the run lock: a host binary built against
another SP1 reads `<root>/<its own version>`, finds it absent and downloads; and a process that can write `<root>`
moves the verified directory away mid-run, so SP1 fetches a fresh copy whose bytes match the record. With `<root>`
read-only for the run, the first fails to create its directory instead of downloading, and the second cannot rename
the directory. Should either happen anyway (the owner or the superuser undoing the lock), the identity comparison after
the run refuses a tree that has the same bytes at other inodes.

## Time of check, time of use

The gate re-hashes every installed file to decide, again under the run lock immediately before it starts the host,
and again after the host exits; it opens each file with `O_NOFOLLOW` and `O_NONBLOCK`, checking the descriptor itself
(a regular file with exactly one link). It also compares the installation's identity before and after the run, so a
tree removed and re-created with the same bytes is refused, and it runs those after-run checks even when the host
fails. What remains, and is outside this lane's fully eliminated threat surface:

- the root's owner (the operator's own user) or the superuser can undo the lock and rewrite or replace proving inputs,
  the host binary included, during the run; the after-run checks detect a change that persists, not one reverted in
  between;
- SP1's gnark container mounts the circuit directory read-write and runs as root inside it, so the pinned image could
  write there; the after-run checks detect, not prevent, that;
- `docker run` has no `--pull=never`: if the image is removed between the gate's check and SP1's `docker run`,
  docker pulls it again, by digest (the same bytes, but a network fetch);
- a local `DOCKER_HOST` socket that is forwarded to another machine would mount that machine's directory;
- a flooding host is killed, not its docker child or container, and a run has no overall time limit (proofs take
  hours);
- the gate is not the only way to run the host: running `mldsa65-host` directly still lets SP1 download. The proving
  lane should also run with network egress blocked, so a download fails even if every other control did.

Proving from a private copy made per session was considered and not adopted: it doubles the 6+ GB of disk and I/O, a
same-user or root process can rewrite the copy just as well, and the gnark container's mount is the same either way.
The read-only root lock is the low-complexity part that holds against every other user; closing the race against the
owner and root needs an OS-level sandbox, a different lane.

## SP1-PA2B: the real archive acquired, measured, recorded

SP1-PA2A was the tooling and the closed archive policy; SP1-PA2B is the owner-authorized acquisition of the real
archive, independently measured, and the record derived from those measurements. It establishes that WalletWall has
independently identified, authenticated, recorded and (once the mirror observations are committed) mirrored the exact
proving artifacts its designated verifier expects. It does not establish that the upstream Groth16 trusted setup is
sound, that real proving works, or production readiness. No proof was generated, no image was pulled, nothing was
deployed or installed, and no chain was written.

### What each host measured

Both hosts acquired `v6.1.0-groth16.tar.gz` from the upstream URL (provenance only, never authority) and were measured
by `npm run sp1:measure-circuit-acquisition` (`scripts/measure-sp1-circuit-acquisition.ts`), which writes one
observation per host (`walletwall.sp1-circuit-acquisition.v1`): the transfer's provenance, the host's independent
digests, the merged inspector's measurement, the census, and the gnark image resolved from the registry.

| | Host A, `developer-workstation` | Host B, `github-hosted-runner` |
|---|---|---|
| Copy | the SP1-PA2B copy acquired 2026-10-17 22:16:46–22:22:39 UTC (curl over HTTPS, remote 3.5.90.58), kept unmodified; located, never rewritten | a fresh GitHub-hosted runner (run 39178864704 on the measure-only branch `measure/sp1-circuit-acquisition-2`, `ba56a622`, image ubuntu24 20261012.334.1) downloaded the URL itself 2026-10-19 00:01:07–00:02:38 UTC (remote 3.5.93.98); it never received host A's bytes |
| Length | 6,211,807,514 bytes (Content-Length agreed) | 6,211,807,514 bytes (Content-Length agreed) |
| sha256 | `18beebb6cd0cc9b4d4a240ee4f49511da6c2a7e51724bad4232de538a9147810` by the inspector (Node crypto), coreutils and certutil | the same, by the inspector, coreutils and OpenSSL |
| Merged PA2A inspector (measuring mode, anchor d1) | accepted: 7 members, `groth16_vk.bin` 492 bytes = the designated `VERIFIER_HASH`, 8 AppleDouble entries and 8 provenance records ignored, no directory | identical, member for member |
| Census | sha256 `e39376dd…` = the committed census | the same; CPython `tarfile` agreed on all 16 entries |
| `ghcr.io/succinctlabs/sp1-gnark:v6.1.0` | OCI index `sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d`, linux/amd64 image manifest `sha256:be8555f1ad90870acd8c6ec7fd3ba0b1a2133ea9cddf25e130665aa651129e54`; cross-checked with `docker buildx imagetools inspect --raw` | the same digests, the same cross-check |

The members, in archive order: `groth16_vk.bin` (492), `groth16_circuit.bin` (2,437,991,441),
`SP1VerifierGroth16.sol` (3,236), `groth16_pk.bin` (5,862,173,061), `Groth16Verifier.sol` (26,770),
`constraints.json` (111,997,113), `groth16_witness.json` (2,802,920); each sha256 is in the observations and in the
record. The AppleDouble entries and the provenance records are exactly the amendment's closed policy, on both copies;
nothing new was observed, so the policy was not widened (a new member, path, body, key, value or occurrence on either
copy would have stopped the lane, as would any disagreement between the hosts).

Host independence is the rationale the validator cannot check: different machines, operating systems, networks and
dates, with each host's identity lines and transfer window recorded in its observation. What the validator does check
is that the two observations agree on every measured fact and that each is bound to the committed measurement script
by sha256; two files on one filesystem that merely agree are not two acquisitions, which is why the hosts' identities
are recorded for review rather than derived.

### The gnark image: an immutable digest, the tag provenance only

The pinned prover defaults to the mutable tag `ghcr.io/succinctlabs/sp1-gnark:v6.1.0`. Each host resolved it through
the OCI distribution API with an anonymous pull token (manifests only, a few KB; nothing pulled): the raw index bytes
hash to the digest above, which equals the registry's `Docker-Content-Digest`; the index is a multi-platform
`application/vnd.oci.image.index.v1+json` listing one linux/amd64 image manifest (fetched by digest and re-hashed)
and one attestation manifest. The record pins `ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62…` (the index: what
`docker pull` by digest resolves and what `docker image inspect` reports as the repo digest), and names the
linux/amd64 manifest and its config digest in the observation's method so the platform is unambiguous. The prove gate
sets `SP1_GNARK_IMAGE` to that digest-pinned reference and refuses a tag. The image's bytes are not archived under
WalletWall's control: the digest is supply-chain identity, not proof-system correctness, and not availability.

### Two WalletWall-controlled mirrors

A mirror counts only as a mirror observation (`walletwall.sp1-circuit-mirror.v1`, one file
`evidence/zk/sp1-impl/observations/circuit-archive-mirror-<id>.raw.json` per location) written by
`npm run sp1:measure-circuit-mirror -- --location <as the record names it> --url <https URL> --control "<who controls it>"
--host <label> --expect-bytes 6211807514 --expect-sha256 18beebb6…`: it re-reads the location byte for byte and
records the host and path (never a signed URL's query or a token), the length and sha256 served, and the verdict.
The record requires at least two, each serving exactly the archive's bytes, at the owner's two providers only: a
location is `gs://<bucket>/<object>` (Google Cloud Storage) or `r2://<account>/<bucket>/<object>` (Cloudflare R2, the
account its 32-hex id), with no query, fragment, credential or whitespace (a signed URL is never a location), and the
re-read must have been served by that provider's host for that object (`storage.googleapis.com/<bucket>/<object>` or
`<bucket>.storage.googleapis.com/<object>`; `<account>.r2.cloudflarestorage.com/<bucket>/<object>` or
`<bucket>.<account>.r2.cloudflarestorage.com/<object>`): a re-read from any other host (the upstream host or its
domain, a CDN, a release page) or of another object than the location names is refused. Two mirrors are two objects:
one object under two addressing styles or spellings is one mirror. The upstream Succinct S3 location is never a mirror.
"Controlled by WalletWall" is an assertion the observation records and the validator cannot verify, and a mirror
observation is a re-read at one moment: **a recorded mirror assertion is not continuously verified availability.**
Two mirrors improve availability; they do not prove eternal availability, and the record says so.

The owner chose Google Cloud Storage and Cloudflare R2 as the two locations. Establishing them (buckets, uploads) was
an owner act in the owner's cloud accounts; SP1-PA2B carried the tooling that records them and derives the record, and
the two acquisition observations. Until both mirror observations were committed, no record existed and the state
stayed `TOOLING_READY_NO_ARTIFACT`; SP1-PA2C committed them
([below](#sp1-pa2c-two-walletwall-controlled-mirrors-the-record-admitted)).

### The record, derived

`npm run sp1:proving-archive-record` derives `evidence/zk/sp1-impl/proving-archives/v6.1.0-groth16.json`
(`walletwall.sp1-proving-archive.v2`, created once, never overwritten) from the committed observations:
`deriveArchiveRecord` is a pure function of designation d1's anchor, the acquisition observations and the mirror
observations, and `acquisitionErrors` names every reason they derive none. The record binds the subject (designation,
circuit `v6.1.0`, `PROGRAM_VKEY`, verifier version, runtime code hash, `VERIFIER_HASH`, the verifying key's length
and hash); the archive (file, length, sha256, the earliest acquisition time, the source URL as provenance); one
acquisition per host, each agreeing; every member and every ignored AppleDouble entry, sorted; the gnark repository,
tag (provenance) and index digest with its observation; and the mirrors, each naming the archive's sha256. The record
then passes the unchanged PA2A validator (`archiveRecordErrors`) and, against the real archive, the production
inspector (`sp1:circuit-archive:inspect -- --archive <file> --record <record>`: exact member and metadata sets, the
designated key), which the measure-only runner also runs when its checkout holds a record.

### State, derived from facts

`productionArchiveEvidence` judges the archive directory: no record (state 1); exactly the one record, named after the
archive, that is byte for byte what the committed observations derive, accepted by the PA2A validator for d1's anchor,
with the two acquisition observations present (each file holding its own host's observation, each carrying that
host's identity line: the runner its run id, the workstation its operating system), bound to the committed scripts (a
script absent from the checkout binds nothing) and agreeing on every fact, each a copy whose length, sha256, members
and AppleDouble entries are exactly the committed census's, their image the pinned prover's and resolved to one index
digest with one linux/amd64 manifest, at least two mirror observations at distinct objects at the two providers
serving the archive's bytes, and every one of these files exactly as HEAD commits them (state 2); anything else is
refused with every reason. The transition fails, independently, for: a record absent, a second file, a record that is
a link, another schema, another designation or key, another tar sha256 or length, one acquisition, a host counted
twice, two labels that are not the lane's two, one acquisition relabeled as the other (one transfer window, one
measurement time, one image-resolution time or one set of identity lines under two labels), hosts that disagree, a
copy that is not the censused archive (its length, sha256, a member or an AppleDouble entry), an observation with a
field the schema does not name (a refusal marker beside an inspection, say), fewer than two mirrors, one object twice,
a mirror outside the two providers, a re-read of another object than its location names, a mirror serving other bytes
or sitting upstream, a tag without a digest, hosts resolving the tag to different images, a member missing or added,
metadata other than the census-derived policy, uncommitted evidence, or a record outside the authoritative directory. `selfHostedPath.exercised` stays `false`: SELF_HOSTED_PATH_EXERCISED is never derived
here. Each of those failures is pinned by a test in `test/Sp1CircuitAcquisition.test.ts`.

### What admission changes, and what it does not

When the record is derived, `npm run sp1:proving-availability` regenerates the availability record (its own generator
owns it; it is never hand-edited): status `ARCHIVED_VERIFIED_UNEXERCISED`, the tarball's measured length and sha256,
the archived members' digests, the image digest, the accepted record and its observations, and the one remaining
owner action (authorize the proving run). `npm run sp1:circuit-tooling` regenerates the tooling record with the state
and the acquisition facts. Two couplings then follow, each honest rather than silent:

- **#220 (host advisories):** `A_NO_PROVING_WITHOUT_ARCHIVE` is restated to hold in both states: availability is
  `OWNER_DOWNLOAD_REQUIRED` (no record, no local copy) or `ARCHIVED_VERIFIED_UNEXERCISED` (exactly the accepted
  record), never an unverified local copy where SP1 reads; the self-hosted path is unexercised and proves only from a
  verified archive. The record is regenerated offline (`npm run sp1:host-advisories`) and stays `ASSESSMENT_VALID`;
  rustls's conditional finding keeps its reachability. The stronger statement this lane supports is still only:
  **WalletWall has a gate capable of refusing the built-in circuit downloader
  once verified artifacts exist.** It is not yet "WalletWall proving never exercises the downloader"; that needs the
  exercised-proof lane. `zkvm/host/Cargo.lock` is untouched, so `HOST_LOCKFILE_REMEDIATION =
  DEFER_TO_NEXT_PROGRAM_REBUILD` stands.
- **#221 (receipt integration):** the implementation receipt binds `PROVING_AVAILABILITY` and the availability
  file's digest, read from the working tree, so admitting the record would make every descendant derive another
  receipt. The receipt is never restamped: `npx tsx scripts/generate-sp1-impl-receipt.ts --supersession --lane SP1-PA2B
  --record <the record> --reason "<why>"` writes `evidence/zk/sp1-impl/receipt-supersession.json`, which pins the
  receipt's bytes and names the first-parent main commit where it was last live; `validate:sp1-impl-receipt` then
  derives that one status and that one file's digest at that commit, read from git, and everything else live. A
  supersession is refused unless the live availability record validates and names an archived state, so it cannot
  hide a live refusal or be filed while nothing moved ([docs/SP1_Impl_Receipt_Integration.md](SP1_Impl_Receipt_Integration.md)).
  No `contracts/` file changes, so the integration binding is byte-identical.

### What SP1-PA2B establishes, and what it does not

- Established: WalletWall independently identified (two hosts, the same bytes), authenticated (the designated key,
  member by member, under the closed metadata policy), recorded (the derived record) and, once the mirror observations
  are committed, mirrored (two locations re-read byte for byte) the exact proving artifacts its designated verifier
  expects, and pinned the gnark image by its immutable digest.
- Not established: that the Groth16 trusted setup behind the `v6.1.0` key is sound (verifying-key equality is
  integrity and compatibility, never trusted-setup proof); that the self-hosted proving path works, on what hardware,
  or within the 2-day rotation delay (no real proof has been produced; no wall-clock or memory figure exists); that
  the mirrors stay available (recorded at one moment, never continuously verified); that the image digest is more
  than supply-chain identity; production readiness (the receipt's `PRODUCTION_SP1_BINDING` stays `NOT_ESTABLISHED`).
  An availability problem is not converted into a trust claim.

### Next: SP1-PA3, the self-hosted proving exercise (not executed here)

Install exclusively from the committed verified archive (`sp1:circuit-install`), with the digest-pinned gnark image
in the local store and network egress off; generate one real Groth16 proof of designation d1's program through
`sp1:prove:archive-only`; verify it through the designated verifier path; record peak memory and wall time and compare
them with the 2-day rotation delay; only then `SELF_HOSTED_PATH_EXERCISED`. That lane needs its own owner
authorization. SP1-PA3A built the evidence path and the derivation for it
([below](#sp1-pa3a-the-proof-exercise-evidence-path-no-proof-generated)); SP1-PA3B is the execution.

## SP1-PA2C: two WalletWall-controlled mirrors, the record admitted

SP1-PA2B left one fact missing: two real WalletWall-controlled mirrors, each independently re-read from its provider.
SP1-PA2C (owner-authorized) supplied it and nothing else. It uploaded the authenticated archive (the SP1-PA2B host A
copy, re-measured before upload to exactly 6,211,807,514 bytes and sha256 `18beebb6…a9147810`, and accepted again by
the merged inspector) to the two providers the owner named, re-read each object through `sp1:measure-circuit-mirror`,
committed the two observations, and ran the admission chain exactly as designed above. It changed no decision code,
grammar, schema, policy or state derivation, pulled no image, generated no proof, deployed nothing and wrote to no
chain.

### The two mirrors

| | Google Cloud Storage | Cloudflare R2 |
|---|---|---|
| Location (as the record names it) | `gs://walletwall-sp1-archive-328o457ytfv/sp1/v6.1.0/v6.1.0-groth16.tar.gz` | `r2://b69bb874d4dd3937e1255b8527a84854/walletwall-sp1-archive/sp1/v6.1.0/v6.1.0-groth16.tar.gz` |
| Provider identity | generation `1792387232081573`, one non-composite object, created 2026-10-19T05:20:32Z; the provider's MD5 equals the source file's | ETag `"f65a0bc730b4d3bd7bc54d7531acd515-60"`, Last-Modified 2026-10-19 04:22:08 GMT (R2 keeps no generations) |
| Written | once, 2026-10-19 03:56:49–05:20:33Z, `gcloud storage cp --no-clobber` with composite uploads disabled, into a dedicated bucket that was empty (public access prevention enforced, uniform bucket-level access) | once, 2026-10-19 03:57:45–04:22:09Z, a 60-part S3 multipart upload with SigV4 header authentication into a private bucket; `HEAD` 404 before, 200 after |
| Re-read | 05:21:21–05:29:28Z from `storage.googleapis.com/<bucket>/<object>` with a short-lived OAuth bearer token in an environment variable; no signed URL | 04:39:00–04:44:08Z from `<account>.r2.cloudflarestorage.com/<bucket>/<object>` through a one-hour SigV4 presigned GET given to the unchanged tool as an argument; the tool records host and path, never the query |
| Served | HTTP 200, `Content-Length` 6211807514, 6,211,807,514 bytes, sha256 `18beebb6…a9147810`: `AGREES` | the same: `AGREES` |
| Observation | [`circuit-archive-mirror-gcs.raw.json`](../evidence/zk/sp1-impl/observations/circuit-archive-mirror-gcs.raw.json) | [`circuit-archive-mirror-r2.raw.json`](../evidence/zk/sp1-impl/observations/circuit-archive-mirror-r2.raw.json) |

Both observations bind `scripts/measure-sp1-circuit-mirror.ts` by sha256. Independence, as far as the validator checks
it: two providers, two canonical object identities, each re-read served by its own provider's host for exactly the
object its location names, two separate reads and tool invocations, one content digest, and no upstream host. Two
mirrors are two objects, never two addressing styles, signed URLs or cache copies of one. **Each observation establishes
content identity at measurement time, not continuous availability**; "controlled by WalletWall" is an assertion the
observation records and the validator cannot verify.

### The record and what followed from it

`npm run sp1:proving-archive-record` derived
[`evidence/zk/sp1-impl/proving-archives/v6.1.0-groth16.json`](../evidence/zk/sp1-impl/proving-archives/v6.1.0-groth16.json)
(`walletwall.sp1-proving-archive.v2`) from the four committed observations, and the availability generator refused to
read the record until the record itself was committed: designation `mldsa65-withdrawal-d1`; the archive, 6,211,807,514
bytes, sha256 `18beebb6…a9147810`; two acquisitions (`developer-workstation`, `github-hosted-runner`); 7 members;
8 ignored AppleDouble metadata entries, exactly the PA2A policy; the designated verifying key (492 bytes,
`0x4388a21c…e696`); the gnark image pinned by its OCI index digest `sha256:e1a1cd62…48c4d` with the linux/amd64
manifest `sha256:be8555f1…29e54` named in the observation method, the tag provenance only; two mirrors, each naming
the archive's sha256. The record passed the unchanged PA2A validator, `validate:sp1-proving-archive-record`, and the
production inspector against the real archive bytes (`sp1:circuit-archive:inspect -- --archive <host A copy> --record
<the record>`: exact member and metadata sets, the designated key).

Then, each by its own generator and never by hand: `sp1:proving-availability` wrote status
`ARCHIVED_VERIFIED_UNEXERCISED` with the measured tarball, the archived members' digests, the image digest, the accepted
record and its four observations, and one remaining owner action (authorize SP1-PA3); `sp1:circuit-tooling` derived
state `ARCHIVED_VERIFIED_UNEXERCISED` with `acquisition.state = ACCEPTED` (its `lane` field names SP1-PA2B, the lane
that built the derivation it runs; SP1-PA2C supplied the evidence); `sp1:host-advisories` regenerated the record in the
archived state (`A_NO_PROVING_WITHOUT_ARCHIVE` holds: exactly the one accepted record, never an unverified local copy;
still `ASSESSMENT_VALID` and still `NOT_DEPENDENCY_SAFE`, nothing patched); and
`generate-sp1-impl-receipt.ts --supersession --lane SP1-PA2C` filed
[`receipt-supersession.json`](../evidence/zk/sp1-impl/receipt-supersession.json), pinning the historical receipt's bytes
and reading its `PROVING_AVAILABILITY` at `ab26dd6b`, the last first-parent main commit where it was live. The receipt
itself is byte-identical; nothing was restamped.

### What SP1-PA2C establishes, and what it does not

- Established: WalletWall now controls two independently measured copies of the exact authenticated artifact SP1-PA2A
  and SP1-PA2B characterized, and the committed evidence derives the archived state without assertion or manual
  status-setting: `TOOLING_READY_NO_ARTIFACT` → `ARCHIVED_VERIFIED_UNEXERCISED`, with
  `SELF_HOSTED_PATH_EXERCISED = false`.
- Not established: that the mirrors stay available (each observation is a re-read at one moment; the GCS object is not
  versioned and R2 keeps no versions, so a later overwrite is caught only by the next re-read, or by the installer and
  prove gate, which re-hash the archive before every use); that the Groth16 trusted setup behind the key is sound
  (archive hashing establishes identity, never proving-system soundness); that the self-hosted path proves at all, on
  what hardware, or within the 2-day rotation delay (no real WalletWall Groth16 proof has been produced; no wall-clock
  or memory figure exists); production readiness (`PRODUCTION_SP1_BINDING` stays `NOT_ESTABLISHED`).
- Next lane: SP1-PA3, [above](#next-sp1-pa3-the-self-hosted-proving-exercise-not-executed-here), under its own owner
  authorization. Nothing here is production ready.

## SP1-PA3A: the proof-exercise evidence path (no proof generated)

Three lanes, kept apart. **SP1-PA2C**: verified archived artifacts exist. **SP1-PA3A** (this section): the
repository knows how to recognize authoritative proof-exercise evidence, and no real proof exists. **SP1-PA3B**: the
owner-authorized first real self-hosted proof exercise, whose committed evidence moves the state. **Production
binding**: later still, and established by neither. SP1-PA3A changed no rule of `sp1:prove:archive-only`
(the committed production record, the exact installed circuit, the exact digest-pinned image, `SP1_PROVER=cpu`, the
refused modes and `NETWORK_*` variables, the local docker endpoint, the unprivileged POSIX host, the locked root, the
proof bound to the designated `PROGRAM_VKEY` and selector) and pulled no image, downloaded nothing, deployed nothing
and wrote to no chain.

### Five facts, never confused

Artifact identity (the archive record: SP1-PA2B/C), proving execution (the run), verifier acceptance (the designated
verifier's answer), performance (wall time and memory against the 2-day rotation delay) and production readiness (the
implementation receipt's). The proof-exercise record carries the first four and never the fifth: an exercised path is
liveness on one host at one time, never soundness of the Groth16 trusted setup and never production readiness.

### Facts -> observations -> record -> state

- **The run observation** (`walletwall.sp1-proof-exercise-run.v1`,
  `evidence/zk/sp1-impl/observations/proof-exercise-run-<host>.raw.json`) is written by
  `sp1:measure-proof-exercise` (`scripts/measure-sp1-proof-exercise.ts`, Linux only), which refuses before any act
  unless the record is a production record exactly as committed and the checkout is clean, probes egress (name
  resolution and TCP 443 at the archive's upstream host and the gnark image's registry), runs the **unchanged** gate
  (`runArchiveOnlyProve`, every check of `sp1:prove:archive-only`) through a spawner that measures the host, probes
  egress again, and records: the checkout (this repository, HEAD, the designated host source tree), the committed
  anchor and archive record (by sha256), the installation the gate re-hashed (exactly the record's members), the host
  executable and the proof input (`zkvm/fixtures/mldsa65-withdrawal.inputs.json`) by sha256, the gnark image by the
  record's digest and the local store's repo digests, the prover mode and the gate's frozen environment (names only
  of what passed through or was dropped), the probes before and after with the operator's statement of the
  enforcement, the gate's and the host's wall time (monotonic, rounded up) with their stamps, the host process's peak
  RSS (`/proc/<pid>/status` VmHWM) and the gnark containers' sampled memory (`docker stats` at a fixed interval), and
  the proof (vkey, public values, bytes, the selector, both digests). It asserts nothing.
- **The verification observation** (`walletwall.sp1-proof-exercise-verification.v1`,
  `evidence/zk/sp1-impl/observations/proof-exercise-verification-<host>.raw.json`) is written by
  `sp1:verify-proof-exercise` (`scripts/verify-sp1-proof-exercise.ts`, `hardhat run`): the CREATE2-authenticated
  v6.1.0 initcode SP1-TD1 recorded, accepted only as its keccak is the designation's, is deployed on the development
  chain, the code hash at the address is measured, and `verifyProof` is asked with the proof and with its tampered
  copy (the last public-value bit flipped, as SP1-TD1's chain-execution check does); a check on a deployed chain can
  be added (the designation's CREATE2 address, the same code hash required). It binds the run observation's
  **committed** bytes and the proof's digests; `acceptance` is computed from the chain's answers, never set.
- **The record** (`walletwall.sp1-proof-exercise.v1`, `evidence/zk/sp1-impl/proof-exercises/<designation>.json`) is
  derived by `sp1:proof-exercise-record` from the two committed observations, write-once, never by hand; it carries
  every binding and the performance facts (`wallClockSeconds`, `hostSeconds`, `rotationDelaySeconds` = 172800,
  `withinRotationDelay`, the fraction, both peak-memory figures), and names what it establishes and what it does not.
- **The state** follows from the record: `toolingState` and `provingAvailabilityStatus` take the judged exercise
  evidence beside the judged archive evidence; `selfHostedPath.exercised` and `selfHostedPath.record` in
  `proving-availability.json` follow the accepted record, `exercises` counts the directory, and the host-advisory
  assumption `A_NO_PROVING_WITHOUT_ARCHIVE` holds in the exercised state only with exactly that record on disk and in
  the availability record. Stale generated outputs are refused as they are today: each generator's validator compares
  the committed file with what the evidence derives, byte for byte.

### State, derived from facts (SP1-PA3A)

`productionExerciseEvidence` judges `evidence/zk/sp1-impl/proof-exercises`: no record (state 2 stays); or exactly the
one record named after the designation, a regular file, that is byte for byte what the committed run and
verification observations derive (exactly one of each, each file holding its own host's observation), for the
accepted archive record (its committed bytes by sha256, its members, its gnark digest), bound to the committed tools
by sha256, with the run's source commit in this repository's history and the designation's host source tree, and
every one of these files exactly as HEAD commits them (state 3); anything else is refused with every reason, never
read as "no record". The transition fails, independently, for each of: no record; `selfHostedPath.exercised` or the
state string hand-set (the generated files no longer match their derivation); another designation; another
archive-record sha256 or archive sha256; another circuit version; another `PROGRAM_VKEY`; another host tree or an
unmeasured host executable; another proof-input digest; another gnark digest, or a tag in place of the digest; a
prover mode other than `cpu`, or an environment other than the gate's frozen one, or a refused variable; egress
resolved or connected at any required target, a probe without a refusal code, probes missing, or probes taken inside
the run window; a verifier rejection, a tampered copy accepted, a check at another code hash, no check of the
authenticated runtime, or a verification of another proof or another run; a zero, negative or impossible wall time
(the host run outside the gate run, seconds that do not match the stamps); a malformed or missing peak-memory
measurement; an uncommitted observation or record; a run observation edited after it was verified; a second record,
a link, a duplicate or stray observation, a relabeled host; a record outside the authoritative directory (which is
then no record); an exercise of another commit or baseline; and the archive record changed or removed after the
exercise record exists (exercise evidence without an accepted archive derives no state at all). Each is pinned by a
test in [`test/Sp1ProofExercise.test.ts`](../test/Sp1ProofExercise.test.ts), and the transition itself is proved
reachable there in a temporary repository with synthetic observations, so the real checkout's `NO_RECORD` is a fact
about its evidence, not a dead branch.

### The verifier path, re-executed

A pure validator cannot execute a pairing, so the verification observation records the designated verifier's answer
and [`test/Sp1ProofExerciseVerifier.test.ts`](../test/Sp1ProofExerciseVerifier.test.ts) is the layer that
re-executes it on every run: the authenticated runtime is deployed on the development chain, its code hash must be
the designation's, SP1-TD1's real mainnet proof verifies and its tampered copy reverts `ProofInvalid` (the positive
control), a flipped byte and a synthetic proof are refused, and whenever a proof-exercise record is committed, its
proof must verify there. A verification observation forged without a proof the runtime accepts fails that suite.

### What SP1-PA3A establishes, and what it does not

- Established: the repository recognizes authoritative proof-exercise evidence and derives the third state from it,
  through generators and validators and never through an edit; every invariant above refuses on its own; the
  derivation is reachable (synthetic evidence in a test repository) and not reached (the real checkout: no record,
  `selfHostedPath.exercised = false`, `ARCHIVED_VERIFIED_UNEXERCISED`).
- Not established: that the self-hosted path proves at all, on what hardware, or within the rotation delay (no proof
  has been made); anything about egress, memory or wall time (nothing was measured); that the Groth16 trusted setup
  behind the key is sound (a proof the verifier accepts is compatibility with the key, never soundness); production
  readiness (`PRODUCTION_SP1_BINDING` stays `NOT_ESTABLISHED`). SP1-PA3A is not proving availability.
- Residuals of the evidence model, once SP1-PA3B runs it: egress is attested by probes at the edges of the run and by
  the operator's statement of the enforcement, not watched during it, and a container's egress is covered only as
  far as the host's enforcement reaches the docker bridge; the containers' peak memory is sampled (a lower bound);
  one host, one run, one time; a committed observation names its tool by sha256 and binds every fact the repository
  holds, but the validator cannot know that the host was a distinct machine or that the enforcement was what the
  operator stated (the same limit SP1-PA2B records for its hosts and mirrors).

### SP1-PA3B: what the owner must supply (not started)

1. Authorize the run and, on a Linux host, obtain the exact gnark image by the committed digest
   (`ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62…48c4d`, so that `docker image inspect` lists it by that digest).
2. Install the circuit only from the committed v2 archive record (`sp1:circuit-install` from one of the two recorded
   mirrors, verified against the record) into a root only the operator's user can change.
3. Build or use the designated `mldsa65-host` from the designated host source tree (the checkout's `zkvm/host` at the
   commit the run names; the observation records the tree and the executable's sha256).
4. Disable egress on the host (and the docker bridge) by a stated enforcement; the probes must find name resolution
   and TCP 443 refused at `sp1-circuits.s3-us-east-2.amazonaws.com` and `ghcr.io` before and after the run.
5. Run exactly one proof: `npm run sp1:measure-proof-exercise -- --record evidence/zk/sp1-impl/proving-archives/v6.1.0-groth16.json --circuit-root <root> --host <mldsa65-host> --inputs zkvm/fixtures/mldsa65-withdrawal.inputs.json --host-label <label> --enforcement "<statement>" --out evidence/zk/sp1-impl/observations/proof-exercise-run-<label>.raw.json`
   from a clean checkout; commit the observation.
6. Verify: `SP1_PROOF_EXERCISE_RUN=<that file> SP1_PROOF_EXERCISE_HOST=<label> SP1_PROOF_EXERCISE_OUT=evidence/zk/sp1-impl/observations/proof-exercise-verification-<label>.raw.json npm run sp1:verify-proof-exercise`
   (add `SP1_PROOF_EXERCISE_DEPLOYED=1 -- --network <name>` for a deployed-chain check); commit the observation.
7. Derive: `npm run sp1:proof-exercise-record`, then `sp1:proving-availability`, `sp1:circuit-tooling` and
   `sp1:host-advisories`, each by its own generator; state the new status at the top of this page; commit, and every
   validator and suite above passes on the commit with `SELF_HOSTED_PATH_EXERCISED` derived from facts. No production
   binding and no deployment in that lane.

## Relation to #220 and #221 (SP1-PA2A)

- **#220 (host advisories):** still `ASSESSMENT_VALID`; SP1-PA2B's restatement of its archive assumption is
  [above](#what-admission-changes-and-what-it-does-not), and SP1-PA2C regenerated the record in the archived state
  (`A_NO_PROVING_WITHOUT_ARCHIVE` holds for exactly the one accepted record; nothing patched, still
  `NOT_DEPENDENCY_SAFE`).
- **#221 (receipt integration):** no `contracts/` change, so the historical implementation receipt and its
  integration binding are byte-identical; SP1-PA2C filed the supersession SP1-PA2B designed
  (`evidence/zk/sp1-impl/receipt-supersession.json`, lane `SP1-PA2C`, the receipt pinned by sha256, its
  `PROVING_AVAILABILITY` read at `ab26dd6b`), and `validate:sp1-impl-receipt` passes through it.

## Evidence

- `npm run validate:sp1-circuit-tooling` (CI): re-derives the tooling record, including the self-test: the safe
  synthetic archive inspects, installs and passes the gate with a stub image store; the upstream-shaped synthetic
  archive inspects with its eight AppleDouble entries and eight provenance records ignored, and installs its members
  only; every hostile archive meets its refusal; d1's anchor refuses every fixture (`SUBJECT_MISMATCH`, `VK_MISMATCH`);
  no production record exists; and the two census observations are one census, from which every metadata constant
  derives.
- Suites: [`test/Sp1CircuitArchive.test.ts`](../test/Sp1CircuitArchive.test.ts),
  [`test/Sp1CircuitInstall.test.ts`](../test/Sp1CircuitInstall.test.ts),
  [`test/Sp1ProveGate.test.ts`](../test/Sp1ProveGate.test.ts),
  [`test/Sp1CircuitTooling.test.ts`](../test/Sp1CircuitTooling.test.ts),
  [`test/Sp1CircuitArchiveCensus.test.ts`](../test/Sp1CircuitArchiveCensus.test.ts). Link and FIFO cases run on POSIX
  (CI).
- Hostile catalog: 153 archives (21 path, 18 link, special-type and mode, 18 ambiguity, 11 structure and bound,
  9 integrity, 40 AppleDouble, 36 binary provenance), each pinned by refusal code and reason.
- SP1-PA2B: [`test/Sp1CircuitAcquisition.test.ts`](../test/Sp1CircuitAcquisition.test.ts) (the observations, the
  agreement rules, the derived record, the committed evidence in a temporary repository, the state) and
  [`test/Sp1ImplReceiptSupersession.test.ts`](../test/Sp1ImplReceiptSupersession.test.ts); the committed acquisition
  observations are re-checked against the committed script, census and designation on every run.
- SP1-PA2C: the two mirror observations are re-checked against the committed script and the record on every run; the
  adversarial closeout (a throwaway clone of the lane commit, each attempted state inflation refused by the validators)
  is in its pull request.
- SP1-PA3A: [`test/Sp1ProofExercise.test.ts`](../test/Sp1ProofExercise.test.ts) (the two observations' validators,
  the derived record, the committed-evidence judge in a temporary repository, the state transitions, the
  measurement helpers with injected readers, the commands) and
  [`test/Sp1ProofExerciseVerifier.test.ts`](../test/Sp1ProofExerciseVerifier.test.ts) (the designated runtime on the
  development chain); `npm run validate:sp1-proof-exercise-record` is the exercise judgement on its own, and the real
  checkout answers "no proof-exercise record".
- Mutation and adversarial review: see the pull requests.

## Reproduce

```bash
npm run validate:sp1-circuit-tooling
npm run validate:sp1-proving-archive-record
npm run validate:sp1-proof-exercise-record
npx hardhat test test/Sp1CircuitArchive.test.ts test/Sp1CircuitInstall.test.ts test/Sp1ProveGate.test.ts test/Sp1CircuitTooling.test.ts test/Sp1CircuitArchiveCensus.test.ts test/Sp1CircuitAcquisition.test.ts test/Sp1ImplReceiptSupersession.test.ts test/Sp1ProofExercise.test.ts test/Sp1ProofExerciseVerifier.test.ts
# re-measure the upstream observation (offline; needs a CARGO_HOME holding the pinned crates)
npm run sp1:measure-circuit-upstream -- --cargo-home ~/.cargo && npm run sp1:circuit-tooling
# census an acquired archive (read-only; prints JSON that depends only on the archive's bytes)
npm run --silent sp1:circuit-archive:census -- --archive v6.1.0-groth16.tar.gz
# SP1-PA2B, on a host that acquired the archive (curl -D headers.txt -w '<json>' > transfer.json as the runner does;
# --source-url <URL> records the URL asked for when a redirect made the effective URL differ, the default):
npm run sp1:measure-circuit-acquisition -- --archive v6.1.0-groth16.tar.gz --host <label> --transfer transfer.json \
  --headers headers.txt --started-at <UTC> --finished-at <UTC> --digest coreutils=@sha256.txt --digest openssl=@sha256-openssl.txt \
  --gnark-image ghcr.io/succinctlabs/sp1-gnark:v6.1.0 --platform-file runner.txt \
  --out evidence/zk/sp1-impl/observations/circuit-acquisition-<label>.raw.json
# a WalletWall-controlled mirror, re-read byte for byte (the URL's query and any token are never recorded):
npm run sp1:measure-circuit-mirror -- --location "<as the record names it>" --url "<https URL>" --control "<controller>" \
  --host <label> --expect-bytes 6211807514 --expect-sha256 18beebb6cd0cc9b4d4a240ee4f49511da6c2a7e51724bad4232de538a9147810 \
  --out evidence/zk/sp1-impl/observations/circuit-archive-mirror-<id>.raw.json
# then, with both mirror observations committed: derive the record and let every dependent record follow from it
npm run sp1:proving-archive-record && npm run sp1:proving-availability && npm run sp1:circuit-tooling && npm run sp1:host-advisories
npx tsx scripts/generate-sp1-impl-receipt.ts --supersession --lane SP1-PA2C \
  --record evidence/zk/sp1-impl/proving-archives/v6.1.0-groth16.json --reason "the archive record moved proving availability"
# and state the new status at the top of this page (`PROVING_AVAILABILITY = ARCHIVED_VERIFIED_UNEXERCISED`): the
# tooling suite holds the page to the status the evidence derives; commit the record, the observations, the
# regenerated records, the supersession and the page together, then every validator above passes on the commit
# and verify the record against the real archive wherever the archive is:
npm run sp1:circuit-archive:inspect -- --archive v6.1.0-groth16.tar.gz --record evidence/zk/sp1-impl/proving-archives/v6.1.0-groth16.json
```

## Limits

The parser's rules (100-byte names, portable characters, no long-name forms, the listed PAX keys, UTF-8 values) stay
strict by design. The two exceptions above are the census of one archive: they are widened by nothing but a new census
and a reviewed amendment. The environment census covers literal environment reads in the sp1-* and slop-* crates' `src/`;
other crates' reads reach the host only through the pass-through list. CI binds the upstream observation to the host
lockfile and its script but cannot re-read the crates (it holds no crate cache); any host that has them re-derives it
with `npm run sp1:measure-circuit-upstream -- --cargo-home <dir> --check`. The gate's rules are constants, so a forged
observation could hide a future SP1 change, never widen the gate. The gate does not bind the host binary: a host for
another circuit is stopped by the lock (it cannot create its directory) and by the proof's selector and `PROGRAM_VKEY`
checks, and the designated verifier refuses another program.
