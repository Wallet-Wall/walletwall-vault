# SP1 circuit install and archive-only prove gate (SP1-PA2A, SP1-PA2B, SP1-PA2C, SP1-PA3A, SP1-PA3B, SP1-PA3C, SP1-PA3D0)

**Status:** `SELF_HOSTED_PATH_EXERCISED`: SP1-PA3B (owner-authorized) made the first real WalletWall Groth16 proof of
the designated program through the unchanged archive-only gate, on a Linux proving host with network egress refused,
from the committed verified archive, with the digest-pinned gnark image, the canonical-build host binary and the
committed proof input; the designated verifier (the CREATE2-authenticated v6.1.0 runtime) accepted the proof and
refused its tampered copy. The run took 647 s of wall time (the host process 606 s), 0.37 % of the 2-day rotation
delay, with a host-process peak resident set (`VmHWM`) of 23,366,266,880 bytes, a lower bound of its demand under the
host's 24 GB memory cap with swap in use, and 18,962,280,612 bytes sampled in the gnark container.
`PROVING_AVAILABILITY = SELF_HOSTED_PATH_EXERCISED` and `selfHostedPath.exercised = true`, derived from the two
committed observations and the record by `validate:sp1-circuit-tooling`, never set
([SP1-PA3B](#sp1-pa3b-the-first-real-self-hosted-proof-exercise)). An exercised path is liveness on one host at one
time: it is not proof-system soundness and not production readiness, and `PRODUCTION_SP1_BINDING` stays
`NOT_ESTABLISHED`. The earlier states remain as reached: SP1-PA2C admitted the archive record
([SP1-PA2C](#sp1-pa2c-two-walletwall-controlled-mirrors-the-record-admitted)) and SP1-PA3A built the evidence path and
the derivation that SP1-PA3B's evidence now satisfies
([SP1-PA3A](#sp1-pa3a-the-proof-exercise-evidence-path-no-proof-generated)). SP1-PA3B's v1 record is history and
stays the authoritative evidence of the first real exercise; since SP1-PA3D0 the exercise directory holds history
([SP1-PA3D0](#sp1-pa3d0-the-exercise-directory-holds-history-no-proof-generated)), so a future attributed (v2)
exercise is recorded beside it, never in its place, and two records are still this one state. No v2 exists yet.

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
> exactly one accepted record on the accepted archive record, or not at all. At the time no real proof existed, no
> image was pulled, nothing was downloaded, deployed or written to a chain, and `selfHostedPath.exercised` was still
> `false`.
> SP1-PA3B, under its own owner authorization, supplies the evidence; production binding is later still.
>
> **SP1-PA3B** (owner-authorized, one proof): the gate was run once, unchanged, on a Linux proving host whose egress
> was refused by a stated and rehearsed packet filter, from the committed archive installed by the committed
> installer, with the gnark image local by its committed digest and the host binary the canonical procedure
> reproduced byte for byte; the designated verifier accepted the proof and refused its tampered copy; the two
> observations were committed as written and the record derived from them. Proving succeeded on one host at one time:
> that is liveness of the self-hosted path, not soundness of the trusted setup and not production readiness.
>
> **SP1-PA3C** (no proof): tooling for a future exercise to watch its whole window and attribute every network
> attempt in it ([SP1-PA3C](#sp1-pa3c-continuous-egress-attribution-for-future-proof-exercises-no-proof-generated)):
> a root kernel-probe observer, a derivation that judges its capture, and a v2 evidence contract beside v1. SP1-PA3B's
> evidence is unchanged and stays edge-probed only: its unattributed refused packets remain unattributed.
>
> **SP1-PA3D0** (no proof): the exercise directory holds history, never ambiguity
> ([SP1-PA3D0](#sp1-pa3d0-the-exercise-directory-holds-history-no-proof-generated)). SP1-PA3B's v1 record keeps its
> path and bytes; a v2 record of a future attributed exercise goes beside it under a name derived from its own run
> observation, every record is judged on its own and the directory as a whole, two records are one state, each keeps
> its own egress assurance, and the directory's git history must show no committed record withdrawn or edited.
> Nothing was proved, observed or captured; no v2 record exists.

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
| Proof-exercise observations, record derivation, state from facts (SP1-PA3A) | [`scripts/lib/sp1-proof-exercise.ts`](../scripts/lib/sp1-proof-exercise.ts) (`walletwall.sp1-proof-exercise.v1`; shape: [`evidence/zk/schema/sp1-proof-exercise.v1.schema.json`](../evidence/zk/schema/sp1-proof-exercise.v1.schema.json)); the authoritative directory `evidence/zk/sp1-impl/proof-exercises` holds SP1-PA3B's v1 record in its slot, [`mldsa65-withdrawal-d1.json`](../evidence/zk/sp1-impl/proof-exercises/mldsa65-withdrawal-d1.json), and admits one v2 record beside it (`mldsa65-withdrawal-d1.v2.<token>.json`, SP1-PA3D0; none exists yet); SP1-PA3B's record is derived from [`proof-exercise-run-developer-workstation-wsl2.raw.json`](../evidence/zk/sp1-impl/observations/proof-exercise-run-developer-workstation-wsl2.raw.json) and [`proof-exercise-verification-developer-workstation-wsl2.raw.json`](../evidence/zk/sp1-impl/observations/proof-exercise-verification-developer-workstation-wsl2.raw.json) |
| Blocking, offline check | `npm run validate:sp1-circuit-tooling` in CI's `Build, lint & test` (it judges the archive evidence and the proof-exercise evidence too; `validate:sp1-proving-archive-record` and `validate:sp1-proof-exercise-record` are the same judgements on their own); `test/Sp1ProofExerciseVerifier.test.ts` re-executes every committed proof against the authenticated verifier runtime |
| Commands for the later lanes | `sp1:circuit-archive:inspect`, `sp1:circuit-install`, `sp1:prove:archive-only`; SP1-PA2B's `sp1:measure-circuit-acquisition`, `sp1:measure-circuit-mirror`, `sp1:proving-archive-record`; SP1-PA3A's `sp1:measure-proof-exercise`, `sp1:verify-proof-exercise`, `sp1:proof-exercise-record` (each run exactly once by SP1-PA3B) |
| Continuous egress attribution (SP1-PA3C) | the root observer [`scripts/sp1-egress-observer.ts`](../scripts/sp1-egress-observer.ts) (run from a root-owned copy; it alone starts the attributed tool [`scripts/measure-sp1-attributed-proof-exercise.ts`](../scripts/measure-sp1-attributed-proof-exercise.ts)); the derivation [`scripts/lib/sp1-egress-attribution.ts`](../scripts/lib/sp1-egress-attribution.ts); `walletwall.sp1-proof-exercise-run.v2` and `walletwall.sp1-proof-exercise.v2` beside v1 in [`scripts/lib/sp1-proof-exercise.ts`](../scripts/lib/sp1-proof-exercise.ts) |

## Four states, not interchangeable

| State | Means | Reached |
|---|---|---|
| 1. Tooling exists (`TOOLING_READY_NO_ARTIFACT`) | the inspection, installer and archive-only gate exist and pass their self-test; no WalletWall archive record exists | **SP1-PA2A** |
| 2. Verified archive exists (`ARCHIVED_VERIFIED_UNEXERCISED`) | an owner-authorized acquisition produced a record in `evidence/zk/sp1-impl/proving-archives`: two hosts agreeing on the archive's sha256, two WalletWall mirrors, the gnark image by digest | **SP1-PA2C** (the two mirror observations committed and the record derived; the acquisitions are SP1-PA2B's) |
| 3. Self-hosted proving path exercised (`SELF_HOSTED_PATH_EXERCISED`) | a real Groth16 proof of the designated program made through this gate from the archive, egress off, accepted by the designated verifier: every committed proof-exercise record accepted, each derived from its own run and verification observations (SP1-PA3B's v1 alone today; a v2 beside it is still this state, SP1-PA3D0) | **SP1-PA3B** (the run and verification observations committed and the record derived; SP1-PA3A built the derivation) |
| 4. Production binding established | the implementation receipt's `PRODUCTION_SP1_BINDING`; needs, among other things, state 3 | not reachable here |

Before SP1-PA2A, main was `TOOLING_NOT_PRESENT`: no WalletWall inspection, installer or gate existed. The tooling
record's vocabulary is that state and the first three rows'; production binding is the implementation receipt's.

`validate:sp1-circuit-tooling` derives the state from facts, never from a string anyone sets: state 1 while
`evidence/zk/sp1-impl/proving-archives` holds nothing; state 2 only while it holds exactly the one record the
committed acquisition and mirror observations derive, accepted for designation d1 and committed with them
(`scripts/lib/sp1-circuit-acquisition.ts`, [below](#state-derived-from-facts)); state 3 only while, on top of state 2,
`evidence/zk/sp1-impl/proof-exercises` holds only records its contract admits, each exactly the record its own
committed run and verification observations derive for that archive record, and its history shows none withdrawn
(`scripts/lib/sp1-proof-exercise.ts`, [below](#sp1-pa3a-the-proof-exercise-evidence-path-no-proof-generated) and
[SP1-PA3D0](#sp1-pa3d0-the-exercise-directory-holds-history-no-proof-generated)); anything else in either directory, or
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
  resolution and TCP 443 at the archive's upstream host and the gnark image's registry, and TCP 443 at the
  acquisitions' upstream addresses and two canary addresses, which must be refused at the connection), runs the
  **unchanged** gate
  (`runArchiveOnlyProve`, every check of `sp1:prove:archive-only`) through a spawner that measures the host, probes
  egress again, and records: the checkout (this repository, HEAD, the designated host source tree), the committed
  anchor and archive record (by sha256), the installation the gate re-hashed (exactly the record's members), the host
  executable by sha256 (it must be the canonical-build host binary the committed canonical rebuild observation names
  for the designated host tree) and the proof input (`zkvm/fixtures/mldsa65-withdrawal.inputs.json`) by sha256, the
  gnark image by the
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
  the committed file with what the evidence derives, byte for byte. (SP1-PA3D0 keeps this for every record the
  directory admits: `selfHostedPath.record` became `selfHostedPath.witnesses`, and the assumption accounts for every
  record on disk: [SP1-PA3D0](#sp1-pa3d0-the-exercise-directory-holds-history-no-proof-generated).)

### State, derived from facts (SP1-PA3A)

As SP1-PA3A built it (SP1-PA3D0 holds every record the directory admits to the same judgement, each on its own:
[SP1-PA3D0](#sp1-pa3d0-the-exercise-directory-holds-history-no-proof-generated)), `productionExerciseEvidence`
judges `evidence/zk/sp1-impl/proof-exercises`: no record (state 2 stays); or exactly the
one record named after the designation, a regular file, that is byte for byte what the committed run and
verification observations derive (exactly one of each, each file holding its own host's observation), for the
accepted archive record (its committed bytes by sha256, its members, its gnark digest), bound to the committed tools
by sha256, with the run's source commit in this repository's history and holding what the run claims it ran from (the
designated host tree at `zkvm/host`, the archive record and the measurement tool as committed), the host executable
the canonical-build host binary for the designated host tree, the observations and the record regular LF files in
their directories, and every one of these files exactly as HEAD commits them (state 3); anything else is refused
with every reason, never read as "no record". The transition fails, independently, for each of: no record;
`selfHostedPath.exercised` or the state string hand-set (the generated files no longer match their derivation);
another designation; another archive-record sha256 or archive sha256; another circuit version; another
`PROGRAM_VKEY`; another host tree, a host executable other than the canonical-build binary, or a commit in the
history that does not hold the designated host tree, the archive record or the tool; another proof-input digest;
another gnark digest, or a tag in place of the digest; a prover mode other than `cpu`, or an environment other than
the gate's frozen one, or a refused variable; egress resolved or connected at any required target, a probe without a
refusal code, a probe at an address refused only by name resolution, a required address probe missing, probes
missing, or a probe taken inside the run window or more than ten minutes from it; a verifier rejection, a tampered
copy accepted, a check at another code hash, no check of the
authenticated runtime, or a verification of another proof or another run; a zero, negative or impossible wall time
(the host run outside the gate run, seconds that do not match the stamps); a malformed or missing peak-memory
measurement; an uncommitted observation or record, or one committed with CRLF line ends; a run observation edited
after it was verified; a second record, a record or an observation that is a link, a duplicate or stray observation,
a relabeled host; a record outside the authoritative directory (which is
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
- Residuals of the evidence model, once SP1-PA3B runs it. **The designated verifier proves the proof's validity under
  the designated key, never its provenance**: that the proof was made through the gate, with `SP1_PROVER=cpu`, with
  egress refused, by the canonical host binary, in the recorded time and memory are the operator's observations. The
  repository binds them as far as it can (the proof's digests; the run's commit content; the canonical host binary;
  the committed input; the probes' shape, codes and timing); the rest rests on the owner's review of the pull request
  that commits them, and a valid proof of the designated program made by any other means, wrapped in self-consistent
  observations, is refused only by that review. Egress is attested by probes within ten minutes before and after the
  run and by the operator's statement of the enforcement, not watched during it, and a container's egress is covered
  only as far as the host's enforcement reaches the docker bridge; the containers' peak memory is sampled (a lower
  bound); one host, one run, one time; a run over the 2-day rotation delay is still an exercised path (the record
  carries `withinRotationDelay = false` and the availability record says EXCEEDING), never a timely one; the
  validator cannot know that the host was a distinct machine (the same limit SP1-PA2B records for its hosts and
  mirrors).

### SP1-PA3B: what the owner must supply (since executed: [SP1-PA3B](#sp1-pa3b-the-first-real-self-hosted-proof-exercise))

1. Authorize the run and, on a Linux host, obtain the exact gnark image by the committed digest
   (`ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62…48c4d`, so that `docker image inspect` lists it by that digest).
2. Install the circuit only from the committed v2 archive record (`sp1:circuit-install` from one of the two recorded
   mirrors, verified against the record) into a root only the operator's user can change.
3. Use the canonical-build `mldsa65-host`: the committed canonical rebuild observation names its sha256 for the
   designated host tree (`fc8eff69…abf1b` for `30f72596…`); a host built on the proving host is admitted only by first
   extending that observation there under the canonical procedure, since the run observation's executable sha256
   must be that binary's.
4. Disable egress on the host (and the docker bridge) by a stated enforcement; within ten minutes before and after
   the run the probes must find name resolution and TCP 443 refused at `sp1-circuits.s3-us-east-2.amazonaws.com` and
   `ghcr.io`, and the connection refused at the acquisitions' upstream addresses (`3.5.90.58`, `3.5.93.98`) and the
   canaries `1.1.1.1` and `8.8.8.8` on TCP 443.
5. Run exactly one proof: `npm run sp1:measure-proof-exercise -- --record evidence/zk/sp1-impl/proving-archives/v6.1.0-groth16.json --circuit-root <root> --host <mldsa65-host> --inputs zkvm/fixtures/mldsa65-withdrawal.inputs.json --host-label <label> --enforcement "<statement>" --out evidence/zk/sp1-impl/observations/proof-exercise-run-<label>.raw.json`
   from a clean checkout; commit the observation.
6. Verify: `SP1_PROOF_EXERCISE_RUN=<that file> SP1_PROOF_EXERCISE_HOST=<label> SP1_PROOF_EXERCISE_OUT=evidence/zk/sp1-impl/observations/proof-exercise-verification-<label>.raw.json npm run sp1:verify-proof-exercise`
   (add `SP1_PROOF_EXERCISE_DEPLOYED=1 -- --network <name>` for a deployed-chain check); commit the observation.
7. Derive: `npm run sp1:proof-exercise-record`, then `sp1:proving-availability`, `sp1:circuit-tooling` and
   `sp1:host-advisories`, each by its own generator; state the new status at the top of this page; commit, and every
   validator and suite above passes on the commit with `SELF_HOSTED_PATH_EXERCISED` derived from facts. No production
   binding and no deployment in that lane.

## SP1-PA3B: the first real self-hosted proof exercise

SP1-PA3A left one fact missing: a real proof. SP1-PA3B (owner-authorized) supplied it and nothing else: one run of
the unchanged archive-only gate under measurement, the designated verifier's answer, and the record derived from the
two. It changed no decision code, no gate rule, no schema, no designation, no `PROGRAM_VKEY`, no verifier identity, no
archive record and no mirror; it deployed nothing and wrote to no chain. The transition
`ARCHIVED_VERIFIED_UNEXERCISED` → `SELF_HOSTED_PATH_EXERCISED` is the generators' reading of the committed evidence,
not a line anyone wrote.

### The proving host, prepared before the boundary

| | |
|---|---|
| Host | `developer-workstation-wsl2`: the SP1-PA2B acquisition workstation (AMD Ryzen 7 9800X3D, 8 cores / 16 threads) running Ubuntu 24.04.4 LTS in WSL2 (kernel 6.18.33.1-microsoft-standard-WSL2), its virtual machine capped at 24 GB of memory with 40 GB of swap, raised for this lane from the default 16 GB before the run (the preparation logs show 16.3 GB at 23:06Z and 24.6 GB at 23:24Z); an unprivileged user (uid 1001), as the gate's POSIX guard requires |
| Docker | a native Docker Engine (Ubuntu `docker.io` 29.1.3) inside that distribution, reached at `unix:///var/run/docker.sock`, context `default`; no Docker Desktop integration, so the gnark container's bridge is in the proving host's own network namespace |
| Checkout | a clone of this repository at protected main `da7936bb…` (the merge of SP1-PA3A), `zkvm/host` tree `30f72596…`, clean when the measurement started |
| gnark image | pulled by the committed digest before the boundary: `docker image inspect` lists exactly `ghcr.io/succinctlabs/sp1-gnark@sha256:e1a1cd62…48c4d` (39,957,988 bytes, linux/amd64) |
| Archive | the SP1-PA2B host A copy, copied to the proving host and re-measured there: 6,211,807,514 bytes, sha256 `18beebb6…a9147810`; installed by `sp1:circuit-install` against the committed record into a root only that user can change (7 members, 166 s, the tree left read-only) |
| Host binary | rebuilt by the committed canonical procedure (`scripts/sp1-canonical/canonical-build.sh`: a fresh container of the vendor image by digest, SP1-TD1's entrypoint unchanged) from the lane checkout's `zkvm/guest` and `zkvm/host` at `da7936bb…`, through a scratch copy of that driver differing in one line only (it keeps the binary the committed driver deletes after hashing it), on the workstation's Docker Desktop engine (the Windows side, where the vendor image was already local), not on the proving host's engine; it reproduced the committed canonical rebuild observation byte for byte: `mldsa65-host` sha256 `fc8eff69…abf1b` (57,567,008 bytes), the same ELF digests, the same source digests, the same `PROGRAM_VKEY` |
| Proof input | the committed [`zkvm/fixtures/mldsa65-withdrawal.inputs.json`](../zkvm/fixtures/mldsa65-withdrawal.inputs.json), sha256 `5f317816…a0e9` |

### The egress boundary

One nftables table (`inet pa3b_egress_off`) created as root in the root network namespace of the WSL2 virtual
machine, which every WSL2 distribution on that machine shares: the output hook refuses the WSL DNS-tunnelling resolver
(`10.255.255.254`, an address on `lo` that proxies to the Windows host) first, accepts packets to the host's own
addresses (`fib daddr type local`, which never leave the machine and carry the kernel's own reset and ICMP answers back
to the refusing socket), and refuses everything else the host originates (TCP by reset, UDP by ICMP port-unreachable,
the rest by ICMP admin-prohibited); the forward hook (policy drop) refuses every forwarded packet, so every container of
the local engine, the gnark container included; the input hook drops every packet a container sends to the host, so no
container reaches the host's resolver. The exact statement is the observation's `egress.enforcement`. It was rehearsed
twice before the run with the same probes from the host and from a container: the first rehearsal used a precursor
ruleset (no explicit rule for the DNS-tunnelling resolver, loopback accepted by address rather than `fib daddr type
local`), under which every probe was refused too but the address probes ended `ETIMEDOUT` after ten seconds because the
kernel's own reset and ICMP answers to the host's address were caught by the table; the `fib daddr type local` accept
was added and the second rehearsal, with the ruleset the run then used, found every probe refused at once (the docker
endpoint still answering), and every name resolved and every address connected after the table's removal. For the run
it was created at 23:24:12Z, before the before-probes, and deleted at 23:35:29Z, after the after-probes (11 minutes
17 seconds), with no Windows-side rule. Every required probe was refused on both sides of the run: the two hosts by
name with `EAI_AGAIN`, and the four addresses (the acquisitions' `3.5.90.58` and `3.5.93.98`, the canaries `1.1.1.1`
and `8.8.8.8`) with `ECONNREFUSED` at the connection. The table's counters at its removal: 176 packets refused at the
DNS-tunnelling resolver rule, 8 TCP packets reset (the four address probes before and after: the only outbound TCP
attempted, so no download or pull was even tried), 4 UDP and 23 other packets refused, and 0 packets in the forward
and `docker0` input chains: the gnark container never sent a packet. The tool's two probe sets account for about 64 of
the 176 resolver packets (a refused lookup is retried: one probe set was measured at 32 packets); the remaining ~112
were refused name resolutions by something else on the host during the run, and are unattributed: a capture on the
resolver's interface afterwards, with no block in place, saw no DNS query at all from four idle minutes, from thirty
rounds of the docker calls the measurement makes, from an `npm run`, or from the SP1 host's SDK setup path
(`mldsa65-host vkey`); the proving path itself was not re-run for the capture (that would be a second proof), and the
host's journal for the window was volatile and gone. Whatever asked, the table refused it, and the TCP counter shows
nothing but the probes tried to connect anywhere. Egress is attested by the probes at the edges, the stated
enforcement and these counters, not by watching the run.

### The run

`npm run sp1:measure-proof-exercise` (the command exactly as the SP1-PA3A section lists it, `--host-label
developer-workstation-wsl2`) wrote
[`proof-exercise-run-developer-workstation-wsl2.raw.json`](../evidence/zk/sp1-impl/observations/proof-exercise-run-developer-workstation-wsl2.raw.json)
(sha256 `5cc66ed5…b3ff`), committed as written:

| | |
|---|---|
| Gate run | 2026-10-19T23:24:14Z–23:35:00Z, `gateSeconds` 647 (the record check, the re-hash of the installation, the host, the re-hash again) |
| Host run | 23:24:26Z–23:34:31Z, `hostSeconds` 606 (core proving, compression, the BN254 wrap and the Groth16 wrap in the gnark container) |
| Peak memory | host process 23,366,266,880 bytes: the kernel's resident-set high-water mark (`VmHWM`), a lower bound of the process's demand under the host's 24 GB cap with swap in use; gnark container 18,962,280,612 bytes, the largest of 61 `docker stats` samples at 2 s (a lower bound of its peak) |
| Prover | `SP1_PROVER=cpu`; the gate's four frozen variables; six variables passed through (`HOME`, `LANG`, `LOGNAME`, `PATH`, `USER`, `XDG_RUNTIME_DIR`); every other caller variable dropped by name; no refused variable set |
| Proof | `vkey` = the designated `PROGRAM_VKEY` `0x0001a4c6…c2dc`; selector `0x4388a21c` (the designated verifying key's); `publicValuesSha256` `64e08d05…67db`; `proofBytesSha256` `dfe975da…0eee` |
| Rotation delay | 647 s of 172,800 s: `withinRotationDelay = true`, fraction 0.003744 |

Operator's notes, outside the observation: the host process's resident set reached its peak within the first two
minutes (core proving) and fell before the gnark container started; the virtual machine used about 6 GB of swap at
the gnark stage, so the default WSL2 cap of half the machine's 32 GB would not have carried this run. Nothing in the
measurement depends on these notes.

### The verification

`npm run sp1:verify-proof-exercise` (the default local path; the deployed-chain check was not requested, since it would
add nothing the designation does not already pin and this lane writes to no chain), run on the proving host in the
same Linux checkout, moved to the commit that holds the committed run observation, wrote
[`proof-exercise-verification-developer-workstation-wsl2.raw.json`](../evidence/zk/sp1-impl/observations/proof-exercise-verification-developer-workstation-wsl2.raw.json)
(sha256 `6057bf21…b918`), bound to the committed run observation's bytes: the CREATE2-authenticated v6.1.0 initcode
deployed on the development chain (chain id 31337), the code hash at the address measured equal to the designated
`runtimeCodeKeccak` `0xcceb864c…04dd`, `verifyProof` answered `success` to the proof and `revert ProofInvalid`
(`0x7fcdd1f4`) to its tampered copy; `acceptance = ACCEPTED`, computed from the chain's answers.

### The record and what followed from it

`npm run sp1:proof-exercise-record` derived
[`evidence/zk/sp1-impl/proof-exercises/mldsa65-withdrawal-d1.json`](../evidence/zk/sp1-impl/proof-exercises/mldsa65-withdrawal-d1.json)
(`walletwall.sp1-proof-exercise.v1`, exercise id `mldsa65-withdrawal-d1:5cc66ed58a4a2cf8`) from the two committed
observations, write-once: every binding the SP1-PA3A section requires agreed (designation, `PROGRAM_VKEY`, the archive
record by its committed sha256 and the archive's sha256, the 7 members, the canonical host binary from the designated
tree at `da7936bb…`, the committed input, the gnark digest, the `cpu` mode and the frozen environment, the proof's
digests, the designated verifier's acceptance, the wall time, both peak-memory figures, the 172,800 s delay, the
probes' shape and timing). `npm run validate:sp1-proof-exercise-record` accepts it. Then, each by its own generator
and never by hand: `sp1:proving-availability` wrote status `SELF_HOSTED_PATH_EXERCISED` with `selfHostedPath.exercised
= true`, the record it follows, and the exercise directory judged (one record, its host, times, memory, verifier check
and egress condition); `sp1:circuit-tooling` derived state `SELF_HOSTED_PATH_EXERCISED` with the fourth state
reached, `exercise.state = ACCEPTED` and `next` = production binding (its `lane` field stays `SP1-PA3A`, the lane that
built the derivation it runs, as it stayed `SP1-PA2B` through SP1-PA2C; and the availability record's first basis line
still restates the 2026-10-16 proving-artifacts observation, under which the artifacts were absent on
`developer-workstation`: a derived line about that observation, never hand-edited); `sp1:host-advisories` regenerated the record in
the exercised state (`A_NO_PROVING_WITHOUT_ARCHIVE` holds with exactly the one accepted archive record and exactly the
one accepted exercise record; still `ASSESSMENT_VALID` and still `NOT_DEPENDENCY_SAFE`, nothing patched). The
implementation receipt and its supersession are byte-identical: the supersession reads `PROVING_AVAILABILITY` at
`ab26dd6b` and stays valid while the live status is an archived one, so nothing was restamped and no new supersession
was filed. `PRODUCTION_SP1_BINDING` remains `NOT_ESTABLISHED`.

### What SP1-PA3B establishes, and what it does not

- Established: the self-hosted path is live on one host at one time. One real Groth16 proof of the designated program
  was made through the archive-only gate from the committed verified archive, with the digest-pinned gnark image, the
  canonical-build host binary, the committed input and `SP1_PROVER=cpu`, with network egress refused by name and by
  connection before and after the run; the designated verifier accepted it and refused its tampered copy; artifact
  identity (the archive record), proving execution (the run) and verifier acceptance were each exercised, and the
  performance facts (647 s against a 172,800 s rotation delay; 23.37 GB host peak, 18.96 GB container sample) are
  recorded. The state follows from those facts through the generators and validators.
- Not established: the provenance of the proving beyond what the repository binds (the designated verifier proves the
  proof's validity under the designated key, whoever made it; that it was made through the gate, with egress refused,
  by that binary, in that time and memory are the operator's observations, bound by the proof's digests, the run's
  commit content, the canonical host binary, the committed input and the probes' shape and timing, and otherwise
  resting on the owner's review of the pull request); that egress stayed refused between the two probe sets (an
  attestation at the edges, plus the operator's statement and the table's counters); the soundness of the Groth16
  trusted setup behind the key (acceptance is compatibility with the key, never soundness); that any other hardware
  proves within the rotation delay (one run on one 16-thread host that needed more than 23 GB for the host process
  alone); that the archive, the mirrors or the image remain available (each used once); a deployed-chain verification
  (the local authenticated runtime only, whose code hash the designation pins to the measured chains); production
  readiness (`PRODUCTION_SP1_BINDING` stays `NOT_ESTABLISHED`). Proving success is not proof-system soundness and
  not production readiness.
- Next lane: production binding (the implementation receipt's `PRODUCTION_SP1_BINDING`), under its own owner
  authorization; nothing here is production ready.

## SP1-PA3C: continuous egress attribution for future proof exercises (no proof generated)

SP1-PA3B proved under a refused boundary, and its probes and counters established the refusal; they did not establish
who asked. Of the 176 packets its table refused at the DNS-tunnelling resolver rule, the tool's two probe sets account
for about 64; the remaining ~112 stay what SP1-PA3B recorded: refused, but unattributed. SP1-PA3C does not revisit that
run and attributes none of them. It adds tooling, a versioned evidence contract and tests, so that a future proof
exercise can be watched over its whole measured window and every network attempt in it attributed to the process,
container or kernel that made it, or named as unattributed. No proof was generated, no image pulled, nothing deployed or
written to a chain. The gate (`scripts/lib/sp1-prove-gate.ts`, `scripts/sp1-prove-archive-only.ts`), the designation,
`PROGRAM_VKEY`, the designated verifier and the archive record are byte-identical, as are SP1-PA3B's run and
verification observations, its record and the v1 tools they bind; the state is still `SELF_HOSTED_PATH_EXERCISED`,
derived from that record, and `PRODUCTION_SP1_BINDING` stays `NOT_ESTABLISHED`. Blocked traffic is not attributed
traffic, captured traffic is not automatically a process's traffic, and stronger evidence for a future run does not
rewrite the evidence of a past one.

### The mechanism, chosen on the proving host

Measured on `developer-workstation-wsl2` (kernel 6.18.33.1-microsoft-standard-WSL2, 16 CPUs) before anything was
written: the audit subsystem refuses rule control outside the initial PID namespace, and a WSL2 distribution runs in its
own; eBPF front ends (bpftrace, BCC) are not installed, and installing them would change the proving host; tracefs
kprobes and kretprobes with BTF arguments (`CONFIG_PROBE_EVENTS_BTF_ARGS=y`) are built in. The observer
([`scripts/sp1-egress-observer.ts`](../scripts/sp1-egress-observer.ts)) uses those, in a private tracefs instance of its
own (`sp1obs_<nonce>`: `trace_clock` `mono`, thread groups recorded, overwrite off, 4,096 KB per CPU), with 27 probes:

| What | Probes |
|---|---|
| Every send a process starts on a UDP, raw, ping or packet socket, and every TCP connect | entry and return of `udp_sendmsg`, `udpv6_sendmsg`, `tcp_v4_connect`, `tcp_v6_connect`, `raw_sendmsg`, `rawv6_sendmsg`, `ping_v4_sendmsg`, `ping_v6_sendmsg` and `packet_sendmsg`: the socket, the destination (the message's address, or the connected peer), the message's length, the network namespace, the result and the source port |
| Every call that may drive an AF_XDP socket's transmission (the kernel on the proving host has AF_XDP: `CONFIG_XDP_SOCKETS=y`) | `xsk_sendmsg`, `xsk_poll`: the socket and its namespace (no destination is read) |
| A connection's life | `tcp_set_state`, `tcp_retransmit_skb` |
| Every refused packet | `sk_skb_reason_drop`, filtered to `NETFILTER_DROP` (its number read from the running kernel): the socket, its namespace and the packet's first 192 bytes |
| Every packet leaving through a device (but frames that skip it: `PACKET_QDISC_BYPASS`, an AF_XDP ring, an XDP program's redirect, netpoll, each needing root, `CAP_NET_RAW` or `CAP_NET_ADMIN` in the host's namespace) | `dev_hard_start_xmit`, filtered to the host's namespace and every device but `lo` |
| Lineage | `wake_up_new_task`, `begin_new_exec` (device, inode, the first 128 bytes of the path), `do_exit` |

Data on a TCP connection opened before the observer started, and protocols outside these (SCTP), are not seen as
attempts: their packets are seen only where the boundary refuses them (unattributed) or where they leave through a
device (a leak). A packet socket's send names no destination, a raw socket's names one its header may not carry
(`IP_HDRINCL` writes the header itself), and an AF_XDP socket's frames carry none the probes read: each such send is
counted as one of unseen destination (below), never read as harmless. Two kernel behaviours, found by experiment, shaped
the probes. A string fetched as text is printed raw, so an exec path holding a newline could forge whole trace lines:
every string an unprivileged process controls is fetched as a hex array, and the only text field, the kernel's 15-byte
`comm`, is last on its line and read by position. User memory cannot be fetched as an array, so a DNS question name is
read from the refused packet's bytes, never from the sender's buffer.

The observer runs as root under plain Node.js from a root-owned copy (it refuses to start when its file or any directory
above it is owned by anyone but root or writable by group or others, and refuses a raw directory under any such
directory, where the proving user could swap it), installs the probes, snapshots the declared nftables table's counters,
and only then starts the attributed measurement tool
([`scripts/measure-sp1-attributed-proof-exercise.ts`](../scripts/measure-sp1-attributed-proof-exercise.ts)) as the
unprivileged proving user through `setpriv --no-new-privs`. That tool does what the v1 tool does around the unchanged
gate; it refuses to run unless its stdin opens with a `READY` for this boot in run mode (a check of form: what binds the
evidence is the observer's markers, which only root writes), and it asks the observer, over its own stdin and stdout
(which none of its children inherit), to mark each phase before acting on it. The observer writes every marker itself,
as root, with the run's nonce and a gap-free sequence, and refuses requests out of order. The observer wraps the
measurement; it is not a way to invoke the prover, and the gate remains the sole proving path.

### The coverage invariant

A capture covers the run only if its trace holds, each once and in this order: `READY`, the first counter snapshot,
`SPAWNED` (the tool started), `HELLO` (the run's commit and host label), the eight phases (`PROBES_BEFORE_BEGIN`,
`PROBES_BEFORE_END`, `GATE_BEGIN`, `HOST_SPAWN`, `HOST_EXIT`, `GATE_END`, `PROBES_AFTER_BEGIN`, `PROBES_AFTER_END`),
`TOOL_DONE`, the second counter snapshot and `STOP`: the observer starts before the before-probes and stops after the
after-probes. Continuity: a heartbeat every second, numbered without a gap, each with tracing on and nothing lost (no
ring-buffer overrun or dropped event on any CPU, and no miss by any probe: a return probe misses when more calls are in
flight than it can follow, and a miss stops the run), at most 30 s between two, one before the window opens and one
after it closes; no lost-events line in the trace and no loss in any CPU's ring buffer at the end. Binding: one marker
writer and this run's nonce on every marker; `READY` naming this boot, the host's network namespace, the configuration's
digest and a monotonic reading its own trace stamp follows within 2 s; `HELLO` naming the run's commit and host label;
the gate's recorded wall-clock stamps inside `GATE_BEGIN`..`GATE_END` on the trace's clock (±5 s); the run's platform
lines naming the observed boot. An observer that cannot start, starts late, exits, stalls, stops early, loses an event
or marks a failure, and a capture that is malformed, unbound or without attribution, derive nothing: a capture the
observer left partial is refused, never read as continuous (one edited afterwards is the operator's to answer for: see
the trust paragraph below).

### Attribution, joins and reconciliation

Every process is placed in a scope from the trace alone: the observer (the writer of `READY`), the tool (the observer's
last child before `SPAWNED`), the proof (the one exec, in the tool's tree between `HOST_SPAWN` and `HOST_EXIT`, of
exactly the measured host binary by device, inode and whole path; a path its probe could not read whole is refused, and
the tool refuses such a `--host` before the run), the proof's containers (network namespaces the observer registered
after checking that each container process's cgroup names the container), other containers, other processes, and the
kernel. A refused packet joins an attempt by structure, never by timing: refused inside the attempt's own send, on its
socket; the boundary's own reset or ICMP answer, refused while the attempt was being sent; a later packet of a
connection the attempt opened, by its socket, until it closes; a datagram, echo or connection from a network namespace
other than the host's (a container's: one on the host's network is in the host's namespace, and its sockets join as the
host's do), by protocol, destination address and ports, unless anything in such a namespace sent through a packet, raw
or AF_XDP socket (which could craft any header, as any address: then no packet joins a container's attempt this way).
Such a packet joins only an attempt that could have sent it, and only when no other could: a send of n bytes leaves as
one datagram of exactly n bytes (or, segmented, as several shorter ones), an echo once, a connection's packets until its
socket closes; and it is named only when it has one candidate, or when every candidate is a send of one socket of
exactly its length, all inside the window or all outside it (a socket's datagrams leave in order). Another namespace's
socket or another socket of the namespace on the same ports (ports are per namespace and per local address), a segmented
send, or a send across the window's edge could otherwise make another's leaked datagram read as refused: then none is
named. Any other refused packet is a kernel message (a reset, an ICMP answer, a neighbour or multicast-group message, by
its header, and only from one of the host's own addresses as read at the start, or from a link-scoped source a kernel
uses before or beside them, the unspecified address or an IPv6 link-local one, read in the packet's own family, which no
router forwards and for which the reason says the drop records no direction; never once a container crafted) or
`UNATTRIBUTED`. A link-scoped message may be one a process caused its kernel to send (a membership report for groups it
joined, a reset on its own link-local connection): it reads as a kernel's, and joins no attempt. The declared table's
refusing rules must have counted, between the two snapshots, no fewer refused packets than the observer saw strictly
inside the counters' window and no more than it saw inside their outer brackets (the reads take time), with the rules
unchanged: fewer means another table refused (the declared boundary is not the boundary), more means a refusal went
unobserved. Both counts come from the capture (the observer reads the counters into its facts), so the reconciliation
finds a gap or a second boundary in an honest capture, not an edited one. Inside the window, a frame leaving through an
uplink, an attempt from the host's namespace (a container on the host's network among them) to a destination beyond the
VM that was sent or connected, or an attempt from any namespace to a resolver that was sent or connected (a resolver on
the host forwards beyond the VM, on a channel no device transmit shows) is a leak, and refuses. A container's attempt
beyond the VM is a leak only by the transmit that carries it out: its own namespace's send shows only that it left the
container. A send whose destination the capture cannot read or trust (a packet socket's, a raw socket's, an AF_XDP
socket's send or poll), inside the window, from any namespace, that may have let a packet out (it did not fail; a raw
send no refused packet shows stopped) is no leak by itself, but one of unseen destination: it may have reached a
resolver, so the attribution is partial (`unseenDestinations`). A boundary that also refuses traffic from containers to
the host at the input hook and every forwarded packet at the forward hook (as SP1-PA3B's table did) turns such a send's
packet into a refused one instead.

A v2 record carries the result as `egress.assurance`, metadata orthogonal to the state; no new state was created:

| Level | Meaning |
|---|---|
| `EDGE_PROBES_ONLY` | refusal attested by probes at the edges, a stated enforcement and the table's counters; nothing watched. SP1-PA3B's v1 record, always: its attribution counts are `null` (unknown), never 0 |
| `CONTINUOUS_ATTRIBUTED` | the whole run watched and reconciled; every refused packet the capture holds attributed (around `READY` and in the drain after `STOP` too), no attempt inside the window, toward a resolver from any namespace or beyond the VM from the host, whose outcome the capture does not show, and no send inside the window whose destination it cannot read or trust |
| `CONTINUOUS_PARTIALLY_ATTRIBUTED` | the whole run watched and reconciled, with refused packets no observed attempt sent (`unattributedEvents` inside the window of the probes and the proof, `unattributedOutsideWindow` outside it), attempts of unseen outcome (`unknownOutcomes`) or sends of unseen destination (`unseenDestinations`) |

### What is observed, and what is not

| Field | Source | Marked unknown when |
|---|---|---|
| Thread and process | the trace's thread and thread-group ids (the virtual machine's global PIDs, not a distribution's own) | the kernel printed no thread group (`null`) |
| Process name | the kernel's `comm` (for a spawn, the creating process's) | a spawn outside the disclosed scopes (`null`) |
| Executable identity | `begin_new_exec`: device, inode and path bytes | an exec outside the disclosed scopes is not committed |
| Time | `CLOCK_MONOTONIC` microseconds, mapped to UTC through `READY` | never |
| Protocol | the probe (UDP, TCP, raw, ping, packet socket) and the refused packet's IP protocol | never |
| Destination and port | the message's address or the connected peer | neither given, as for a packet socket (`null`); a raw socket's is the message's address, which its header may not carry, and an AF_XDP socket's is never read: each such send counts as one of unseen destination |
| DNS question name | the refused packet's bytes | the query was not refused (it then left: a leak, whose name is not read), it does not decode, or it is outside the disclosed scopes (`withheld`) |
| Outcome | the joins, the return value and the TCP states | no return seen, or a connect that neither connected nor closed (`UNKNOWN`) |

Not observed at all: channels outside the observed IP stack (WSL interop, the 9P file system, `AF_VSOCK`); a packet a
TUN or TAP device injects (it enters the stack as received, past no send probe; opening one needs a device root made); a
frame that leaves without the device transmit (`PACKET_QDISC_BYPASS`, an AF_XDP ring, an XDP program's redirect,
netpoll), seen at most as a send of unseen destination; a root process, which could also switch the probes or the trace
off and on again between two heartbeats (a heartbeat samples that tracing is on, every probe enabled and, where debugfs
shows it, the kernel's global kprobe switch armed: it sees one left off, never one switched back in time, and not a
probe left enabled but silenced by a filter or a CPU mask); the requester behind a daemon (an attempt `dockerd` or
`systemd-resolved` makes on another process's behalf is the daemon's); the direction of a refused packet (the drop probe
records none: a link neighbour's message from a link-scoped source, refused on its way in, reads as a kernel message, as
the host's own would; the label hides no leak, since it joins the packet to no attempt, so no attempt reads refused by
it). Whether the global switch was shown (not where debugfs is unmounted, nor under a locked-down kernel, which refuses
even root's read) is the raw facts' `kprobesGlobalArm`, kept with the raw evidence and not committed.

### Raw evidence and privacy

The observer writes the raw trace, its facts and a manifest of both (each file's length and sha256) to a new directory,
each file created exclusively and then used only through its own descriptor (the manifest binds the bytes written or
read through it, never a path opened again), where they stay with the operator (`OPERATOR_LOCAL`), owned by root and
readable only by root and the proving user's primary group (the directory `0750`, each file `0640`): the tool reads them
back after the proof as that user, and no user outside that group can. That holds while the group is the user's own: a
primary group shared with other users, or a default access-control list on the parent directory, widens it, and the
group can read the trace while the run writes it; the observer checks neither. The observer also tightens its own umask
(adding `022`, never loosening it), so nothing the tool or the gate creates is group- or world-writable. The measurement
tool normalizes them deterministically into the run observation, which commits the manifest's digest, the configuration
(rebuilt from the committed observer by every validator), the counter snapshots, the per-CPU statistics, the normalized
events and their own digest. DNS names are committed only for attempts of the observer, the tool, the proof and the
proof's registered containers, exec paths only for the observer's, the tool's and the proof's processes; any other
process's spawn name is `null`, its execs and exits are dropped, and its DNS names are withheld (`qname: null, withheld:
true`). Packet bytes are committed only as header fields and a DNS question, never as payload; no environment variable's
value, token, credential, cookie or SSH material is committed; local paths appear only as the executables the disclosed
scopes ran (the measured host binary among them), and the observer's own facts (the proving user, the tool's command
line) stay in the raw directory. The host's interface addresses are committed (a WSL2 machine's private and link-local
ones; a link-local IPv6 address can encode its virtual interface's MAC). Anyone can re-derive from the committed
observation the coverage, continuity, lineage, joins, reconciliation, leaks and privacy filter, and check the digests it
can check itself: the normalized events' digest, the configuration's (rebuilt from the committed observer), and the
observer's and the tool's as committed. The manifest's digest and the raw files' lengths and digests can be checked only
against the raw files: the operator's raw directory re-checks the normalization (its re-normalization must reproduce the
committed digest), and even that shows the normalization faithful to those files, not the files unedited.

Trust, stated plainly: every digest the repository holds is computed from the files the operator keeps, and the counters
the reconciliation uses were read into those same facts, so the evidence is consistent with itself, not independent of
the operator. An operator, or any root process on the host, able to edit the capture before its normalization could
remove an event (a transmit through the uplink, say), alter a packet's header (a reset bit turns an unattributed packet
into a kernel response) or rewrite a counter, and every committed check would still pass. No check made on the same host
can prevent that. The proving user is among those roots in effect: the gate needs the host's Docker engine, whose socket
lets any process of the proof's tree start a privileged container, so the tree could also switch the probes off for the
whole window (and back on between two heartbeats), unseen. Continuous attribution therefore adds what an honest observer
saw (an unexpected process, a send that passed, a second boundary, a gap in the capture) on the same operator trust as
the edge probes, and the v2 record's `doesNotEstablish` says so first.

### Versioned beside v1

`walletwall.sp1-proof-exercise-run.v2` and `walletwall.sp1-proof-exercise.v2` (shapes:
[`sp1-proof-exercise-run.v2.schema.json`](../evidence/zk/schema/sp1-proof-exercise-run.v2.schema.json),
[`sp1-proof-exercise.v2.schema.json`](../evidence/zk/schema/sp1-proof-exercise.v2.schema.json)) sit beside v1, which is
unchanged: SP1-PA3B's observations validate exactly as before, its record keeps `walletwall.sp1-proof-exercise.v1` and
`EDGE_PROBES_ONLY`, and `validate:sp1-proof-exercise-record` now names that assurance. A v2 run must pass every v1 rule
(the v1 validator itself, on the fields the two share), bind the attributed tool and the observer as committed at the
run's commit, and carry observer evidence that meets everything above; the v1 validator never accepts a v2 run, nor the
v2 validator a v1 run. At SP1-PA3C the exercise directory still accepted exactly one record, so a v2 exercise beside
SP1-PA3B's record needed that rule changed first, in its own lane; SP1-PA3D0 changed it
([SP1-PA3D0](#sp1-pa3d0-the-exercise-directory-holds-history-no-proof-generated)).

### Measured on the proving host while building this lane

The observer's `self-test` mode ran on the proving host's kernel as root, with a synthetic workload (TEST-NET
connections and one DNS query to `192.0.2.53`) under a table refusing the host's resolver and TEST-NET-1: no proof, no
real destination. Its last capture, by the observer as committed, is a fixture
([`test/fixtures/sp1-egress-observer/selftest-capture/`](../test/fixtures/sp1-egress-observer/selftest-capture/),
reviewed for privacy: the observer, `nft`, `setpriv` and `node`, the test user, private addresses and a link-local one
that encodes the virtual interface's MAC), judged by the suite on every run: every kernel line reads, the observer, the
tool and the stand-in host are identified, the tool's two connections and the stand-in host's DNS query are each refused
inside its own send, the table's 3 refused packets reconcile with the 3 the observer saw, no probe missed, and the
derivation reaches `CONTINUOUS_ATTRIBUTED`; the workload, as the unprivileged user, then reads the raw evidence back as
the tool does after a proof, and checks each file against the manifest the observer named. That capture exercises 9 of
the 27 probes (process creation, exec and exit; UDP and TCP over IPv4 with their returns; TCP states; the netfilter
drop); the other 18 are read in the format the same kernel function prints, against the observer's own definitions, and
the opt-in integration test installs and verifies all 27 on the kernel as root. Two host behaviours were measured with
the self-test; they are stated here and not applied to SP1-PA3B. A reject rule on a resolver address on `lo` counts each
refused query twice: the query, and the kernel's own ICMP answer to that address, which the same rule refuses first.
WSL's own processes (`GnsEngine` and `DnsTunneling`, in the virtual machine's root PID namespace) send DNS queries and
TCP connectivity checks in the shared network namespace. SP1-PA3B's ~112 refused resolver packets remain refused but
unattributed; neither behaviour is evidence about a window nothing watched.

### A future proof exercise under the observer (procedure; not executed here)

```bash
# as root on the proving host: a byte-identical, root-owned copy of the committed observer, and a parent for the raw
# directory that only root can change and anyone can pass (the tool reads the raw evidence as <user>, after the proof:
# not under /root, which is 0700, where the observation would be lost and the observer refuses it)
install -d -m 0755 /root/sp1-observer && install -m 0644 scripts/sp1-egress-observer.ts /root/sp1-observer/
install -d -m 0755 /var/lib/sp1-observer
# the declared boundary table in place (every refusal from a counted rule, the host's resolvers refused at the output
# hook, and, as SP1-PA3B's table did, traffic from containers to the host refused at the input hook and every forwarded
# packet at the forward hook), no observer's probes or instance left over; --host is an absolute path of at most 127
# printable ASCII bytes, no space (the observer reads the exec's path whole from 128 bytes); the raw directory must not
# exist yet
node /root/sp1-observer/sp1-egress-observer.ts run --as <user> --repo <checkout> --table inet <table> \
  --raw-dir /var/lib/sp1-observer/raw-<UTC> -- --record <record.json> --circuit-root <dir> --host <absolute path> \
  --inputs <absolute path> --host-label <label> --enforcement "<statement>" --out <new file>
```

The verification tool and the record generator are the v1 commands; the record they derive from a v2 run is v2 (since
SP1-PA3D0 its three files are named after the run's token, so `--out` names a new file outside the observation
directory: [the names](#the-names-and-the-next-exercises-procedure)). Keep the
raw directory: it is the only way to re-check the normalization. Two things remain for the host to show before the first
owner-authorized run, and the committed self-test (a window of under a second, with no container) shows neither: how
often its probes miss over hours (any miss stops the run, and an unprivileged process can force misses by keeping more
calls in flight than a return probe follows: the run fails closed), and whether the Docker engine sends through a packet
socket inside a container's namespace (an engine announcing a container's address that way makes every container's
packets unjoinable, no refused packet a kernel's message, the host's own included, every such send one of unseen
destination, and its refused lookups read as leaks: again closed). A soak self-test of hours and a self-test that starts
a container, both on the proving host, are recommended before SP1-PA3D; neither ran in this lane.

### What SP1-PA3C establishes, and what it does not

- Established: tooling, a contract and tests for continuous, attributed egress evidence of a future run. The derivation
  is pinned by deterministic traces in the kernel's own line format (coverage, continuity, binding, joins,
  reconciliation, leaks, privacy and parsing, each refusal by name) and by mutation testing, and the observer ran on the
  proving host's kernel in self-test mode. SP1-PA3B's evidence is byte-identical and classified `EDGE_PROBES_ONLY`.
- Not established: anything about SP1-PA3B's unattributed packets (they stay refused but unattributed); that a future
  capture is complete or unedited (it rests on the operator, as the edge probes do, and the proving user reaches root
  through the Docker engine); that a future run will be `CONTINUOUS_ATTRIBUTED` (the evidence decides); how often the
  host's probes miss over hours, or whether its Docker engine sends through a packet socket in a container's namespace
  (the soak and container self-tests recommended above); that the observer sees channels outside the IP stack or
  survives a hostile root; a second proof; production readiness (`PRODUCTION_SP1_BINDING` stays `NOT_ESTABLISHED`).
- Next lane: a proof exercise under the observer (`SP1-PA3D`, owner-authorized), after the exercise directory accepts a
  v2 record beside SP1-PA3B's.

## SP1-PA3D0: the exercise directory holds history (no proof generated)

Multiple valid exercises are history, not ambiguity. Before this lane every reader of the exercise directory assumed
one record: the judge refused two (`records.length !== 1`), required exactly one run and one verification
observation, and named observations by host label alone, so a v2 exercise on SP1-PA3B's own proving host would have
collided with SP1-PA3B's file names; the availability record, the tooling record and the host-advisory assumption
named "the" record in scalars. A second legitimate exercise would therefore have lost state 3 merely by being
second. This lane changes the evidence model only. Nothing was proved, observed or captured, the proving host was not
used, and SP1-PA3B's run and verification observations and record, the archive record, the designation,
`PROGRAM_VKEY`, the verifier, the prove gate and SP1-PA3C's observer, tools, run schema and fixture are
byte-identical. SP1-PA3C's v2 record schema changed in its two observation-path patterns and one sentence of its
description (below), while no v2 record exists.

### The names and the next exercise's procedure

| | The v1 slot (SP1-PA3B's, history) | A v2 exercise (attributed) |
|---|---|---|
| Record (`evidence/zk/sp1-impl/proof-exercises/`) | `<designation>.json`, `walletwall.sp1-proof-exercise.v1` | `<designation>.v2.<token>.json`, `walletwall.sp1-proof-exercise.v2` |
| Run observation (`evidence/zk/sp1-impl/observations/`) | `proof-exercise-run-<host>.raw.json`, run v1 | `proof-exercise-run-<host>.<token>.raw.json`, run v2 |
| Verification observation | `proof-exercise-verification-<host>.raw.json` | `proof-exercise-verification-<host>.<token>.raw.json` |
| Records per designation | 1 (its one name) | at most 1 (`MAX_RECORDS`, this contract's scope) |

The v2 record's JSON schema (`evidence/zk/schema/sp1-proof-exercise.v2.schema.json`) names a v2 exercise's
observations with their token: its `derivedFrom` and `verification.observation.path` patterns require the `.<token>`
part, so a record derived under these names conforms to its schema and one under the v1 slot's names does not. The v1
schema, which describes SP1-PA3B's record, is unchanged.

An exercise's token is its identity: the first 16 hexadecimal digits of the sha256 of its run observation's committed
(LF) bytes, the digest SP1-PA3A's `exercise.id` (`<designation>:<token>`) already carries. A v2 file's name is thus a
function of the exercise it holds: two v1 records cannot coexist (a v1 record has one name), nor two v2 records (over
the count), nor one exercise under two names (one of them is not its run's token, or the copy has no observations of
its own). Filename order, modification time, listing order and schema version choose nothing. A second v2 never needs
a committed file renamed (the names already carry each exercise's identity), but raising `MAX_RECORDS` is not enough:
every v2 record is derived with `ATTRIBUTED_EXERCISE_LANE = SP1-PA3D`, and changing that constant would re-derive the
committed v2 record differently and refuse the directory ([what a committed record
freezes](#what-a-committed-record-freezes)); the lane that admits a second v2 first makes the lane a fact of each record.

The next exercise (SP1-PA3D, owner-authorized; not executed here) follows SP1-PA3C's procedure with these names:

```bash
# the attributed measurement's --out is a new file outside the repository; its token names all three files
token=$(sha256sum /var/lib/sp1-observer/run.raw.json | cut -c1-16)
# -n: never over an existing file (a name missing its token would replace SP1-PA3B's committed run on its host)
cp -n /var/lib/sp1-observer/run.raw.json evidence/zk/sp1-impl/observations/proof-exercise-run-<host>.$token.raw.json
# commit it, then verify that committed file and commit the verification
SP1_PROOF_EXERCISE_RUN=evidence/zk/sp1-impl/observations/proof-exercise-run-<host>.$token.raw.json \
  SP1_PROOF_EXERCISE_HOST=<host> \
  SP1_PROOF_EXERCISE_OUT=evidence/zk/sp1-impl/observations/proof-exercise-verification-<host>.$token.raw.json \
  npm run sp1:verify-proof-exercise
# derives evidence/zk/sp1-impl/proof-exercises/<designation>.v2.$token.json, write-once, then the dependent records
npm run sp1:proof-exercise-record
npm run sp1:proving-availability && npm run sp1:circuit-tooling && npm run sp1:host-advisories
```

`sp1:proof-exercise-record` derives the one exercise whose observations are committed without a record
(`derivePendingExerciseRecord`). It refuses when none is pending (a record is never derived twice) or more than one
is (one at a time), when the observations are not committed, when the generation already holds its count, when a v2
run sits under the v1 slot's names, and when the files carry another token than the run's. A v2 run under the v1
slot's names is named to its right file only while that slot holds no record; beside SP1-PA3B's record the slot holds
two runs, and the directory's refusal (`needs exactly one run observation`) comes first. An attempt no committed record
was derived from (a rejected proof, a refused capture, a mistyped or missing token, a second file in a committed
record's slot) may still be renamed, re-made or dropped by a later commit; from the commit that holds a record on, the
two observations its `derivedFrom` names are as permanent as the record.

The pull request that commits an exercise reaches main by a merge commit, never squashed or rebased: the run names
the commit it was made from, the judge requires that commit in main's history, and a squash or a rebase would leave
it outside, refusing a record that can never be withdrawn, and with it the directory (SP1-PA3B's v1 included), for
good.

### The judgement

- `exerciseDirectoryOf` reads the names alone, as a pure function of the two listings that sorts them itself, so no
  listing order chooses anything. Every other name in the records directory (another designation's, another
  generation's, `README.md`, a subdirectory) and every other `proof-exercise-*` observation name is refused, never
  ignored; each record needs exactly one run and one verification observation of its own; no generation exceeds its
  count.
- `productionExerciseEvidence` then judges every record on its own, exactly as SP1-PA3A judged the one: the generation
  its name says (a v1 run and record in the v1 slot, a v2 run and record under a v2 name; SP1-PA3C's earlier
  temporary layout, a v2 in the v1 slot, is refused), its run file of its own token, byte for byte the record its own
  two observations derive for the accepted archive record, the designation and `PROGRAM_VKEY`, its run's commit in the
  history and holding what it ran from. Then the directory as a whole: observations without their record are refused
  (evidence of an exercise is never left unaccounted), byte-identical proofs in two records are refused (one proof is
  one exercise; a proof re-encoded into other valid bytes, as Groth16 allows by negating two of its points, is not
  detected: an exercise's provenance rests on its observations and the owner's review, as it always has), and every
  file must be committed, LF, and a regular file directly in its directory.
- Mixed verdicts fail closed: a refused v2 refuses the directory although SP1-PA3B's v1 is valid, a refused v1 although
  a v2 is, and both name each by its record's path. `accepted` is empty whenever anything is refused, so no consumer
  can take one exercise out of a refused directory. A record outside `evidence/zk/sp1-impl/proof-exercises` is no
  record and counts for nothing.

### State and assurance

No record: `ARCHIVED_VERIFIED_UNEXERCISED` (observations without any record are not judged, as SP1-PA3A had it; the
history still is). One accepted record, or SP1-PA3B's v1 and an accepted v2: `SELF_HOSTED_PATH_EXERCISED`. Anything
refused: no state. No state was added; a second exercise is history, never a second state.

Assurance belongs to each exercise. SP1-PA3B's record stays `EDGE_PROBES_ONLY` whatever else the directory holds; a v2
record carries the assurance its own observer evidence derives (`CONTINUOUS_ATTRIBUTED` or
`CONTINUOUS_PARTIALLY_ATTRIBUTED`), and a stronger one never reaches another record. No aggregate ("strongest",
"current", "latest") is derived: no consumer needs one.

### History, never withdrawn

The directory's git history must be append-only, and so must the observations of every committed record
(`exerciseHistoryErrors`: the repository's `directoryHistoryErrors`, which already guards the designations, the
evidence bundles and the wrapper builds, over every parent edge of every commit and over the working tree against
HEAD; in the shared observation directory an observation is held to it from the first commit whose tree holds a
record derived from it, as that record's `derivedFrom` names it, whatever the record's name or designation, while
every other observation, an attempt among them, may still be re-measured or dropped; beside a records-directory file
that is no record naming its observations (a subdirectory, a link, a file that is not JSON or names no list of
paths), every proof-exercise observation is held too, failing closed; a blob git cannot read refuses the history).
A record, and its observations from then on, is never removed, renamed or changed, so deleting SP1-PA3B's record
after a v2 is committed can never look like "only ever a v2", and SP1-PA3B's observations cannot be restamped, even
into content-equivalent bytes. The history is checked even when no record is left (an
emptied directory is refused, never "no record") and even while no archive record is accepted: withdrawing the
archive record together with SP1-PA3B's exercise refuses the availability record too. A shallow clone, a directory
without git or a repository without a commit is refused, never read as clean (CI's `Build, lint & test` checks out
with full history). A rewrite of main's own history is out of its reach, as it is for every append-only check here;
the main ruleset is what refuses that. Because every parent edge is walked, a record deleted in any commit that reaches
main (even one a later commit restores, through a merge commit) refuses from then on: never delete a committed record or
its observations, even temporarily, on a branch that will be merged. A working tree checked out with CRLF line ends
(`core.autocrlf=true`) reads every record and every observation of one as changed (the message names no line ends), as
the registry's own history check already does for its records; the repository's checkouts are LF.

### What a committed record freezes

A committed exercise record is re-derived by the code of the day on every check, byte for byte, and the history
forbids withdrawing it. Once committed, everything its derivation reads is therefore frozen, exactly as SP1-PA3B's v1
record already froze it for the v1 generation:

- the tools, as committed now: the v1 measurement tool (v1) or the attributed measurement tool and the root observer
  (v2), and the verification tool;
- the judge's rules and constants: the observation shapes, the required probe targets (`EGRESS_CANARY_IPS` among
  them), `PROBE_WINDOW_SECONDS`, the refusal codes, the clock tolerance, `ROTATION_DELAY_SECONDS`, and for a v2 the
  observer evidence's normalization and judgement (`scripts/lib/sp1-egress-attribution.ts`);
- the archive-only gate's environment policy the run is held to (`FROZEN_ENV`, `REFUSED_ENV`, `REFUSED_ENV_PREFIX`,
  `PASS_THROUGH_ENV` in `scripts/lib/sp1-prove-gate.ts`);
- the committed inputs the expectations read: the archive record's bytes, the acquisitions' addresses, the canonical
  rebuild observation, the proof-input fixture and the latest designation;
- the record's text: the v1 `establishes`/`doesNotEstablish`, or `ATTRIBUTED_ESTABLISHES`,
  `ATTRIBUTED_DOES_NOT_ESTABLISH` and `ATTRIBUTED_EXERCISE_LANE` for a v2.

A change that alters a committed record's derivation, a hardening of the gate's environment policy included, refuses
the whole directory (SP1-PA3B's v1 with it, as any refused record does), and only the old bytes restore it; the suite
pins this. Hardening therefore never applies retroactively: a lane that must evolve any of these versions the
derivation by run schema, or adds an explicit, append-only retirement, before it changes them, never a deletion.

### The generated records

- `proving-availability.json` is `walletwall.sp1-proving-availability.v2`: `exercises.accepted` lists every accepted
  record in path order (its schema, lane, exercise id, observations, host, times, performance, verifier, egress
  condition and its own `egressAssurance`) and `selfHostedPath.witnesses` names them (each establishes the exercised
  path on its own; together, still one state). v1's scalars, `exercises.accepted` as one object and
  `selfHostedPath.record`, are removed rather than redefined: nothing outside this repository reads them, every reader
  inside was changed, and no scalar can name "the" record once two coexist.
- `circuit-tooling.json` is `walletwall.sp1-circuit-tooling.v2`: `exercise.generations` names both record generations
  (name, schema, run schema, count, and each JSON schema by sha256), `exercise.records` lists every accepted record with
  its own assurance, and the derivation refuses an availability record that accounts for another set of exercises,
  as accepted exercises or as witnesses.
- The host-advisory assumption `A_NO_PROVING_WITHOUT_ARCHIVE` holds in the exercised state only when every record on
  disk is named by the availability record both as an accepted exercise and as a witness, in path order, and no other.
- `test/Sp1ProofExerciseVerifier.test.ts` re-executes every committed run observation's proof against the
  authenticated runtime, not only the first.

In this repository the regenerated records still say one accepted exercise, SP1-PA3B's v1, `EDGE_PROBES_ONLY`,
`SELF_HOSTED_PATH_EXERCISED`; only the shapes changed.

### What SP1-PA3D0 establishes, and what it does not

- Established: SP1-PA3B's v1 record and one v2 record are accepted side by side without ambiguity, shadowing, state
  inflation or any change to SP1-PA3B's history, and every malformed, duplicate, orphan, mixed or withdrawn directory
  is refused with its reasons. [`test/Sp1ProofExerciseDirectory.test.ts`](../test/Sp1ProofExerciseDirectory.test.ts)
  pins the names, a synthetic v1 beside a synthetic v2 (each refusal by its reason), the derivation of a pending record,
  this checkout's real history with a synthetic v2 beside SP1-PA3B's real v1 (the availability, tooling and advisory
  accounting, and SP1-PA3B's record withdrawn), and the real checkout as merged; mutation testing pins the decisions.
- Not established: any v2 exercise (none was made: no proof, no observer run, no capture); anything about SP1-PA3B's
  unattributed refused packets; a second v2 (the count is one, and every v2 record is derived with
  `ATTRIBUTED_EXERCISE_LANE = SP1-PA3D`: that lane first makes the lane a fact of each record, since changing the
  constant refuses the committed v2); that two records hold two proving runs beyond their bytes (a re-encoded proof is
  not detected); exercises of a later designation (a rotation leaves SP1-PA3B's d1 record under a name a d2 directory
  does not admit: that lane's owner decision, refused until then); production readiness (`PRODUCTION_SP1_BINDING`
  stays `NOT_ESTABLISHED`).
- Next: the observer's soak and container self-tests on the retained proving host; then SP1-PA3D (owner-authorized),
  one attributed proof exercise through the procedure above; then production binding's prerequisites, reassessed.

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
  development chain); `npm run validate:sp1-proof-exercise-record` is the exercise judgement on its own (until
  SP1-PA3B the real checkout answered "no proof-exercise record").
- SP1-PA3B: the run and verification observations and the record are re-judged on every run by
  `validate:sp1-proof-exercise-record` and `validate:sp1-circuit-tooling` (CI), and the committed proof is
  re-executed against the authenticated v6.1.0 runtime by
  [`test/Sp1ProofExerciseVerifier.test.ts`](../test/Sp1ProofExerciseVerifier.test.ts) on every run; the fresh-context
  adversarial review of the real observations and the fail-closed checks against them are in its pull request.
- SP1-PA3C: [`test/Sp1EgressAttribution.test.ts`](../test/Sp1EgressAttribution.test.ts) (every rule of the
  derivation on traces written in the kernel's own line format, each check in a case where it alone refuses, and the
  committed real self-test capture), [`test/Sp1EgressObserver.test.ts`](../test/Sp1EgressObserver.test.ts) (the
  observer against an in-memory tracefs, and its decisions), [`test/Sp1ProofExerciseV2.test.ts`](../test/Sp1ProofExerciseV2.test.ts)
  (SP1-PA3B unchanged and edge-probed only, the v2 run and record, a v2 exercise in a temporary repository) and
  [`test/Sp1EgressObserverLinux.test.ts`](../test/Sp1EgressObserverLinux.test.ts) (the real observer on the kernel;
  opt-in, Linux, root: `SP1_EGRESS_OBSERVER_INTEGRATION=1 SP1_EGRESS_OBSERVER_USER=<user>`).
- SP1-PA3D0: [`test/Sp1ProofExerciseDirectory.test.ts`](../test/Sp1ProofExerciseDirectory.test.ts) (the names, a v1
  beside a v2 in a temporary repository with every refusal by its reason, the pending record, this checkout's history
  with a synthetic v2 beside SP1-PA3B's real v1, the real checkout); `validate:sp1-circuit-tooling` and
  `validate:sp1-proving-availability` (both in CI) judge every record and the exercise history on every run, and
  `validate:sp1-proof-exercise-record` is the same judgement on its own.
- Mutation and adversarial review: see the pull requests.

## Reproduce

```bash
npm run validate:sp1-circuit-tooling
npm run validate:sp1-proving-archive-record
npm run validate:sp1-proof-exercise-record
npx hardhat test test/Sp1CircuitArchive.test.ts test/Sp1CircuitInstall.test.ts test/Sp1ProveGate.test.ts test/Sp1CircuitTooling.test.ts test/Sp1CircuitArchiveCensus.test.ts test/Sp1CircuitAcquisition.test.ts test/Sp1ImplReceiptSupersession.test.ts test/Sp1ProofExercise.test.ts test/Sp1ProofExerciseVerifier.test.ts
npx hardhat test test/Sp1EgressAttribution.test.ts test/Sp1EgressObserver.test.ts test/Sp1ProofExerciseV2.test.ts
npx hardhat test test/Sp1ProofExerciseDirectory.test.ts
# SP1-PA3C on a Linux host, as root (opt-in; for its seconds it refuses TEST-NET-1 and the host's resolvers, so DNS
# across a WSL2 machine, and creates and removes its own tracefs instance and a directory under /var/lib):
SP1_EGRESS_OBSERVER_INTEGRATION=1 SP1_EGRESS_OBSERVER_USER=<unprivileged user> \
  node node_modules/tsx/dist/cli.mjs node_modules/mocha/bin/mocha.js test/Sp1EgressObserverLinux.test.ts
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
