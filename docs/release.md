# Release process (S01)

A release is a directory (`dist/release`) or its archive. It is verifiable
offline against a **trusted public key** that the verifier obtains out of band.
Status of what was actually run is in [STATUS.md](STATUS.md); this page describes
the mechanism and the operator steps.

## Contents

| File | Purpose |
|---|---|
| wheel, `requirements.txt`, `bundles/` | The deployable artifacts (unchanged by S01) |
| `accepted-subset.json` | Feature subset the release claims, normalised from [`release/accepted-subset.yml`](../release/accepted-subset.yml) |
| `sbom.cdx.json` | CycloneDX 1.5: Python pins with hashes (from `requirements.txt`), the wheel hash, web UI packages from `webapp/package-lock.json` (build tools marked `excluded`); license where installed metadata or the lock file states it, otherwise marked unknown |
| `provenance.intoto.json` | in-toto statement, SLSA provenance v1 predicate: every released file as subject, version, subset hash, source commit and dirty flag, hashes of `uv.lock` and the web lock file |
| `manifest.json` | `version`, `wheel`, `files` (hash of every artifact, bound by deploy) and `attestations` (hash of the three files above) |
| `manifest.json.sig` | Detached Ed25519 signature over the exact bytes of `manifest.json` (domain-separated); records the signing key id |

`manifest.json` binds everything, so one signature covers all files. The
deployment binding (`version`, `files`, `wheel`) is unchanged: the supply-chain
files are not installed on the host.

The build host self-attests the provenance. The offline signature binds that
statement to the released files. Independent evidence is required to establish
how the artifacts were built or assess a SLSA level.

## Accepted subset

`release/accepted-subset.yml` lists the features the release claims, each with
the evidence that justifies it (a `STATUS.md` row or commit). The build refuses
an invalid file. Anything not listed is not claimed. The file is maintained
together with `STATUS.md`; changing it changes the signed release.

## Signing key custody

* Algorithm: Ed25519 (Python `cryptography`, already a dependency; no extra tool
  or network needed).
* Keep the release private key on the operator's offline machine. Pass its
  reference explicitly to `release sign` with `--signing-key-ref`. Use
  `file:/path/key.pem` with mode 0600 outside the repository tree. The existing
  `env:NAME` reference also accepts PEM text.
* The key must be an unencrypted PKCS#8 PEM Ed25519 key; passphrase handling is
  deliberately not part of this step.
* Generate a pair: `./steward release keygen --private-out ~/.config/steward-release/key.pem --public-out release-key.pub`
  (refuses repository paths and never overwrites).
* Publish the **public** key and its key id (printed by `keygen`, shown by
  `verify`) through a channel independent of the release download. Verifiers
  compare against that key, never against a key shipped inside the release.

## Build, pack, sign, verify

On the build host, leave `STEWARD_RELEASE_SIGNING_KEY_REF` unset and run the build and pack commands.

```bash
./steward release build
./steward release pack --output dist/steward-release-unsigned.tar.gz
```

Transfer the unsigned archive to the offline operator. Compare its SHA-256 with
the build receipt obtained through a trusted channel. On the offline machine, use
a trusted Steward checkout with the controller environment already provisioned.

```bash
./steward release sign steward-release-unsigned.tar.gz \
  --signing-key-ref "file:$HOME/.config/steward-release/key.pem" \
  --output steward-release.tar.gz
./steward release verify steward-release.tar.gz --public-key release-key.pub
```

`sign` checks artifact hashes, the subset, SBOM, provenance and clean source
metadata before loading the key. It preserves the original manifest and payload
bytes, adds the detached signature, and writes a separate deterministic archive
to a new path. For development, `release build` still supports signing at build
time via `--signing-key-ref` or `STEWARD_RELEASE_SIGNING_KEY_REF`.

`verify` requires a signature and a valid source commit. For a dirty build,
`verify --allow-dirty` reports a warning.

`verify` exits 0 only when all of these hold, and says so in its summary:

1. `manifest.json.sig` exists, names the trusted key, and the signature over the
   manifest bytes is valid.
2. The manifest has the expected structure (safe relative paths, 64-hex hashes).
3. Every listed file exists as a regular file with the listed hash, and no
   unlisted file or non-regular entry (symlink, device) is present.
4. The subset file is valid and in normalised form.
5. SBOM and `requirements.txt` agree exactly (name, version, hashes), and the
   SBOM root matches the version and wheel hash.
6. Provenance subjects equal the manifest files, and version and subset hash
   match the manifest.

Archives are extracted into a private temporary directory accepting only regular
files and directories under one top-level directory (no links, devices, absolute
or `..` paths). Failures exit 1 with each reason on stderr. It does **not** prove
that the wheel was built from the named commit, that the SBOM is complete for
code outside the pins, or that installation from the archive works; those need
the S01 acceptance gate. Verify the exact signed archive on an authorized fresh
target and on a supported upgrade path. Check installation, unchanged redeploy,
reboot, and the wrong-key, unsigned and tampered archive refusals.

## CI handoff

The release build is a single manually dispatched job with no inputs. Run it
on the protected default branch of `grethel-labs/server-deploy-toolkit`.
Before the first run, a repository administrator must protect the actual
default branch with required pull requests and CODEOWNERS review, and forbid
direct pushes, force pushes and bypasses. Add confirmed public owners with
repository write access before enabling the CODEOWNERS requirement. Submit CI and policy changes
separately for the review required by [CONTRIBUTING.md](../CONTRIBUTING.md).

Pre-create the `steward-release-build` environment before dispatch. GitHub can
auto-create a missing environment without protection rules. Set the sole
allowed ref to the exact default branch as a **Branch** rule. Allow no tags.
Set a required reviewer, enable **Prevent self-review**, disable administrator
bypass and leave the environment free of secrets. Update branch protection
and the environment rule if the default branch changes. Required reviewer
availability depends on repository visibility and GitHub plan. Use this
handoff only where that approval can be enforced. See
[GitHub environment setup](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

The job uses `deployment: false` to avoid creating a deployment object.
Required reviewers still apply. Custom deployment protection apps are
incompatible with this setting. See
[GitHub deployment controls](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/control-deployments).

Download the candidate artifact for the exact attempt of a trusted, reviewed,
successful run. It contains `steward-release-unsigned.tar.gz`, its SHA-256
checksum file and `receipt.json`. Record the run URL, source commit and inner
archive SHA-256 with the verification evidence. GitHub's artifact digest
covers the Actions transport bundle. Compare the SHA-256 of the extracted
unsigned archive with the build receipt before transferring it for offline
signing.
Authenticate the signed archive using the operator's Ed25519 signature and
an independently obtained trusted public key.

Each build is bound to its source commit. Keep the selected unsigned archive
and its receipt together. Use that archive for offline signing and retain the
matching controller checkout for the signed archive's host acceptance.

## Deploy a signed archive

Run `./steward` from a separately trusted controller checkout for the same
Steward version as the release. The archive supplies the files installed on the
target. The controller checkout supplies the wrapper, Ansible playbooks, roles,
connection plugin and controller dependency pins. Obtain the Ed25519 public key
independently of the archive.

```bash
./steward deploy --config config/server.yml --limit my-server \
  --release-archive /path/to/steward-release.tar.gz \
  --release-public-key /path/to/trusted-release-key.pub
```

`deploy` verifies the signature, manifest, files and attestations before it
contacts the target. Ansible uses the verified files from a private temporary
directory for that invocation. Verified deploy rejects Ansible Vault payload
files because Ansible would try to decrypt them before copying.
For [`--resume-deployment`](operations.md#resuming-an-interrupted-guarded-deployment),
pass the original archive and its trusted key again. An interrupted operation
must still match the recorded configuration and payload.

The running CLI requires both verification options from `0.1.0rc1` onward.
Earlier versions make archive verification opt-in and use the local
`dist/release` build by default. For intentional testing with a
local development build, `--allow-unsigned-development-release` explicitly
selects `dist/release` and checks its version and checksums before preflight.
Use the development flag on its own or supply the archive and key together.

## Acceptance status

See the S01 row in [STATUS.md](STATUS.md) for deployment and archive
installation acceptance.
