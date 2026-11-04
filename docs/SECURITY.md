# Veritas — Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories:
<https://github.com/lumidren/Digital-Forensics-Tool/security/advisories/new>. Do not open a public issue.

Please include the affected version or commit, the component (agent, parser crate, API, web, deployment),
reproduction steps or a proof of concept, and the impact you observed. Never send real case evidence;
use the public reference corpus (`testdata/MANIFEST.json`) or a synthetic sample.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement | 3 business days |
| Triage and severity (CVSS 4.0) | 7 days |
| Fix for critical / high | 30 days |
| Fix for medium / low | next minor release |
| Public advisory and credit (if wanted) | when the fix is released |

Issues that affect evidence integrity (custody ledger, hashing, WORM store, report signing) or that let
hostile evidence escape a parser are treated as critical regardless of exploit complexity.

Good-faith research that respects this policy, avoids privacy violations and service disruption, and
does not touch data you do not own will not lead to legal action from the maintainers.

## Supported versions

| Version | Supported |
|---|---|
| latest minor release (0.x, currently 0.1) | security fixes |
| previous minor release | critical fixes for 90 days after the next minor release |
| older releases, unreleased branches | no |

## Release signing

Every release (`.github/workflows/release.yml`) publishes:

* platform archives of `veritas`, `veritas-verify`, `veritas-agent`, `fs-tool`, `ewf-tool`,
  `veritas-artifacts-dump` for Linux (glibc and a static musl agent), Windows and macOS;
* `SHA256SUMS`, a CycloneDX SBOM (`veritas-<version>.cdx.json`) and container image digests;
* a Sigstore bundle `<file>.sigstore.json` next to every file.

Signing is **keyless**: cosign obtains a short-lived certificate from Sigstore Fulcio bound to the GitHub
Actions OIDC identity of the release workflow, and every signature is recorded in the Rekor transparency
log. There is no long-lived signing key to steal or rotate. In addition, Windows executables are
Authenticode-signed (signtool, RFC 3161 timestamp) and macOS binaries are signed with a Developer ID and
notarized.

### Verifying a release file

```bash
cosign verify-blob \
  --bundle veritas-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sigstore.json \
  --certificate-identity "https://github.com/lumidren/Digital-Forensics-Tool/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  veritas-v0.1.0-x86_64-unknown-linux-gnu.tar.gz

cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/lumidren/Digital-Forensics-Tool/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

`Verified OK` from cosign plus `OK` from `sha256sum` means the file was produced by the release workflow
of this repository for that tag and has not been modified. Any other identity, issuer or tag must be
treated as a failure.

Windows: `Get-AuthenticodeSignature .\veritas-verify.exe` must report `Valid`. macOS:
`codesign --verify --strict --verbose=2 veritas-verify` and `spctl --assess --type execute veritas-verify`.

### Verifying container images

```bash
cosign verify ghcr.io/lumidren/veritas-api:v0.1.0 \
  --certificate-identity-regexp '^https://github.com/lumidren/Digital-Forensics-Tool/.github/workflows/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation --type cyclonedx ghcr.io/lumidren/veritas-api:v0.1.0 \
  --certificate-identity-regexp '^https://github.com/lumidren/Digital-Forensics-Tool/.github/workflows/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The deploy workflow runs the same `cosign verify` for every image before `helm upgrade`. Deploy by digest
(`<image>@sha256:...`) in production.

## Supply-chain controls

* Lockfiles (`Cargo.lock`, `web/package-lock.json`) are committed; CI and image builds use `--locked` /
  `npm ci` (THREAT:T7.4 in `.github/workflows/ci.yml`).
* cargo-audit, pip-audit, npm audit, Bandit, Semgrep and Trivy (dependencies, secrets, IaC, images)
  fail the build on HIGH or CRITICAL findings (THREAT:T7.1). Accepted findings are listed with a reason,
  owner and review date in `.trivyignore`.
* SBOMs (CycloneDX) for the source tree and for each image (THREAT:T7.2); keyless signatures for every
  release file and image (THREAT:T7.3).
* Container images run as uid 10001 with a read-only root filesystem, all capabilities dropped and the
  RuntimeDefault seccomp profile; processing workers have no network egress beyond the data stores and
  can run under gVisor.

## Hardening references

Threat model: `docs/THREAT_MODEL.md`. Operations (key rotation, revocation, incident steps):
`docs/RUNBOOK.md`. Backups and recovery: `docs/DR.md`.
