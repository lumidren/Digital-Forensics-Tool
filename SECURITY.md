# Security Policy

**Report vulnerabilities privately** through GitHub Security Advisories:
<https://github.com/lumidren/Digital-Forensics-Tool/security/advisories/new>. Do not open public issues for
security problems and never attach real case evidence.

We acknowledge reports within 3 business days, triage within 7 days and fix critical or high issues within
30 days. Anything that weakens evidence integrity (custody ledger, hashing, WORM store, report signing) or
lets hostile evidence escape a parser is treated as critical.

## Supported versions

| Version | Supported |
|---|---|
| latest minor release (currently 0.1) | yes |
| previous minor release | critical fixes for 90 days |
| older | no |

## Verifying releases

Release files and container images are signed keyless with Sigstore cosign from the release workflow
(no long-lived signing key). Verify a download with:

```bash
cosign verify-blob --bundle <file>.sigstore.json \
  --certificate-identity "https://github.com/lumidren/Digital-Forensics-Tool/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>
```

Full policy, image verification, Windows/macOS signature checks and the supply-chain controls are in
[`docs/SECURITY.md`](docs/SECURITY.md).
