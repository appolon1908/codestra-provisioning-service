# Production preflight

No canonical production release has been adopted: `canonical_image` in
`scripts/production_preflight.sh` is intentionally empty. Before activation,
the existing production approval process must accept an exact canonical image
and review its pin into protected Git. This source change supplies no accepted
image or deployment approval.

After adoption, run from the repository root before every production activation:

```bash
PROVISIONING_IMAGE='ghcr.io/appolon1908/codestra-provisioning-service@sha256:<accepted-digest>' \
  scripts/production_preflight.sh
```

The preflight prints names and status only. It never prints secret contents.
The exact production digest remains controlled by protected Git in preflight.
It rejects an empty or malformed protected pin before any host or secret probe.
`PROVISIONING_IMAGE` supplies a candidate only: it must use the canonical
repository and a nonzero 64-character lowercase hexadecimal digest, and equal
the protected pin exactly. Missing, malformed, or mismatched candidates stop
before Docker, Cosign, systemd, certificate, or secret checks. Signature
verification requires the canonical repository's exact main-workflow identity
and the GitHub Actions OIDC issuer.

Both production Compose services require an explicit `PROVISIONING_IMAGE`.
Compose enforces presence only; it does not adopt a release or enforce the
protected pin. No repository launcher automatically invokes preflight, so the
activation procedure must run it before invoking Compose. CI supplies a
synthetic canonical digest solely to parse Compose configuration; it never
pulls, runs, publishes, signs, or accepts that fixture as a release.

Preflight also fails closed if the image signature, complete protected secret bundle,
certificate profile, required Docker networks, backup/restore timers, or
production container are absent. A passing preflight does not replace live
readiness fault injection, integration canaries, DR, rollback, or soak tests.

The container currently preserves its existing Python 3.14.7 interpreter while
upgrading the vulnerable OS pip wheel. The project's declared Python 3.12
constraint and CI version still differ from that preexisting runtime; resolving
that mismatch requires a separate compatibility change.
