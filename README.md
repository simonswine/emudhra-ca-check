# emudhra-ca-check

Static Docker image PEM certificate inventory for the [eMudhra CA incident](https://scotthelme.co.uk/eight-bits-of-trust-emudhras-ca-keys-cracked-in-milliseconds/).

Requires Go 1.22+ and Docker. No third-party Go dependencies. Missing images are pulled automatically with `docker pull`. Existing local images are used without refreshing them.

```sh
go build -o emudhra-ca-check .
./emudhra-ca-check grafana/pyroscope:2.0.2
./emudhra-ca-check -json grafana/pyroscope:2.0.2
```

The checker creates but never starts a container and streams its exported filesystem. It parses PEM certificates using Go's x509 library, matching affected root and intermediate SPKI SHA-256 identities, including Sectigo's `AAA Certificate Services` cross-signing route, with certificate SHA-256 fingerprints and paths. Temporary containers are removed afterward.

Exit codes:
- **0**: no matching certificates in scanned PEM files (not proof of safety).
- **1**: potential exposure detected.
- **2**: failure or inconclusive scan (including no parsed certificates).

## Limitations

This is a cryptographic public-key identity inventory, not an end-to-end TLS verification test. A certificate's presence does not establish that an application trusts it. Conversely, absent matches do not establish safety. Unrelated eMudhra G1/C1/C3 keys are not flagged; subject names alone never establish identity.

All regular files are streamed for PEM blocks, including large binaries, with a 32 MiB per-block limit. JKS v1/v2 trusted certificate entries are supported (32 MiB store limit); private-key entries, malformed stores and unsupported versions are inconclusive. JKS integrity digests are not authenticated. OpenSSL trusted PEM with auxiliary data may be reported as unparseable.

Detected Node binaries trigger inspection of image Entrypoint/Cmd and NODE_OPTIONS. A direct `--use-openssl-ca` request is reported as advisory; unknown or bundled-CA configurations make an otherwise clean scan inconclusive. Wrappers, runtime overrides and application-created trust pools cannot be verified statically. DER/NSS stores, non-PEM embedded roots and mounted files are not inspected. The legacy JSON `pem_certificates_scanned` count now includes JKS certificates.

Removing only an eMudhra root may not remove the Sectigo cross-signing route. Review application-specific trust policies before remediation; do not indiscriminately delete unrelated trust anchors.

## Tests

```sh
go test ./...
```

Tests verify signatures in a public incident chain from https://emudhra.we-have-a-problem.com/chains.zip and exercise a generated signed chain with and without its trust anchor. Reissued certificates with the same key match; unrelated keys with matching names do not. Tests do not execute images or contact test TLS servers.
