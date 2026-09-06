# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in getcertgo, please report it
responsibly:

1. **Do not** open a public GitHub issue.
2. Email **security@ravocode.io** (or open a [private security advisory](https://github.com/ravocode/get-cert-go/security/advisories/new) on GitHub) with:
   - A description of the vulnerability.
   - Steps to reproduce it.
   - The potential impact.
3. You will receive an acknowledgment within **48 hours** and a follow-up with
   a fix timeline.

## Scope

The following are in scope:

- Certificate handling and parsing logic.
- Keystore read/write operations (data integrity and permission handling).
- System trust store installation commands.
- Any command injection or path traversal vectors.

## Design notes

getcertgo intentionally uses `InsecureSkipVerify: true` in two places:

1. **`internal/certs/fetch.go`** — The TLS fetch phase disables verification so
   it can retrieve certificates from self-signed or otherwise untrusted hosts.
   This is the core purpose of the tool.
2. **`internal/certs/issuer.go`** — The AIA issuer fetch also disables
   verification because the AIA URL may be served by the same untrusted
   infrastructure.

Both uses are intentional and documented with `//nolint:gosec` annotations.
They do not represent a vulnerability; they are required for the tool to
function.

## Supported versions

| Version | Supported |
| ------- | --------- |
| latest  | ✅         |

