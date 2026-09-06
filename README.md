# getcertgo

[![CI](https://github.com/ravocode/get-cert-go/actions/workflows/ci.yml/badge.svg)](https://github.com/ravocode/get-cert-go/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

![getcertgo](/img/logo.jpeg)

A developer utility for fetching, inspecting, and trusting remote TLS
certificates — so you stop wrestling with raw `keytool`/`openssl` incantations
to fix `ValidatorException: PKIX path building failed` against internal servers.

## Features

- **`getcertgo inspect <url>`** — Pull a host's certificate chain and print a
  color-coded table (role, CN, issuer, validity, SHA-256 fingerprint).
  Expired/expiring certs are highlighted.
- **`getcertgo import <url>`** — Fetch the chain, interactively pick which
  certificates to trust, and add them to a Java keystore. Auto-discovers the
  JVM `cacerts` (via `JAVA_HOME` and common OS paths) unless `--keystore` is
  given. Uses `keytool` when available (lossless), otherwise writes natively.
- **`getcertgo list [filter]`** — List trusted certificates in a keystore, with an
  optional case-insensitive filter over alias / CN / issuer.
- **`getcertgo doctor <url>`** — Do a real verifying handshake using trust anchors
  from the Java keystore or the OS trust store (`--system`) to confirm a host
  is now trusted.

The fetch phase uses a "blind trust" TLS client (verification disabled) so it
can retrieve certificates from self-signed or untrusted internal hosts without
crashing first.

## Install / Build

Requires Go 1.22+.

```sh
# Install directly
go install github.com/ravocode/get-cert-go@latest

# Or build from source
go mod tidy
go build -o getcertgo .    # produces ./getcertgo (getcertgo.exe on Windows)
```

## Download

Pre-built binaries are published on every release. Download the one for your
platform from the [Releases](https://github.com/ravocode/get-cert-go/releases/latest) page:

| Platform | Asset |
| --- | --- |
| Linux x64 | `getcertgo-linux-amd64` |
| Linux ARM64 | `getcertgo-linux-arm64` |
| macOS Intel | `getcertgo-darwin-amd64` |
| macOS Apple Silicon | `getcertgo-darwin-arm64` |
| Windows x64 | `getcertgo-windows-amd64.exe` |

No Go toolchain required — just download, make executable (`chmod +x` on
Linux/macOS), and run.

## Usage

```sh
# Inspect a chain before trusting anything
getcertgo inspect https://dev-cluster.local

# Import into the default JVM cacerts (interactive selection + password prompt)
getcertgo import https://dev-cluster.local

# Import the whole chain non-interactively into a custom store
getcertgo import https://dev-cluster.local --all --keystore ./my-store.jks

# Search what's already trusted
getcertgo list "enterprise ca"

# Verify the host now validates against the keystore
getcertgo doctor https://dev-cluster.local

# Verify using the OS trust store instead
getcertgo doctor https://dev-cluster.local --system
```

### Global flags

| Flag | Description |
| --- | --- |
| `--keystore <path>` | Keystore to target (default: auto-discovered `cacerts`) |
| `--password <pw>` | Keystore password (default: prompt, falls back to `changeit`) |
| `--timeout <dur>` | Connection timeout (default `10s`) |
| `--no-color` | Disable ANSI colors |

### `import` flags

| Flag | Description |
| --- | --- |
| `--all` | Import every certificate in the chain without prompting |
| `--alias <name>` | Alias to use (single-certificate imports only) |
| `--native` | Force native Go keystore writing instead of `keytool` |
| `--system` | Import into the **OS trust store** instead of a Java keystore |
| `--machine` | With `--system`, target the machine-wide store (needs admin/root) |

## System (OS) trust store

`getcertgo import <url> --system` installs the selected certificate(s) as trusted
roots in the operating system trust store, which is honored by Chrome, Edge and
Safari (and by curl/Python on macOS/Linux). Per OS:

| OS | Mechanism | Default scope | Machine scope (`--machine`) |
| --- | --- | --- | --- |
| Windows | `certutil -addstore Root` | `CurrentUser\\Root` (no admin) | `LocalMachine\\Root` (admin) |
| macOS | `security add-trusted-cert` | login keychain (no sudo) | System keychain (sudo) |
| Linux | copy to CA anchors + `update-ca-certificates`/`update-ca-trust` | machine-wide (root) | machine-wide (root) |

Notes:

- Import the **root** CA; browsers build the chain from the leaf plus the
  intermediates the server sends.
- The "Not secure" warning only clears if the certificate is otherwise valid:
  present **SAN** matching the hostname (CN alone is ignored), not expired, and
  `EKU = serverAuth`. Restart the browser afterwards.
- **Firefox** uses its own (NSS) trust store and is unaffected; enable
  `security.enterprise_roots.enabled` in `about:config` or import into Firefox
  directly.

## Keystore support

- **JKS** (legacy default) — read and written natively with 100% fidelity.
- **PKCS12** (JDK 9+ default) — read natively where possible. Writing delegates
  to `keytool` if installed to perfectly preserve existing entry aliases.

`keytool` is discovered automatically by checking next to the target keystore 
(e.g., `../bin/keytool`), checking `JAVA_HOME/bin`, and finally searching your system `PATH`.

**If `keytool` is not installed:**
- `getcertgo` still works entirely on its own via native Go implementations!
- JKS operations remain completely lossless.
- Native PKCS12 writes will succeed, but you'll see a warning that the "friendly names" (aliases) of pre-existing entries in the keystore might be regenerated. 
- *Caveat:* Some modern JDKs (like JDK 21) use a MAC-less PKCS12 format for `cacerts` that the strict native decoder rejects. If you encounter a `pkcs12: no MAC in data` error, you will need to install a JDK so `getcertgo` can use `keytool` as a fallback.

## Roadmap

- `--docker` — inject certs into a running Docker daemon / container store.

## License

[MIT](LICENSE)
