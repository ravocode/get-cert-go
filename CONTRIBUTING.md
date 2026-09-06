# Contributing to getcertgo

Thank you for considering a contribution! Here's how to get started.

## Development setup

1. **Go 1.22+** is required.
2. Clone the repository and run:
   ```sh
   go mod tidy
   go build -o getcertgo .
   ```

To cross-compile a static binary for another platform:
```sh
GOOS=linux  GOARCH=amd64 go build -o getcertgo .
GOOS=darwin GOARCH=arm64 go build -o getcertgo .
```

## Architecture overview

```
main.go
internal/
  certs/       TLS blind-trust fetch, chain classification, expiry, fingerprints
  keystore/    cacerts discovery, format detection, JKS/PKCS12 read + import,
               keytool integration, atomic writes
  systemstore/ per-OS trust store install (Windows/macOS/Linux)
  ui/          colored status output, aligned tables, interactive prompts
  cli/         cobra command tree (inspect, import, list, doctor)
```

## Running tests

```sh
go test -v -race ./...
```

## Code style

- Run `go vet ./...` before committing.
- Follow [Effective Go](https://go.dev/doc/effective_go) conventions.
- Every exported function, type, and constant must have a doc comment.

## Pull requests

1. Fork the repo and create a feature branch from `main`.
2. Add tests for any new functionality.
3. Ensure the full test suite passes.
4. Open a pull request with a clear description of the change.

## Reporting bugs

Open an [issue](https://github.com/ravocode/get-cert-go/issues) with:
- The OS and Go version you are using.
- The command you ran and the full output.
- What you expected to happen.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).

