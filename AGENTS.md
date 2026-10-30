# AGENTS.md

- Before you finish, `gofmt -l .` must print nothing and `go vet ./...`,
  `go test -race ./...`, `golangci-lint run ./...` and the js/wasm tests
  (`GOOS=js GOARCH=wasm go test ./...` with `$(go env GOROOT)/lib/wasm` on
  `PATH`) must pass, and each fuzz target must survive a short run.
- Standard library only, also for tests and `cmd/`; register every new
  package in `deps_test.go`.
- Fail closed: missing signatures, digests, sizes, expiry or versions are
  errors. Insecure behaviour needs an explicit opt-in named as such.
- Nothing from a manifest or archive chooses a file path; output paths come
  from the caller or pass `filepath.Localize`.
- Every file swap is recorded in the journal before it happens, and every
  journal state must be recoverable by `Journal.Startup` after a crash.
- No background goroutines; callbacks run on the caller's goroutine with no
  lock held. Tests must not leak goroutines.
- Keep `TestSelfReplaceIntegration` passing on Linux, macOS and Windows;
  it replaces a running executable for real.
- Platform code lives in `*_unix.go`, `*_windows.go` and `*_other.go`;
  every target in the CI cross-vet list must build.
- The README, docs and commits name no other project and quote no benchmark
  numbers.
- Commit subjects are short, English and imperative.
- Never commit host names, IP addresses or credentials.
