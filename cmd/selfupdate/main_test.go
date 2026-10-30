package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "release.key")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-out", keyFile}, nil, &out); err != nil {
		t.Fatal(err)
	}
	pub := strings.TrimSpace(strings.TrimPrefix(strings.Split(out.String(), "\n")[0], "public key:"))
	if err := run([]string{"keygen", "-out", keyFile}, nil, &out); err == nil {
		t.Fatal("keygen overwrote a key")
	}
	bin := filepath.Join(dir, "app")
	if err := os.WriteFile(bin, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"artifact", "-name", "app", "-url", "app", "-format", "raw", bin}, nil, &out); err != nil {
		t.Fatal(err)
	}
	manifest := `{"product":"app","releases":[{"version":"1.0.0","artifacts":[` + out.String() + `]}]}`
	signed := filepath.Join(dir, "signed.json")
	if err := run([]string{"sign", "-key", keyFile, "-out", signed}, strings.NewReader(manifest), &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"verify", "-pub", pub, "-in", signed}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"version": "1.0.0"`) {
		t.Errorf("verify output %s", out.String())
	}
	_, other, _ := strings.Cut(pub, ":")
	if err := run([]string{"verify", "-pub", "ed25519:" + strings.Repeat("A", len(other)-1) + "=", "-in", signed}, nil, &out); err == nil {
		t.Error("verified with a wrong key")
	}
	if err := run(nil, nil, &out); err == nil {
		t.Error("no command accepted")
	}
}
