package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/djylb/selfupdate"
)

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "release.key")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-out", keyFile}, nil, &out); err != nil {
		t.Fatal(err)
	}
	keyInfo := out.String()
	pub := strings.TrimSpace(strings.TrimPrefix(strings.Split(keyInfo, "\n")[0], "public key:"))
	if err := run([]string{"keygen", "-out", keyFile}, nil, &out); err == nil {
		t.Fatal("keygen overwrote a key")
	}
	out.Reset()
	if err := run([]string{"pubkey", "-key", keyFile}, nil, &out); err != nil || out.String() != keyInfo {
		t.Fatalf("pubkey: %q %v", out.String(), err)
	}
	dist := filepath.Join(dir, "dist")
	if err := os.Mkdir(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dist, "app")
	if err := os.WriteFile(bin, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"product":"app","published":"0001-01-01T00:00:00Z","expires":"0001-01-01T00:00:00Z","releases":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	add := []string{"artifact", "-name", "app", "-format", "raw", "-into", manifest, "-version", "1.0.0", bin}
	if err := run(add, nil, &out); err != nil {
		t.Fatal(err)
	}
	if err := run(add, nil, &out); err == nil {
		t.Fatal("same artifact added twice")
	}
	signed := filepath.Join(dir, "signed.json")
	if err := run([]string{"sign", "-key", keyFile, "-in", manifest, "-out", signed}, nil, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"verify", "-pub", pub, "-in", signed, "-dist", dist}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"version": "1.0.0"`) {
		t.Errorf("verify output %s", out.String())
	}
	if err := os.WriteFile(bin, []byte("BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "-pub", pub, "-in", signed, "-dist", dist}, nil, &out); err == nil {
		t.Error("changed artifact passed -dist")
	}
	_, other, _ := strings.Cut(pub, ":")
	if err := run([]string{"verify", "-pub", "ed25519:" + strings.Repeat("A", len(other)-1) + "=", "-in", signed}, nil, &out); err == nil {
		t.Error("verified with a wrong key")
	}
	if err := run(nil, nil, &out); err == nil {
		t.Error("no command accepted")
	}

	// Files signed alone.
	sig := filepath.Join(dir, "app.sig")
	if err := run([]string{"sign-file", "-key", keyFile, "-out", sig, bin}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify-file", "-pub", pub, "-sig", sig, bin}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("other"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify-file", "-pub", pub, "-sig", sig, bin}, nil, &out); err == nil {
		t.Error("changed file verified")
	}
}

// TestSignStrict is a regression test: a misspelt field was dropped
// silently, so a beta release could be signed into the default channel.
func TestSignStrict(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "k")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-out", keyFile}, nil, &out); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		`{"product":"app","releases":[{"version":"1.0.0","chanel":"beta","artifacts":[]}]}`,
		`{"product":"app","releases":[]}}`,
		`{"product":"app","product":"x","releases":[]}`,
	} {
		if err := run([]string{"sign", "-key", keyFile}, strings.NewReader(in), &out); err == nil {
			t.Errorf("signed %s", in)
		}
	}
}

// TestArtifactFormat is a regression test: -format defaulted to raw, so a
// forgotten flag installed a whole archive as the executable.
func TestArtifactFormat(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var out bytes.Buffer
	if err := run([]string{"artifact", "-name", "app", write("app")}, nil, &out); err == nil {
		t.Error("raw file without -format accepted")
	}
	if err := run([]string{"artifact", "-name", "app", "-format", "raw", write("app.tar.gz")}, nil, &out); err == nil {
		t.Error("-format contradicting the name accepted")
	}
	out.Reset()
	if err := run([]string{"artifact", "-name", "app", write("app.zip")}, nil, &out); err != nil || !strings.Contains(out.String(), `"format": "zip"`) {
		t.Errorf("implied format: %v %s", err, out.String())
	}
	if err := run([]string{"artifact", "-name", "app", "-member", "app", write("bad.zip")}, nil, &out); err == nil {
		t.Error("missing member accepted")
	}
}

// TestCheckArtifacts checks that verify covers every artifact of a
// manifest mixing relative and absolute URLs, and that an artifact no
// flag covers fails the check instead of being skipped.
func TestCheckArtifacts(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	local, remote := []byte("local artifact"), []byte("remote artifact")
	if err := os.WriteFile(filepath.Join(dir, "app"), local, 0o644); err != nil {
		t.Fatal(err)
	}
	var served atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		switch r.URL.Path {
		case "/app":
			_, _ = w.Write(remote)
		case "/bad":
			_, _ = w.Write([]byte("remote artifacT"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	artifact := func(u string, data []byte) selfupdate.Artifact {
		d := selfupdate.DigestsOf(data)
		return selfupdate.Artifact{Name: "app", URL: u, Size: int64(len(data)), Format: selfupdate.FormatRaw,
			SHA256: hex.EncodeToString(d.SHA256[:])}
	}
	manifest := func(as ...selfupdate.Artifact) *selfupdate.Manifest {
		return &selfupdate.Manifest{Releases: []selfupdate.Release{{Version: "1.0.0", Artifacts: as}}}
	}
	mixed := manifest(artifact("app", local), artifact(srv.URL+"/app", remote))
	if err := checkArtifacts(ctx, dir, true, mixed); err != nil {
		t.Errorf("mixed manifest: %v", err)
	}
	if served.Load() != 1 {
		t.Errorf("served %d requests, want 1", served.Load())
	}
	served.Store(0)
	for _, tc := range []struct {
		name  string
		dir   string
		fetch bool
		m     *selfupdate.Manifest
		want  string
	}{
		{"absolute without -fetch", dir, false, mixed, "needs -fetch"},
		{"relative without -dist", "", true, mixed, "needs -dist"},
		{"remote mismatch", dir, true, manifest(artifact(srv.URL+"/bad", remote)), "mismatch"},
		{"remote missing", dir, true, manifest(artifact(srv.URL+"/none", remote)), "404"},
		{"local mismatch", dir, false, manifest(artifact("app", []byte("local artifacT"))), "mismatch"},
		{"not http", dir, true, manifest(artifact("file:///etc/passwd", remote)), "not http"},
		{"scheme-relative", dir, false, manifest(artifact("//host/app", remote)), "needs -fetch"},
		{"colon path", dir, false, manifest(artifact("v1:2/app", remote)), "needs -fetch"},
	} {
		err := checkArtifacts(ctx, tc.dir, tc.fetch, tc.m)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	if served.Load() != 2 {
		t.Errorf("unchecked manifests downloaded: %d requests, want 2", served.Load())
	}
}

// TestKeygenLeavesNothing checks that keygen writes the key file whole or
// not at all.
func TestKeygenLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	keyFile := filepath.Join(dir, "k")
	if err := os.WriteFile(keyFile, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "-out", keyFile}, nil, &out); err == nil {
		t.Fatal("keygen overwrote a file")
	}
	if data, _ := os.ReadFile(keyFile); string(data) != "mine" {
		t.Errorf("existing file changed: %q", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left %v", entries)
	}
}
