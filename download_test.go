package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// download runs Download and returns the content read back through the
// returned file.
func download(t testing.TB, ctx context.Context, src Source, a Artifact, dst string, progress ProgressFunc) (string, error) {
	t.Helper()
	f, err := Download(ctx, src, a, dst, progress)
	if err != nil {
		return "", err
	}
	defer closeQuietly(f)
	b, err := io.ReadAll(f)
	return string(b), err
}

func TestDownloadAndResume(t *testing.T) {
	fs := newFileServer(t)
	data := bytes.Repeat([]byte("0123456789"), 10000)
	src := &HTTPSource{URL: fs.put("blob", data)}
	a := artifactFor("blob", "blob", FormatRaw, data)
	dst := filepath.Join(t.TempDir(), "blob")
	var last, calls int64
	got, err := download(t, t.Context(), src, a, dst, func(done, total int64) {
		calls++
		if done < last || total != int64(len(data)) {
			t.Errorf("progress %d/%d after %d", done, total, last)
		}
		last = done
	})
	if err != nil || got != string(data) || last != int64(len(data)) || calls == 0 {
		t.Fatalf("download: %v last=%d calls=%d", err, last, calls)
	}
	// Resume from a prefix: only the rest is transferred.
	must(t, os.WriteFile(dst, data[:4321], 0o600))
	var first int64 = -1
	if got, err = download(t, t.Context(), src, a, dst, func(done, _ int64) {
		if first < 0 {
			first = done
		}
	}); err != nil || got != string(data) {
		t.Fatalf("resume: %v", err)
	}
	if first <= 4321 {
		t.Errorf("resume restarted from %d", first)
	}
	// A complete file needs no request at all.
	before := fs.count("blob")
	if got, err = download(t, t.Context(), src, a, dst, nil); err != nil || got != string(data) || fs.count("blob") != before {
		t.Fatalf("complete file: %v", err)
	}
	// A longer file starts over, and so does a resumed prefix that is
	// wrong.
	for _, bad := range [][]byte{append(bytes.Clone(data), 'x'), []byte("garbage")} {
		must(t, os.WriteFile(dst, bad, 0o600))
		if got, err = download(t, t.Context(), src, a, dst, nil); err != nil || got != string(data) {
			t.Fatalf("bad partial: %v", err)
		}
	}
	// Content that does not match is refused and not kept.
	fs.put("blob", bytes.Repeat([]byte("x"), len(data)))
	must(t, os.Remove(dst))
	if _, err := download(t, t.Context(), src, a, dst, nil); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tampered: %v", err)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Size() != 0 {
		t.Errorf("tampered content kept: %v %v", fi, err)
	}
}

func TestDownloadIgnoredRange(t *testing.T) {
	data := []byte("the whole content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data) // ignores Range
	}))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "f")
	must(t, os.WriteFile(dst, data[:5], 0o600))
	got, err := download(t, t.Context(), &HTTPSource{Client: srv.Client(), URL: srv.URL}, artifactFor("f", "f", FormatRaw, data), dst, nil)
	if err != nil || got != string(data) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDownloadErrors(t *testing.T) {
	data := []byte("0123456789")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/long":
			_, _ = w.Write(append(data, data...))
		case "/short":
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			_, _ = w.Write(data[:5])
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	src := &HTTPSource{URL: srv.URL + "/"}
	dir := t.TempDir()
	get := func(ctx context.Context, name string, a Artifact) error {
		_, err := download(t, ctx, src, a, filepath.Join(dir, name), nil)
		return err
	}
	if err := get(t.Context(), "a", artifactFor("long", "long", FormatRaw, data)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("long: %v", err)
	}
	if err := get(t.Context(), "b", artifactFor("short", "short", FormatRaw, data)); err == nil {
		t.Error("short download accepted")
	}
	if err := get(t.Context(), "c", artifactFor("missing", "missing", FormatRaw, data)); !errors.Is(err, ErrHTTPStatus) {
		t.Errorf("404: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := get(ctx, "d", artifactFor("long", "long", FormatRaw, data)); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
	if err := get(t.Context(), "e", Artifact{Name: "x", URL: "long", Format: FormatRaw}); !errors.Is(err, ErrMalformedManifest) {
		t.Errorf("artifact without size or digest: %v", err)
	}
	if err := get(t.Context(), "f", artifactFor("ftp", "ftp://example.com/x", FormatRaw, data)); !errors.Is(err, ErrMalformedManifest) {
		t.Errorf("non-http url: %v", err)
	}
}

func TestArtifactCheck(t *testing.T) {
	data := []byte("content")
	a := artifactFor("x", "u", FormatRaw, data)
	d := DigestsOf(data)
	if err := a.Check(int64(len(data)), d); err != nil {
		t.Fatal(err)
	}
	if err := a.Check(int64(len(data))+1, d); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("size: %v", err)
	}
	only256 := a
	only256.SHA512 = ""
	bad := DigestsOf([]byte("other"))
	if err := only256.Check(int64(len(data)), bad); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("sha256: %v", err)
	}
	only512 := a
	only512.SHA256 = ""
	if err := only512.Check(int64(len(data)), bad); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("sha512: %v", err)
	}
	mixed := Digests{SHA256: d.SHA256, SHA512: bad.SHA512}
	if err := a.Check(int64(len(data)), mixed); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("both digests must match: %v", err)
	}
	none := a
	none.SHA256, none.SHA512 = "", ""
	if err := none.Check(int64(len(data)), d); !errors.Is(err, ErrMalformedManifest) {
		t.Errorf("no digest: %v", err)
	}
}

func TestDownloadBadResume(t *testing.T) {
	data := []byte("0123456789abcdef")
	for name, handler := range map[string]http.HandlerFunc{
		"416": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") != "" {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			_, _ = w.Write(data)
		},
		"wrong range": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") != "" {
				w.Header().Set("Content-Range", "bytes 0-15/16")
				w.WriteHeader(http.StatusPartialContent)
			}
			_, _ = w.Write(data)
		},
	} {
		srv := httptest.NewServer(handler)
		dst := filepath.Join(t.TempDir(), "f")
		must(t, os.WriteFile(dst, data[:3], 0o600))
		got, err := download(t, t.Context(), &HTTPSource{Client: srv.Client(), URL: srv.URL}, artifactFor("f", "f", FormatRaw, data), dst, nil)
		srv.Close()
		if err != nil || got != string(data) {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
}

func TestDirSource(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "media")
	must(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
	data := []byte("offline build")
	must(t, os.WriteFile(filepath.Join(dir, "bin", "app"), data, 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("signed"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "secret"), data, 0o644))
	src := &DirSource{Dir: dir}
	if m, err := src.Fetch(t.Context()); err != nil || string(m) != "signed" {
		t.Fatalf("fetch: %q %v", m, err)
	}
	dst := filepath.Join(t.TempDir(), "app")
	must(t, os.WriteFile(dst, data[:4], 0o600))
	if got, err := download(t, t.Context(), src, artifactFor("app", "bin/app", FormatRaw, data), dst, nil); err != nil || got != string(data) {
		t.Fatalf("download: %q %v", got, err)
	}
	for _, bad := range []string{"../secret", "/etc/passwd", "file:///etc/passwd", "http://x/app", "bin/app?x"} {
		if _, _, err := src.Open(t.Context(), artifactFor("app", bad, FormatRaw, data), 0); err == nil {
			t.Errorf("%q opened", bad)
		}
	}
}
