package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestDownloadAndResume(t *testing.T) {
	fs := newFileServer(t)
	data := bytes.Repeat([]byte("0123456789"), 10000)
	url := fs.put("blob", data)
	dir := t.TempDir()
	dst := filepath.Join(dir, "blob")
	var last, calls int64
	d, err := Download(t.Context(), nil, url, dst, int64(len(data)), func(done, total int64) {
		calls++
		if done < last || total != int64(len(data)) {
			t.Errorf("progress %d/%d after %d", done, total, last)
		}
		last = done
	})
	if err != nil {
		t.Fatal(err)
	}
	if d != DigestsOf(data) || last != int64(len(data)) || calls == 0 {
		t.Fatalf("digest or progress wrong: last=%d calls=%d", last, calls)
	}
	// Resume from a prefix: only the rest is transferred.
	if err := os.WriteFile(dst, data[:4321], 0o600); err != nil {
		t.Fatal(err)
	}
	var first int64 = -1
	d, err = Download(t.Context(), nil, url, dst, int64(len(data)), func(done, _ int64) {
		if first < 0 {
			first = done
		}
	})
	if err != nil || d != DigestsOf(data) {
		t.Fatalf("resume: %v", err)
	}
	if first <= 4321 {
		t.Errorf("resume restarted from %d", first)
	}
	// A complete file needs no request at all.
	before := fs.count("blob")
	if d, err = Download(t.Context(), nil, url, dst, int64(len(data)), nil); err != nil || d != DigestsOf(data) || fs.count("blob") != before {
		t.Fatalf("complete file: %v", err)
	}
	// A longer file starts over.
	if err := os.WriteFile(dst, append(bytes.Clone(data), 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	if d, err = Download(t.Context(), nil, url, dst, int64(len(data)), nil); err != nil || d != DigestsOf(data) {
		t.Fatalf("oversized partial: %v", err)
	}
}

func TestDownloadIgnoredRange(t *testing.T) {
	data := []byte("the whole content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data) // ignores Range
	}))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(dst, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Download(t.Context(), srv.Client(), srv.URL, dst, int64(len(data)), nil)
	if err != nil || d != DigestsOf(data) || readFile(t, dst) != string(data) {
		t.Fatalf("got %q, %v", readFile(t, dst), err)
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
	dir := t.TempDir()
	if _, err := Download(t.Context(), nil, srv.URL+"/long", filepath.Join(dir, "a"), int64(len(data)), nil); !errors.Is(err, ErrTooLarge) {
		t.Errorf("long: %v", err)
	}
	if _, err := Download(t.Context(), nil, srv.URL+"/short", filepath.Join(dir, "b"), int64(len(data)), nil); err == nil {
		t.Error("short download accepted")
	}
	if _, err := Download(t.Context(), nil, srv.URL+"/missing", filepath.Join(dir, "c"), 1, nil); !errors.Is(err, ErrHTTPStatus) {
		t.Errorf("404: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Download(ctx, nil, srv.URL+"/long", filepath.Join(dir, "d"), int64(len(data)), nil); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
	if _, err := Download(t.Context(), nil, srv.URL, filepath.Join(dir, "e"), 0, nil); err == nil {
		t.Error("zero size accepted")
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
		must(t, os.WriteFile(dst, []byte("XYZ"), 0o600))
		d, err := Download(t.Context(), srv.Client(), srv.URL, dst, int64(len(data)), nil)
		srv.Close()
		if err != nil || d != DigestsOf(data) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
