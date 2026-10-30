package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain runs the helper program of the integration test when asked to,
// and otherwise checks that the tests leave no goroutines behind.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		os.Exit(helperMain(os.Args[1:]))
	}
	code := m.Run()
	if code == 0 {
		if leaked := settleGoroutines(); leaked != "" {
			fmt.Fprintf(os.Stderr, "goroutine leak:\n%s\n", leaked)
			code = 1
		}
	}
	os.Exit(code)
}

// settleGoroutines waits for goroutines started by the tests (this
// package or the network stack) to end and returns the stacks of any that
// remain. Runtime-internal goroutines are not counted.
func settleGoroutines() string {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	var leaked []string
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		buf := make([]byte, 1<<20)
		leaked = leaked[:0]
		for g := range strings.SplitSeq(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
			if !strings.Contains(g, "TestMain") && (strings.Contains(g, "selfupdate.") || strings.Contains(g, "net/")) {
				leaked = append(leaked, g)
			}
		}
		if len(leaked) == 0 || time.Now().After(deadline) {
			return strings.Join(leaked, "\n\n")
		}
	}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func gzipOf(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(data)
	must(t, err)
	must(t, zw.Close())
	return buf.Bytes()
}

var testNow = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

type testKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestKey(t testing.TB) testKey {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return testKey{pub: pub, priv: priv}
}

func (k testKey) trust() Trust { return Trust{Keys: []TrustedKey{{Public: k.pub}}} }

func artifactFor(name, url string, format Format, data []byte) Artifact {
	d := DigestsOf(data)
	return Artifact{
		Name: name, URL: url, Format: format, Size: int64(len(data)),
		SHA256: hex.EncodeToString(d.SHA256[:]), SHA512: hex.EncodeToString(d.SHA512[:]),
	}
}

func manifestOf(product string, releases ...Release) *Manifest {
	return &Manifest{
		Product:   product,
		Published: testNow.Add(-time.Hour),
		Expires:   testNow.Add(24 * time.Hour),
		Releases:  releases,
	}
}

func mustSign(t testing.TB, m *Manifest, keys ...testKey) []byte {
	t.Helper()
	privs := make([]ed25519.PrivateKey, len(keys))
	for i, k := range keys {
		privs[i] = k.priv
	}
	data, err := SignManifest(m, privs...)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type tarEntry struct {
	name     string
	body     string
	link     string
	typeflag byte
}

func tarGz(t testing.TB, gz bool, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	var zw *gzip.Writer
	tw := tar.NewWriter(&buf)
	if gz {
		zw = gzip.NewWriter(&buf)
		tw = tar.NewWriter(zw)
	}
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.body)), Typeflag: e.typeflag, Linkname: e.link}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func zipOf(t testing.TB, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		switch e.typeflag {
		case tar.TypeSymlink:
			h.SetMode(os.ModeSymlink | 0o777)
		case tar.TypeDir:
			h.SetMode(os.ModeDir | 0o755)
		default:
			h.SetMode(0o644)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		body := e.body
		if e.typeflag == tar.TypeSymlink {
			body = e.link
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fileServer serves named byte slices with Range support and counts
// requests.
type fileServer struct {
	files map[string][]byte
	srv   *httptest.Server
	mu    sync.Mutex
	hits  map[string]int
}

func newFileServer(t testing.TB) *fileServer {
	t.Helper()
	fs := &fileServer{files: map[string][]byte{}, hits: map[string]int{}}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		fs.mu.Lock()
		data, ok := fs.files[name]
		fs.hits[name]++
		fs.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *fileServer) put(name string, data []byte) string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.files[name] = data
	return fs.srv.URL + "/" + name
}

func (fs *fileServer) count(name string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.hits[name]
}
