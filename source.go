package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrHTTPStatus reports an unexpected HTTP response status.
var ErrHTTPStatus = errors.New("selfupdate: unexpected HTTP status")

// Source is where the releases of a product come from: the signed
// manifest and the artifacts it lists. Implement it to fetch them any way
// you like (an API, object storage, a peer, removable media); everything a
// Source returns is verified against the signed manifest, so a Source need
// not be trusted. [HTTPSource] and [DirSource] cover the common cases.
type Source interface {
	// Fetch returns the signed manifest document, as produced by
	// [SignManifest].
	Fetch(ctx context.Context) ([]byte, error)
	// Open returns the content of the artifact a, as listed in the
	// manifest, from byte offset on. offset is zero or a resumption point
	// below a.Size. A source that cannot start there returns the content
	// from the beginning; start reports where r begins: offset or zero.
	// The caller closes r.
	Open(ctx context.Context, a Artifact, offset int64) (r io.ReadCloser, start int64, err error)
}

// HTTPSource fetches a manifest from a fixed URL, and the artifacts from
// the URLs it lists, such as a manifest.json placed in a static directory
// next to the artifacts it lists by relative URL. Artifact URLs must be
// http or https.
type HTTPSource struct {
	// Client sends the requests; nil means [http.DefaultClient].
	Client *http.Client
	// URL locates the manifest.
	URL string
	// Base resolves relative artifact URLs; empty means URL.
	Base string
	// MaxSize bounds the manifest size. Zero means 1 MiB.
	MaxSize int64
}

func (s *HTTPSource) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return http.DefaultClient
}

// Fetch implements [Source].
func (s *HTTPSource) Fetch(ctx context.Context) ([]byte, error) {
	limit := s.MaxSize
	if limit <= 0 {
		limit = 1 << 20
	}
	resp, err := s.get(ctx, s.URL, "")
	if err != nil {
		return nil, err
	}
	defer closeQuietly(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s from %s", ErrHTTPStatus, resp.Status, resp.Request.URL.Redacted())
	}
	return readLimited(resp.Body, limit)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: manifest larger than %d bytes", ErrTooLarge, limit)
	}
	return data, nil
}

// Open implements [Source]. A resumption uses a Range request; a server
// that ignores it or answers with another range makes the download start
// over.
func (s *HTTPSource) Open(ctx context.Context, a Artifact, offset int64) (io.ReadCloser, int64, error) {
	loc, err := s.resolve(a.URL)
	if err != nil {
		return nil, 0, err
	}
	rng := ""
	if offset > 0 {
		rng = "bytes=" + strconv.FormatInt(offset, 10) + "-"
	}
	resp, err := s.get(ctx, loc, rng)
	if err != nil {
		return nil, 0, err
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return resp.Body, 0, nil
	case offset > 0 && resp.StatusCode == http.StatusPartialContent && rangeStart(resp.Header.Get("Content-Range")) == offset:
		return resp.Body, offset, nil
	case offset > 0 && (resp.StatusCode == http.StatusPartialContent || resp.StatusCode == http.StatusRequestedRangeNotSatisfiable):
		closeQuietly(resp.Body)
		return s.Open(ctx, a, 0)
	}
	closeQuietly(resp.Body)
	return nil, 0, fmt.Errorf("%w: %s from %s", ErrHTTPStatus, resp.Status, resp.Request.URL.Redacted())
}

func (s *HTTPSource) resolve(ref string) (string, error) {
	r, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("%w: artifact url: %w", ErrMalformedManifest, err)
	}
	base := s.Base
	if base == "" {
		base = s.URL
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r = b.ResolveReference(r)
	if r.Scheme != "http" && r.Scheme != "https" {
		return "", fmt.Errorf("%w: artifact url %q is not http or https", ErrMalformedManifest, r.Redacted())
	}
	return r.String(), nil
}

func (s *HTTPSource) get(ctx context.Context, loc, rng string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	if err != nil {
		return nil, err
	}
	if rng != "" {
		req.Header.Set("Range", rng)
	}
	return s.client().Do(req)
}

// rangeStart parses the first byte position of "bytes start-end/total".
func rangeStart(s string) int64 {
	rest, ok := strings.CutPrefix(s, "bytes ")
	if !ok {
		return -1
	}
	start, _, ok := strings.Cut(rest, "-")
	if !ok {
		return -1
	}
	n, err := strconv.ParseInt(start, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// DirSource reads a manifest and its artifacts from a local directory,
// such as a mounted USB drive or a synced folder, for offline and
// air-gapped updates. Artifact URLs must be relative slash-separated
// paths below Dir; they are checked with [filepath.Localize] and opened
// with [os.Root], so they cannot reach outside it.
type DirSource struct {
	// Dir is the directory holding the manifest and the artifacts.
	Dir string
	// Manifest is the manifest's path below Dir; empty means
	// "manifest.json".
	Manifest string
	// MaxSize bounds the manifest size. Zero means 1 MiB.
	MaxSize int64
}

// Fetch implements [Source].
func (s *DirSource) Fetch(context.Context) ([]byte, error) {
	name := s.Manifest
	if name == "" {
		name = "manifest.json"
	}
	f, err := s.open(name)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(f)
	limit := s.MaxSize
	if limit <= 0 {
		limit = 1 << 20
	}
	return readLimited(f, limit)
}

// Open implements [Source].
func (s *DirSource) Open(_ context.Context, a Artifact, offset int64) (io.ReadCloser, int64, error) {
	u, err := url.Parse(a.URL)
	if err != nil || u.Scheme != "" || u.Host != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, 0, fmt.Errorf("%w: artifact url %q is not a relative path", ErrMalformedManifest, a.URL)
	}
	f, err := s.open(u.Path)
	if err != nil {
		return nil, 0, err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		closeQuietly(f)
		return nil, 0, err
	}
	return f, offset, nil
}

func (s *DirSource) open(name string) (*os.File, error) {
	local, err := filepath.Localize(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrMalformedManifest, name, err)
	}
	root, err := os.OpenRoot(s.Dir)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(root)
	return root.Open(local)
}
