package selfupdate

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// ErrHTTPStatus reports an unexpected HTTP response status.
var ErrHTTPStatus = errors.New("selfupdate: unexpected HTTP status")

var errBadRange = errors.New("selfupdate: server cannot resume the download")

// ProgressFunc observes a download. It is called on the downloading
// goroutine, with no lock held, after each chunk; done counts bytes in the
// file so far and total is the expected size. It must not block for long.
type ProgressFunc func(done, total int64)

// Download fetches url into the file dst, which must hold exactly size
// bytes when complete, and returns its digests. If dst already holds a
// prefix of the content (an interrupted earlier call), that prefix is
// hashed and the rest is requested with a Range header; a server that
// ignores the range makes the download start over. A nil client means
// [http.DefaultClient]; progress may be nil.
//
// Download does not judge the content: compare the digests with
// [Artifact.Check] before using the file.
func Download(ctx context.Context, client *http.Client, url, dst string, size int64, progress ProgressFunc) (Digests, error) {
	if size <= 0 {
		return Digests{}, errors.New("selfupdate: download size must be positive")
	}
	if client == nil {
		client = http.DefaultClient
	}
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return Digests{}, err
	}
	defer closeQuietly(f) // synced explicitly below
	h := newHasher()
	have, err := io.Copy(h, io.LimitReader(f, size+1))
	if err != nil {
		return Digests{}, err
	}
	if have > size {
		if err := restart(f, h); err != nil {
			return Digests{}, err
		}
		have = 0
	}
	if have < size {
		err := fetchRange(ctx, client, url, f, h, have, size, progress)
		if errors.Is(err, errBadRange) {
			// The server cannot continue this file: start over once.
			if err = restart(f, h); err == nil {
				err = fetchRange(ctx, client, url, f, h, 0, size, progress)
			}
		}
		if err != nil {
			return Digests{}, err
		}
	}
	if err := f.Sync(); err != nil {
		return Digests{}, err
	}
	return h.sum(), nil
}

func fetchRange(ctx context.Context, client *http.Client, url string, f *os.File, h *hasher, have, size int64, progress ProgressFunc) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if have > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(have, 10)+"-")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer closeQuietly(resp.Body)
	switch {
	case have > 0 && (resp.StatusCode == http.StatusRequestedRangeNotSatisfiable ||
		resp.StatusCode == http.StatusPartialContent && rangeStart(resp.Header.Get("Content-Range")) != have):
		return errBadRange
	case resp.StatusCode == http.StatusPartialContent && have > 0:
	case resp.StatusCode == http.StatusOK:
		if have > 0 {
			if err := restart(f, h); err != nil {
				return err
			}
			have = 0
		}
	default:
		return fmt.Errorf("%w: %s from %s", ErrHTTPStatus, resp.Status, req.URL.Redacted())
	}
	if _, err := f.Seek(have, io.SeekStart); err != nil {
		return err
	}
	w := &progressWriter{w: io.MultiWriter(f, h), done: have, total: size, fn: progress}
	n, err := io.Copy(w, io.LimitReader(resp.Body, size-have+1))
	if err != nil {
		return err
	}
	switch got := have + n; {
	case got > size:
		return fmt.Errorf("%w: more than %d bytes", ErrTooLarge, size)
	case got < size:
		return fmt.Errorf("selfupdate: download ended after %d of %d bytes: %w", got, size, io.ErrUnexpectedEOF)
	}
	return nil
}

func restart(f *os.File, h *hasher) error {
	h.reset()
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err := f.Seek(0, io.SeekStart)
	return err
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

type hasher struct {
	s256, s512 hash.Hash
}

func newHasher() *hasher { return &hasher{s256: sha256.New(), s512: sha512.New()} }

func (h *hasher) Write(p []byte) (int, error) {
	h.s256.Write(p)
	h.s512.Write(p)
	return len(p), nil
}

func (h *hasher) reset() {
	h.s256.Reset()
	h.s512.Reset()
}

func (h *hasher) sum() Digests {
	var d Digests
	h.s256.Sum(d.SHA256[:0])
	h.s512.Sum(d.SHA512[:0])
	return d
}

// DigestFile returns the size and digests of the file at p.
func DigestFile(p string) (int64, Digests, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, Digests{}, err
	}
	defer closeQuietly(f)
	h := newHasher()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, Digests{}, err
	}
	return n, h.sum(), nil
}

type progressWriter struct {
	w           io.Writer
	fn          ProgressFunc
	done, total int64
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.done += int64(n)
	if p.fn != nil && n > 0 {
		p.fn(p.done, p.total)
	}
	return n, err
}
