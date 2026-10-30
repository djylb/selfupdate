package selfupdate

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
)

// ProgressFunc observes a transfer. It is called on the working goroutine,
// with no lock held, after each chunk; done counts bytes so far and total
// is the expected size. It must not block for long.
type ProgressFunc func(done, total int64)

// Download copies the artifact a from src into the file dst and checks it
// against the size and digests the artifact pins. On success it returns
// dst opened for reading, positioned at its start, so the verified content
// is read through the same open file it was checked in; the caller closes
// it. On a mismatch dst is truncated and [ErrDigestMismatch] is returned.
//
// If dst already holds a prefix of the content (an interrupted earlier
// call), only the rest is requested; a source that cannot resume starts
// over, and so does a resumed file that turns out not to match. Only the
// digests the artifact lists are computed. progress may be nil.
func Download(ctx context.Context, src Source, a Artifact, dst string, progress ProgressFunc) (_ *os.File, err error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			closeQuietly(f)
		}
	}()
	h := newHasher(a)
	have, err := io.Copy(h, io.LimitReader(f, a.Size+1))
	if err != nil {
		return nil, err
	}
	if have > a.Size {
		if err := restart(f, h); err != nil {
			return nil, err
		}
		have = 0
	}
	for resumed := have > 0; ; resumed = false {
		if have < a.Size {
			if err := fetch(ctx, src, a, f, h, have, progress); err != nil {
				return nil, err
			}
		}
		err := a.Check(a.Size, h.sum())
		if err == nil {
			break
		}
		if rerr := restart(f, h); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
		if !resumed {
			return nil, err
		}
		have = 0 // the kept prefix was bad: start over once
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return f, nil
}

// fetch appends the artifact from offset have to f.
func fetch(ctx context.Context, src Source, a Artifact, f *os.File, h *hasher, have int64, progress ProgressFunc) error {
	r, start, err := src.Open(ctx, a, have)
	if err != nil {
		return err
	}
	defer closeQuietly(r)
	switch start {
	case have:
	case 0:
		if err := restart(f, h); err != nil {
			return err
		}
	default:
		return fmt.Errorf("selfupdate: source resumed at %d, not %d or 0", start, have)
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	w := &progressWriter{w: io.MultiWriter(f, h), done: start, total: a.Size, fn: progress}
	n, err := io.Copy(w, io.LimitReader(r, a.Size-start+1))
	if err != nil {
		return err
	}
	switch got := start + n; {
	case got > a.Size:
		return fmt.Errorf("%w: more than %d bytes", ErrTooLarge, a.Size)
	case got < a.Size:
		return fmt.Errorf("selfupdate: download ended after %d of %d bytes: %w", got, a.Size, io.ErrUnexpectedEOF)
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

// hasher computes the digests an artifact lists, and only those.
type hasher struct {
	s256, s512 hash.Hash
}

func newHasher(a Artifact) *hasher {
	h := &hasher{}
	if a.SHA256 != "" {
		h.s256 = sha256.New()
	}
	if a.SHA512 != "" {
		h.s512 = sha512.New()
	}
	return h
}

func (h *hasher) Write(p []byte) (int, error) {
	if h.s256 != nil {
		h.s256.Write(p)
	}
	if h.s512 != nil {
		h.s512.Write(p)
	}
	return len(p), nil
}

func (h *hasher) reset() {
	if h.s256 != nil {
		h.s256.Reset()
	}
	if h.s512 != nil {
		h.s512.Reset()
	}
}

// sum returns the digests computed; the others stay zero.
func (h *hasher) sum() Digests {
	var d Digests
	if h.s256 != nil {
		h.s256.Sum(d.SHA256[:0])
	}
	if h.s512 != nil {
		h.s512.Sum(d.SHA512[:0])
	}
	return d
}

// DigestFile returns the size and both digests of the file at p, as a
// publisher needs them to describe an artifact.
func DigestFile(p string) (int64, Digests, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, Digests{}, err
	}
	defer closeQuietly(f)
	h := &hasher{s256: sha256.New(), s512: sha512.New()}
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
