package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Format is how an artifact is packed.
type Format int

// The supported formats. The zero value is invalid, so a manifest must
// name the format of every artifact.
const (
	FormatUnknown Format = iota
	// FormatRaw is a file stored as is.
	FormatRaw
	// FormatGzip is a single gzip-compressed file.
	FormatGzip
	// FormatTar is an uncompressed tar archive.
	FormatTar
	// FormatTarGzip is a gzip-compressed tar archive.
	FormatTarGzip
	// FormatZip is a zip archive.
	FormatZip
)

var formatNames = [...]string{
	FormatUnknown: "",
	FormatRaw:     "raw",
	FormatGzip:    "gz",
	FormatTar:     "tar",
	FormatTarGzip: "tar.gz",
	FormatZip:     "zip",
}

func (f Format) valid() bool { return f > FormatUnknown && int(f) < len(formatNames) }

// String returns the name used in manifests: "raw", "gz", "tar", "tar.gz"
// or "zip".
func (f Format) String() string {
	if f.valid() {
		return formatNames[f]
	}
	return fmt.Sprintf("Format(%d)", int(f))
}

// MarshalText implements [encoding.TextMarshaler].
func (f Format) MarshalText() ([]byte, error) {
	if !f.valid() {
		return nil, fmt.Errorf("selfupdate: invalid format %d", int(f))
	}
	return []byte(formatNames[f]), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler]. "tgz" is accepted
// for "tar.gz".
//
//goland:noinspection GoMixedReceiverTypes
func (f *Format) UnmarshalText(b []byte) error {
	s := string(b)
	if s == "tgz" {
		s = "tar.gz"
	}
	for i, n := range formatNames {
		if n != "" && n == s {
			*f = Format(i)
			return nil
		}
	}
	return fmt.Errorf("selfupdate: unknown format %q", s)
}

// Errors returned by extraction.
var (
	ErrUnsafeEntry   = errors.New("selfupdate: unsafe archive entry")
	ErrMissingMember = errors.New("selfupdate: archive member not found")
	ErrTooLarge      = errors.New("selfupdate: size limit exceeded")
)

// Limits bounds what extraction reads and writes. Zero fields take the
// defaults noted on each field.
type Limits struct {
	// MaxFileSize bounds each extracted file. Default 1 GiB.
	MaxFileSize int64
	// MaxTotalSize bounds all bytes decompressed. For gzip files and tar
	// archives this
	// includes skipped entries, which must be read past; zip entries are
	// only read when extracted. Default 4 GiB.
	MaxTotalSize int64
	// MaxEntries bounds the number of archive entries. Default 100000.
	MaxEntries int
}

func (l Limits) withDefaults() Limits {
	if l.MaxFileSize <= 0 {
		l.MaxFileSize = 1 << 30
	}
	if l.MaxTotalSize <= 0 {
		l.MaxTotalSize = 4 << 30
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = 100000
	}
	return l
}

// Member selects one file to extract.
type Member struct {
	// Name is the slash-separated path of the file inside the archive,
	// such as "bin/app". A leading "./" in the archive is ignored. Name is
	// ignored for [FormatRaw] and [FormatGzip].
	Name string
	// Path is where the file is written. It must not exist yet.
	Path string
	// Mode is the permission of the written file; only the permission
	// bits are used. Zero means 0o644.
	Mode fs.FileMode
}

// Extract writes the selected members of the archive at src to their
// paths. Output paths come only from members, never from the archive, so
// entry names cannot escape. A selected entry that is not a regular file
// (a symlink, hard link or device) is an error, as is a selected name that
// occurs twice or is missing. On error the files written so far are
// removed.
func Extract(src string, format Format, members []Member, limits Limits) (err error) {
	limits = limits.withDefaults()
	for _, m := range members {
		if m.Path == "" {
			return errors.New("selfupdate: member without path")
		}
		if (format == FormatTar || format == FormatTarGzip || format == FormatZip) && !fs.ValidPath(m.Name) {
			return fmt.Errorf("%w: invalid member name %q", ErrUnsafeEntry, m.Name)
		}
	}
	var written []string
	defer func() {
		if err != nil {
			for _, p := range written {
				_ = os.Remove(p)
			}
		}
	}()
	write := func(m Member, r io.Reader) error {
		written = append(written, m.Path)
		return writeLimited(m.Path, m.Mode, r, limits.MaxFileSize)
	}
	switch format {
	case FormatRaw, FormatGzip:
		if len(members) != 1 {
			return errors.New("selfupdate: a single-file format takes exactly one member")
		}
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer closeQuietly(f)
		var r io.Reader = f
		if format == FormatGzip {
			zr, err := gzip.NewReader(f)
			if err != nil {
				return err
			}
			zr.Multistream(false)
			r = zr
		}
		return write(members[0], &countingReader{r: r, limit: limits.MaxTotalSize})
	case FormatTar, FormatTarGzip:
		return walkTar(src, format == FormatTarGzip, limits, func(name string, h *tar.Header, r io.Reader) error {
			m, ok := pick(members, name)
			if !ok {
				return nil
			}
			if h.Typeflag != tar.TypeReg {
				return fmt.Errorf("%w: %s is not a regular file", ErrUnsafeEntry, name)
			}
			if slices.Contains(written, m.Path) {
				return fmt.Errorf("%w: duplicate entry %s", ErrUnsafeEntry, name)
			}
			return write(m, r)
		}, func() error { return missing(members, written) })
	case FormatZip:
		return walkZip(src, limits, func(name string, zf *zip.File, r io.Reader) error {
			m, ok := pick(members, name)
			if !ok {
				return nil
			}
			if !zf.Mode().IsRegular() {
				return fmt.Errorf("%w: %s is not a regular file", ErrUnsafeEntry, name)
			}
			if slices.Contains(written, m.Path) {
				return fmt.Errorf("%w: duplicate entry %s", ErrUnsafeEntry, name)
			}
			return write(m, r)
		}, func() error { return missing(members, written) })
	case FormatUnknown:
	}
	return fmt.Errorf("selfupdate: cannot extract format %v", format)
}

// ExtractDir writes every regular file under prefix in the tar, tar.gz or
// zip archive at src into the directory dst, which must not exist yet.
// Entry names are checked with [filepath.Localize]: absolute paths, ".."
// elements, backslashes and names reserved on Windows are rejected, as are
// symlinks, hard links and devices. Directory entries are implied. Files
// are written with mode 0o755 if the archive marks them executable and
// 0o644 otherwise; setuid, setgid and sticky bits are never set. On error
// dst is removed.
func ExtractDir(src string, format Format, prefix string, dst string, limits Limits) (err error) {
	limits = limits.withDefaults()
	if prefix != "" && !fs.ValidPath(prefix) {
		return fmt.Errorf("%w: invalid prefix %q", ErrUnsafeEntry, prefix)
	}
	if err := os.Mkdir(dst, 0o755); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dst)
		}
	}()
	var seen []string
	visit := func(name string, regular, dir bool, exec bool, r io.Reader) error {
		rel, ok := under(name, prefix)
		if !ok {
			return nil
		}
		local, lerr := filepath.Localize(rel)
		if lerr != nil || strings.Contains(rel, `\`) {
			return fmt.Errorf("%w: %q", ErrUnsafeEntry, name)
		}
		switch {
		case dir:
			return nil
		case !regular:
			return fmt.Errorf("%w: %s is not a regular file", ErrUnsafeEntry, name)
		case slices.Contains(seen, local):
			return fmt.Errorf("%w: duplicate entry %s", ErrUnsafeEntry, name)
		}
		seen = append(seen, local)
		out := filepath.Join(dst, local)
		if err := mkdirUnder(dst, filepath.Dir(local)); err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if exec {
			mode = 0o755
		}
		return writeLimited(out, mode, r, limits.MaxFileSize)
	}
	done := func() error { return nil }
	switch format {
	case FormatTar, FormatTarGzip:
		return walkTar(src, format == FormatTarGzip, limits, func(name string, h *tar.Header, r io.Reader) error {
			return visit(name, h.Typeflag == tar.TypeReg, h.Typeflag == tar.TypeDir, h.Mode&0o111 != 0, r)
		}, done)
	case FormatZip:
		return walkZip(src, limits, func(name string, zf *zip.File, r io.Reader) error {
			return visit(name, zf.Mode().IsRegular(), zf.Mode().IsDir(), zf.Mode()&0o111 != 0, r)
		}, done)
	case FormatUnknown, FormatRaw, FormatGzip:
	}
	return fmt.Errorf("selfupdate: format %v holds no directory", format)
}

// mkdirUnder creates rel below root one element at a time, refusing to
// pass through anything that is not a directory created by MkdirAll
// itself; dst is new, so nothing else can be there.
func mkdirUnder(root, rel string) error {
	if rel == "." {
		return nil
	}
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(p, 0o755); err != nil {
		return err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafeEntry, rel)
	}
	return nil
}

// under returns name relative to prefix when name lies below it.
func under(name, prefix string) (string, bool) {
	name = strings.TrimSuffix(strings.TrimPrefix(name, "./"), "/")
	if name == "" || name == "." {
		return "", false
	}
	if prefix == "" || prefix == "." {
		return name, true
	}
	rest, ok := strings.CutPrefix(name, prefix+"/")
	return rest, ok && rest != ""
}

func cleanEntry(name string) string {
	return path.Clean(strings.TrimPrefix(name, "./"))
}

func pick(members []Member, name string) (Member, bool) {
	name = cleanEntry(name)
	for _, m := range members {
		if m.Name == name {
			return m, true
		}
	}
	return Member{}, false
}

func missing(members []Member, written []string) error {
	for _, m := range members {
		if !slices.Contains(written, m.Path) {
			return fmt.Errorf("%w: %s", ErrMissingMember, m.Name)
		}
	}
	return nil
}

// countingReader fails once more than limit bytes have been read through
// it in total.
type countingReader struct {
	r     io.Reader
	n     int64
	limit int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.limit {
		return n, fmt.Errorf("%w: archive decompresses beyond %d bytes", ErrTooLarge, c.limit)
	}
	return n, err
}

func walkTar(src string, gz bool, limits Limits, fn func(string, *tar.Header, io.Reader) error, done func() error) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer closeQuietly(f)
	var r io.Reader = f
	if gz {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		zr.Multistream(false)
		r = zr
	}
	tr := tar.NewReader(&countingReader{r: r, limit: limits.MaxTotalSize})
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return done()
		}
		if err != nil {
			return err
		}
		if n >= limits.MaxEntries {
			return fmt.Errorf("%w: more than %d entries", ErrTooLarge, limits.MaxEntries)
		}
		if err := fn(h.Name, h, tr); err != nil {
			return err
		}
	}
}

func walkZip(src string, limits Limits, fn func(string, *zip.File, io.Reader) error, done func() error) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer closeQuietly(zr)
	if len(zr.File) > limits.MaxEntries {
		return fmt.Errorf("%w: more than %d entries", ErrTooLarge, limits.MaxEntries)
	}
	total := &countingReader{limit: limits.MaxTotalSize}
	for _, zf := range zr.File {
		if err := visitZip(zf, total, fn); err != nil {
			return err
		}
	}
	return done()
}

func visitZip(zf *zip.File, total *countingReader, fn func(string, *zip.File, io.Reader) error) error {
	if !zf.Mode().IsRegular() {
		return fn(zf.Name, zf, eofReader{})
	}
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer closeQuietly(rc)
	total.r = rc
	return fn(zf.Name, zf, total)
}

// closeQuietly closes a file that was only read: its Close error carries
// no information.
func closeQuietly(c io.Closer) { _ = c.Close() }

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// writeLimited creates path exclusively and copies at most limit bytes
// from r into it, failing if r holds more.
func writeLimited(p string, mode fs.FileMode, r io.Reader, limit int64) (err error) {
	if mode == 0 {
		mode = 0o644
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(p)
		}
	}()
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("%w: %s is larger than %d bytes", ErrTooLarge, filepath.Base(p), limit)
	}
	if err := f.Chmod(mode.Perm()); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	return f.Sync()
}
