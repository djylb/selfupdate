package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
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
	// FormatGzip is a single gzip-compressed file. A file of several gzip
	// members, as concatenation produces, holds their contents in order.
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

// archive reports whether the format holds named entries.
func (f Format) archive() bool { return f == FormatTar || f == FormatTarGzip || f == FormatZip }

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

// FormatOf returns the format a file name's extension implies: ".tar.gz"
// or ".tgz", ".tar", ".zip" and ".gz". Other names, which may be raw files
// or anything else, yield [FormatUnknown].
func FormatOf(name string) Format {
	name = strings.ToLower(name)
	switch {
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return FormatTarGzip
	case strings.HasSuffix(name, ".tar"):
		return FormatTar
	case strings.HasSuffix(name, ".zip"):
		return FormatZip
	case strings.HasSuffix(name, ".gz"):
		return FormatGzip
	}
	return FormatUnknown
}

// Errors returned by extraction.
var (
	ErrUnsafeEntry   = errors.New("selfupdate: unsafe archive entry")
	ErrMissingMember = errors.New("selfupdate: archive member not found")
	ErrTooLarge      = errors.New("selfupdate: size limit exceeded")
)

// ExtractOptions bounds and observes extraction. Zero fields take the
// defaults noted on each field.
type ExtractOptions struct {
	// Progress, when set, is called on the extracting goroutine with the
	// number of bytes of the artifact read so far and its size. Entries
	// that need not be read (zip entries not selected) are skipped, so
	// the count may stop short of the size.
	Progress ProgressFunc
	// MaxFileSize bounds each extracted file. Default 1 GiB.
	MaxFileSize int64
	// MaxTotalSize bounds all bytes decompressed. For gzip files and tar
	// archives this includes skipped entries, which must be read past; zip
	// entries are only read when extracted. Default 4 GiB.
	MaxTotalSize int64
	// MaxEntries bounds the number of archive entries. Default 100000.
	MaxEntries int
}

func (o ExtractOptions) withDefaults() ExtractOptions {
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = 1 << 30
	}
	if o.MaxTotalSize <= 0 {
		o.MaxTotalSize = 4 << 30
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 100000
	}
	return o
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

// input reads the artifact for extraction, checking ctx and reporting
// progress on every read.
type input struct {
	ctx      context.Context
	r        io.ReaderAt
	progress ProgressFunc
	size     int64
	read     int64
}

func (in *input) ReadAt(p []byte, off int64) (int, error) {
	if err := in.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := in.r.ReadAt(p, off)
	if n > 0 && in.progress != nil {
		in.read = min(in.read+int64(n), in.size)
		in.progress(in.read, in.size)
	}
	return n, err
}

func (in *input) stream() io.Reader { return io.NewSectionReader(in, 0, in.size) }

// Extract writes the selected members of the artifact src, of size bytes,
// to their paths. Output paths come only from members, never from the
// archive, so entry names cannot escape. A selected entry that is not a
// regular file (a symlink, hard link or device) is an error, as is a
// selected name that occurs twice or is missing. On error the files
// written so far are removed; files that existed before are never
// touched. ctx cancels a long extraction.
func Extract(ctx context.Context, src io.ReaderAt, size int64, format Format, members []Member, opts ExtractOptions) (err error) {
	opts = opts.withDefaults()
	names, paths := map[string]bool{}, map[string]bool{}
	for _, m := range members {
		if m.Path == "" {
			return errors.New("selfupdate: member without path")
		}
		if format.archive() && !fs.ValidPath(m.Name) {
			return fmt.Errorf("%w: invalid member name %q", ErrUnsafeEntry, m.Name)
		}
		if names[m.Name] || paths[m.Path] {
			return fmt.Errorf("selfupdate: member %q or path %s given twice", m.Name, m.Path)
		}
		names[m.Name], paths[m.Path] = true, true
	}
	in := &input{ctx: ctx, r: src, size: size, progress: opts.Progress}
	written := map[string]bool{} // member names extracted
	var created []string
	defer func() {
		if err != nil {
			for _, p := range created {
				_ = os.Remove(p)
			}
		}
	}()
	write := func(m Member, r io.Reader) error {
		if written[m.Name] {
			return fmt.Errorf("%w: duplicate entry %s", ErrUnsafeEntry, m.Name)
		}
		// writeLimited removes what it created if it fails, and never
		// replaces an existing file.
		if err := writeLimited(m.Path, m.Mode, r, opts.MaxFileSize); err != nil {
			return err
		}
		written[m.Name] = true
		created = append(created, m.Path)
		return nil
	}
	allFound := func() error {
		for _, m := range members {
			if !written[m.Name] {
				return fmt.Errorf("%w: %s", ErrMissingMember, m.Name)
			}
		}
		return nil
	}
	switch format {
	case FormatRaw, FormatGzip:
		if len(members) != 1 {
			return errors.New("selfupdate: a single-file format takes exactly one member")
		}
		r := in.stream()
		if format == FormatGzip {
			zr, err := gzip.NewReader(r)
			if err != nil {
				return err
			}
			r = zr
		}
		return write(members[0], &countingReader{r: r, limit: opts.MaxTotalSize})
	case FormatTar, FormatTarGzip:
		return walkTar(in, format == FormatTarGzip, opts, func(name string, h *tar.Header, r io.Reader) error {
			m, ok := pick(members, name)
			if !ok {
				return nil
			}
			if h.Typeflag != tar.TypeReg {
				return fmt.Errorf("%w: %s is not a regular file", ErrUnsafeEntry, name)
			}
			return write(m, r)
		}, allFound)
	case FormatZip:
		return walkZip(in, opts, func(name string, zf *zip.File, r io.Reader) error {
			m, ok := pick(members, name)
			if !ok {
				return nil
			}
			if !zf.Mode().IsRegular() {
				return fmt.Errorf("%w: %s is not a regular file", ErrUnsafeEntry, name)
			}
			return write(m, r)
		}, allFound)
	case FormatUnknown:
	}
	return fmt.Errorf("selfupdate: cannot extract format %v", format)
}

// ExtractDir writes every regular file under prefix in the tar, tar.gz or
// zip artifact src, of size bytes, into the directory dst, which must not
// exist yet; its parent must. Entry names are checked with
// [filepath.Localize]: absolute paths, ".." elements, backslashes and
// names reserved on Windows are rejected, as are symlinks, hard links and
// devices. Directory entries are implied. Files are written with mode
// 0o755 if the archive marks them executable and 0o644 otherwise;
// setuid, setgid and sticky bits are never set. Files and directories are
// synced, so dst can be swapped in by a [Journal]. An archive with no
// regular file under prefix fails with [ErrMissingMember]. On error dst is
// removed. ctx cancels a long extraction.
func ExtractDir(ctx context.Context, src io.ReaderAt, size int64, format Format, prefix string, dst string, opts ExtractOptions) (err error) {
	opts = opts.withDefaults()
	if prefix != "" && !fs.ValidPath(prefix) {
		return fmt.Errorf("%w: invalid prefix %q", ErrUnsafeEntry, prefix)
	}
	if !format.archive() {
		return fmt.Errorf("selfupdate: format %v holds no directory", format)
	}
	if err := os.Mkdir(dst, 0o755); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dst)
		}
	}()
	seen := map[string]bool{}
	dirs := map[string]bool{".": true}
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
		case seen[local]:
			return fmt.Errorf("%w: duplicate entry %s", ErrUnsafeEntry, name)
		}
		seen[local] = true
		parent := filepath.Dir(local)
		if err := mkdirUnder(dst, parent); err != nil {
			return err
		}
		for d := parent; !dirs[d]; d = filepath.Dir(d) {
			dirs[d] = true
		}
		mode := fs.FileMode(0o644)
		if exec {
			mode = 0o755
		}
		return writeLimited(filepath.Join(dst, local), mode, r, opts.MaxFileSize)
	}
	in := &input{ctx: ctx, r: src, size: size, progress: opts.Progress}
	syncAll := func() error {
		if len(seen) == 0 {
			return fmt.Errorf("%w: no files under %q", ErrMissingMember, prefix)
		}
		for d := range dirs {
			if err := syncDir(filepath.Join(dst, d)); err != nil {
				return err
			}
		}
		return nil
	}
	if format == FormatZip {
		return walkZip(in, opts, func(name string, zf *zip.File, r io.Reader) error {
			return visit(name, zf.Mode().IsRegular(), zf.Mode().IsDir(), zf.Mode()&0o111 != 0, r)
		}, syncAll)
	}
	return walkTar(in, format == FormatTarGzip, opts, func(name string, h *tar.Header, r io.Reader) error {
		return visit(name, h.Typeflag == tar.TypeReg, h.Typeflag == tar.TypeDir, h.Mode&0o111 != 0, r)
	}, syncAll)
}

// mkdirUnder creates rel below root, refusing to pass through anything
// that is not a directory; root is new, so nothing else can be there.
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

func walkTar(in *input, gz bool, opts ExtractOptions, fn func(string, *tar.Header, io.Reader) error, done func() error) error {
	r := in.stream()
	if gz {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		r = zr
	}
	tr := tar.NewReader(&countingReader{r: r, limit: opts.MaxTotalSize})
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return done()
		}
		if err != nil {
			return err
		}
		if n >= opts.MaxEntries {
			return fmt.Errorf("%w: more than %d entries", ErrTooLarge, opts.MaxEntries)
		}
		if err := fn(h.Name, h, tr); err != nil {
			return err
		}
	}
}

func walkZip(in *input, opts ExtractOptions, fn func(string, *zip.File, io.Reader) error, done func() error) error {
	zr, err := zip.NewReader(in, in.size)
	if err != nil {
		return err
	}
	if len(zr.File) > opts.MaxEntries {
		return fmt.Errorf("%w: more than %d entries", ErrTooLarge, opts.MaxEntries)
	}
	total := &countingReader{limit: opts.MaxTotalSize}
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
// from r into it, failing if r holds more. On failure it removes the file
// it created; an existing file makes it fail without touching it.
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
