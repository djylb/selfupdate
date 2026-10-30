package selfupdate

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeTemp(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// extractAt and extractDirAt run Extract and ExtractDir on the file src.
func extractAt(src string, format Format, members []Member, opts ExtractOptions) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer closeQuietly(f)
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return Extract(context.Background(), f, fi.Size(), format, members, opts)
}

func extractDirAt(src string, format Format, prefix, dst string, opts ExtractOptions) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer closeQuietly(f)
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return ExtractDir(context.Background(), f, fi.Size(), format, prefix, dst, opts)
}

// TestExtractKeepsExistingFiles is a regression test: a member path that
// already exists made Extract fail and then delete that file.
func TestExtractKeepsExistingFiles(t *testing.T) {
	dir := t.TempDir()
	src := writeTemp(t, dir, "a.tar", tarGz(t, false, tarEntry{name: "a", body: "A"}, tarEntry{name: "b", body: "B"}))
	keep := writeTemp(t, dir, "keep", []byte("precious"))
	err := extractAt(src, FormatTar, []Member{{Name: "a", Path: filepath.Join(dir, "a")}, {Name: "b", Path: keep}}, ExtractOptions{})
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err = %v", err)
	}
	if readFile(t, keep) != "precious" {
		t.Fatal("existing file changed")
	}
	if _, err := os.Lstat(filepath.Join(dir, "a")); err == nil {
		t.Error("partial output left")
	}
}

// TestExtractMultistreamGzip is a regression test: only the first member
// of a concatenated gzip file was extracted, silently.
func TestExtractMultistreamGzip(t *testing.T) {
	dir := t.TempDir()
	data := append(gzipOf(t, []byte("part1-")), gzipOf(t, []byte("part2"))...)
	src := writeTemp(t, dir, "m.gz", data)
	out := filepath.Join(dir, "out")
	must(t, extractAt(src, FormatGzip, []Member{{Path: out}}, ExtractOptions{}))
	if got := readFile(t, out); got != "part1-part2" {
		t.Fatalf("got %q", got)
	}
	bad := writeTemp(t, dir, "bad.gz", append(gzipOf(t, []byte("x")), "junk"...))
	if err := extractAt(bad, FormatGzip, []Member{{Path: filepath.Join(dir, "bad")}}, ExtractOptions{}); err == nil {
		t.Error("trailing garbage accepted")
	}
}

func TestExtractCancel(t *testing.T) {
	dir := t.TempDir()
	data := tarGz(t, true, tarEntry{name: "app", body: "x"})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := Extract(ctx, bytes.NewReader(data), int64(len(data)), FormatTarGzip, []Member{{Name: "app", Path: filepath.Join(dir, "o")}}, ExtractOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	var last int64
	must(t, Extract(t.Context(), bytes.NewReader(data), int64(len(data)), FormatTarGzip, []Member{{Name: "app", Path: filepath.Join(dir, "p")}},
		ExtractOptions{Progress: func(done, total int64) { last = done }}))
	if last <= 0 || last > int64(len(data)) {
		t.Errorf("progress %d of %d", last, len(data))
	}
}

func readFile(t testing.TB, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFormatText(t *testing.T) {
	for f := FormatRaw; f <= FormatZip; f++ {
		b, err := f.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var g Format
		if err := g.UnmarshalText(b); err != nil || g != f {
			t.Errorf("round trip %v: %v %v", f, g, err)
		}
	}
	var g Format
	if err := g.UnmarshalText([]byte("tgz")); err != nil || g != FormatTarGzip {
		t.Errorf("tgz: %v %v", g, err)
	}
	if err := g.UnmarshalText([]byte("")); err == nil {
		t.Error("empty format accepted")
	}
	if _, err := FormatUnknown.MarshalText(); err == nil {
		t.Error("unknown format marshalled")
	}
	if FormatUnknown.String() != "Format(0)" {
		t.Error(FormatUnknown.String())
	}
}

func TestExtractMembers(t *testing.T) {
	dir := t.TempDir()
	entries := []tarEntry{
		{name: "./bin/", typeflag: tar.TypeDir},
		{name: "./bin/app", body: "APP"},
		{name: "README", body: "readme"},
		{name: "../../evil", body: "evil"},
		{name: "link", typeflag: tar.TypeSymlink, link: "/etc/passwd"},
	}
	archives := map[Format][]byte{
		FormatTar:     tarGz(t, false, entries...),
		FormatTarGzip: tarGz(t, true, entries...),
		FormatZip:     zipOf(t, entries...),
	}
	for format, data := range archives {
		src := writeTemp(t, dir, "a."+format.String(), data)
		out := filepath.Join(dir, "out-"+format.String())
		if err := extractAt(src, format, []Member{{Name: "bin/app", Path: out, Mode: 0o755}}, ExtractOptions{}); err != nil {
			t.Fatalf("%v: %v", format, err)
		}
		if got := readFile(t, out); got != "APP" {
			t.Errorf("%v: got %q", format, got)
		}
		if runtime.GOOS != "windows" && runtime.GOOS != "js" && runtime.GOOS != "wasip1" {
			if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o755 {
				t.Errorf("%v: mode %v", format, fi.Mode())
			}
		}
		fail := map[string][]Member{
			"symlink":   {{Name: "link", Path: out + ".l"}},
			"missing":   {{Name: "nope", Path: out + ".m"}},
			"traversal": {{Name: "../../evil", Path: out + ".e"}},
			"dot":       {{Name: "./bin/app", Path: out + ".d"}},
			"partial":   {{Name: "README", Path: out + ".r"}, {Name: "nope", Path: out + ".n"}},
		}
		for name, members := range fail {
			if err := extractAt(src, format, members, ExtractOptions{}); err == nil {
				t.Errorf("%v %s: extracted", format, name)
			}
			for _, m := range members {
				if _, err := os.Lstat(m.Path); err == nil {
					t.Errorf("%v %s: left %s behind", format, name, m.Path)
				}
			}
		}
		if _, err := os.Lstat(filepath.Join(dir, "..", "..", "evil")); err == nil {
			t.Fatal("zip slip")
		}
		// Existing output is never overwritten.
		if err := extractAt(src, format, []Member{{Name: "bin/app", Path: out}}, ExtractOptions{}); !errors.Is(err, fs.ErrExist) {
			t.Errorf("%v: overwrote: %v", format, err)
		}
	}
}

func TestExtractDuplicate(t *testing.T) {
	dir := t.TempDir()
	src := writeTemp(t, dir, "dup.tar", tarGz(t, false, tarEntry{name: "app", body: "one"}, tarEntry{name: "./app", body: "two"}))
	if err := extractAt(src, FormatTar, []Member{{Name: "app", Path: filepath.Join(dir, "out")}}, ExtractOptions{}); !errors.Is(err, ErrUnsafeEntry) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestExtractSingleFile(t *testing.T) {
	dir := t.TempDir()
	src := writeTemp(t, dir, "f.gz", gzipOf(t, []byte("hello")))
	if err := extractAt(src, FormatGzip, []Member{{Path: filepath.Join(dir, "f")}}, ExtractOptions{}); err != nil || readFile(t, filepath.Join(dir, "f")) != "hello" {
		t.Fatalf("gzip: %v", err)
	}
	raw := writeTemp(t, dir, "raw", []byte("raw"))
	if err := extractAt(raw, FormatRaw, []Member{{Path: filepath.Join(dir, "r")}}, ExtractOptions{}); err != nil || readFile(t, filepath.Join(dir, "r")) != "raw" {
		t.Fatalf("raw: %v", err)
	}
	if err := extractAt(raw, FormatRaw, nil, ExtractOptions{}); err == nil {
		t.Error("raw without member")
	}
	if err := extractAt(raw, FormatUnknown, []Member{{Path: filepath.Join(dir, "u")}}, ExtractOptions{}); err == nil {
		t.Error("unknown format")
	}
}

func TestExtractBombs(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("A", 1<<20)
	// A file over the per-file limit.
	src := writeTemp(t, dir, "big.tar.gz", tarGz(t, true, tarEntry{name: "app", body: big}))
	if err := extractAt(src, FormatTarGzip, []Member{{Name: "app", Path: filepath.Join(dir, "o1")}}, ExtractOptions{MaxFileSize: 1000}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("file limit: %v", err)
	}
	// Skipped entries still count towards the total.
	src2 := writeTemp(t, dir, "skip.tar.gz", tarGz(t, true, tarEntry{name: "junk", body: big}, tarEntry{name: "app", body: "x"}))
	if err := extractAt(src2, FormatTarGzip, []Member{{Name: "app", Path: filepath.Join(dir, "o2")}}, ExtractOptions{MaxTotalSize: 1 << 16}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("total limit: %v", err)
	}
	zsrc := writeTemp(t, dir, "big.zip", zipOf(t, tarEntry{name: "junk", body: big}, tarEntry{name: "app", body: "x"}))
	// Zip entries are read only when selected; then they count.
	if err := extractAt(zsrc, FormatZip, []Member{{Name: "app", Path: filepath.Join(dir, "o3")}}, ExtractOptions{MaxTotalSize: 1 << 16}); err != nil {
		t.Errorf("zip skipped entry counted: %v", err)
	}
	if err := extractDirAt(zsrc, FormatZip, "", filepath.Join(dir, "o3d"), ExtractOptions{MaxTotalSize: 1 << 16}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("zip total limit: %v", err)
	}
	if err := extractAt(zsrc, FormatZip, []Member{{Name: "junk", Path: filepath.Join(dir, "o4")}}, ExtractOptions{MaxFileSize: 1 << 10}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("zip file limit: %v", err)
	}
	many := make([]tarEntry, 20)
	for i := range many {
		many[i] = tarEntry{name: "f" + string(rune('a'+i))}
	}
	src3 := writeTemp(t, dir, "many.tar", tarGz(t, false, many...))
	if err := extractAt(src3, FormatTar, []Member{{Name: "zz", Path: filepath.Join(dir, "o5")}}, ExtractOptions{MaxEntries: 10}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("entry limit: %v", err)
	}
	gsrc := writeTemp(t, dir, "bomb.gz", gzipOf(t, bytes.Repeat([]byte{0}, 1<<20)))
	if err := extractAt(gsrc, FormatGzip, []Member{{Path: filepath.Join(dir, "o6")}}, ExtractOptions{MaxFileSize: 1 << 10}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("gzip bomb: %v", err)
	}
}

func TestExtractDir(t *testing.T) {
	dir := t.TempDir()
	good := []tarEntry{
		{name: "pkg/", typeflag: tar.TypeDir},
		{name: "pkg/a.dat", body: "a"},
		{name: "pkg/sub/b.dat", body: "b"},
		{name: "other/c.dat", body: "c"},
	}
	for _, format := range []Format{FormatTar, FormatZip} {
		var data []byte
		if format == FormatZip {
			data = zipOf(t, good...)
		} else {
			data = tarGz(t, false, good...)
		}
		src := writeTemp(t, dir, "good."+format.String(), data)
		dst := filepath.Join(dir, "dst-"+format.String())
		if err := extractDirAt(src, format, "pkg", dst, ExtractOptions{}); err != nil {
			t.Fatalf("%v: %v", format, err)
		}
		if readFile(t, filepath.Join(dst, "a.dat")) != "a" || readFile(t, filepath.Join(dst, "sub", "b.dat")) != "b" {
			t.Errorf("%v: wrong content", format)
		}
		if _, err := os.Stat(filepath.Join(dst, "c.dat")); err == nil {
			t.Errorf("%v: extracted outside prefix", format)
		}
		if err := extractDirAt(src, format, "", dst, ExtractOptions{}); !errors.Is(err, fs.ErrExist) {
			t.Errorf("%v: reused destination: %v", format, err)
		}
	}
	// A prefix with no files under it (a typo, a release missing the
	// directory) must not install an empty directory.
	for _, c := range []struct {
		prefix  string
		entries []tarEntry
	}{
		{"data", good},
		{"pkg", []tarEntry{{name: "pkg/", typeflag: tar.TypeDir}}},
		{"", []tarEntry{{name: "empty/", typeflag: tar.TypeDir}}},
	} {
		src := writeTemp(t, dir, "nofiles.tar", tarGz(t, false, c.entries...))
		dst := filepath.Join(dir, "nofiles")
		if err := extractDirAt(src, FormatTar, c.prefix, dst, ExtractOptions{}); !errors.Is(err, ErrMissingMember) {
			t.Errorf("prefix %q: %v", c.prefix, err)
		}
		if _, err := os.Lstat(dst); err == nil {
			t.Errorf("prefix %q: destination left", c.prefix)
		}
	}
	attacks := map[string]tarEntry{
		"parent":    {name: "../evil", body: "x"},
		"nested":    {name: "a/../../evil", body: "x"},
		"absolute":  {name: "/evil", body: "x"},
		"backslash": {name: `a\..\..\evil`, body: "x"},
		"symlink":   {name: "link", typeflag: tar.TypeSymlink, link: "../../etc"},
		"hardlink":  {name: "hard", typeflag: tar.TypeLink, link: "/etc/passwd"},
		"device":    {name: "dev", typeflag: tar.TypeChar},
		"duplicate": {name: "./ok", body: "again"},
	}
	for name, e := range attacks {
		entries := []tarEntry{{name: "ok", body: "ok"}, e}
		for _, format := range []Format{FormatTar, FormatZip} {
			if format == FormatZip && (e.typeflag == tar.TypeLink || e.typeflag == tar.TypeChar) {
				continue
			}
			var data []byte
			if format == FormatZip {
				data = zipOf(t, entries...)
			} else {
				data = tarGz(t, false, entries...)
			}
			src := writeTemp(t, dir, name+"."+format.String(), data)
			dst := filepath.Join(dir, "x-"+name+"-"+format.String())
			if err := extractDirAt(src, format, "", dst, ExtractOptions{}); !errors.Is(err, ErrUnsafeEntry) {
				t.Errorf("%s %v: err = %v", name, format, err)
			}
			if _, err := os.Lstat(dst); err == nil {
				t.Errorf("%s %v: destination left behind", name, format)
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "..", "evil")); err == nil {
		t.Fatal("escaped")
	}
}

func FuzzExtractTar(f *testing.F) {
	f.Add(tarGz(f, true, tarEntry{name: "app", body: "x"}, tarEntry{name: "d/b", body: "y"}), true)
	f.Add(tarGz(f, false, tarEntry{name: "../x", body: "x"}, tarEntry{name: "l", typeflag: tar.TypeSymlink, link: "/"}), false)
	f.Fuzz(func(t *testing.T, data []byte, gz bool) {
		fuzzExtract(t, data, map[bool]Format{true: FormatTarGzip, false: FormatTar}[gz])
	})
}

func FuzzExtractZip(f *testing.F) {
	f.Add(zipOf(f, tarEntry{name: "app", body: "x"}, tarEntry{name: "d/b", body: "y"}))
	f.Add(zipOf(f, tarEntry{name: "../x", body: "x"}, tarEntry{name: "l", typeflag: tar.TypeSymlink, link: "/"}))
	f.Fuzz(func(t *testing.T, data []byte) { fuzzExtract(t, data, FormatZip) })
}

func fuzzExtract(t *testing.T, data []byte, format Format) {
	root := t.TempDir()
	src := writeTemp(t, root, "in", data)
	lim := ExtractOptions{MaxFileSize: 1 << 16, MaxTotalSize: 1 << 20, MaxEntries: 64}
	_ = extractAt(src, format, []Member{{Name: "app", Path: filepath.Join(root, "app")}}, lim)
	dst := filepath.Join(root, "dst")
	if extractDirAt(src, format, "", dst, lim) != nil {
		if _, err := os.Lstat(dst); err == nil {
			t.Fatal("destination left after error")
		}
	}
	// Nothing may appear in root except what was asked for.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "in", "app", "dst":
		default:
			t.Fatalf("unexpected file %s", e.Name())
		}
	}
	_ = filepath.WalkDir(dst, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&fs.ModeSymlink != 0 {
			t.Fatalf("symlink %s", p)
		}
		return nil
	})
}

func TestExtractDirModes(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "js" || runtime.GOOS == "wasip1" || runtime.GOOS == "plan9" {
		t.Skip("no Unix permissions")
	}
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, mode := range map[string]int64{"tool": 0o4755, "data": 0o666} {
		must(t, tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: 1, Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte("x"))
		must(t, err)
	}
	must(t, tw.Close())
	src := writeTemp(t, dir, "m.tar", buf.Bytes())
	dst := filepath.Join(dir, "out")
	must(t, extractDirAt(src, FormatTar, "", dst, ExtractOptions{}))
	for name, want := range map[string]fs.FileMode{"tool": 0o755, "data": 0o644} {
		fi, err := os.Stat(filepath.Join(dst, name))
		must(t, err)
		if fi.Mode() != want {
			t.Errorf("%s: mode %v, want %v", name, fi.Mode(), want)
		}
	}
	gsrc := writeTemp(t, dir, "z.gz", gzipOf(t, bytes.Repeat([]byte{0}, 1<<16)))
	if err := extractAt(gsrc, FormatGzip, []Member{{Path: filepath.Join(dir, "g")}}, ExtractOptions{MaxTotalSize: 1 << 10}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("gzip total: %v", err)
	}
}
