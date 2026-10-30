package selfupdate

import (
	"archive/tar"
	"bytes"
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
		if err := Extract(src, format, []Member{{Name: "bin/app", Path: out, Mode: 0o755}}, Limits{}); err != nil {
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
			if err := Extract(src, format, members, Limits{}); err == nil {
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
		if err := Extract(src, format, []Member{{Name: "bin/app", Path: out}}, Limits{}); !errors.Is(err, fs.ErrExist) {
			t.Errorf("%v: overwrote: %v", format, err)
		}
	}
}

func TestExtractDuplicate(t *testing.T) {
	dir := t.TempDir()
	src := writeTemp(t, dir, "dup.tar", tarGz(t, false, tarEntry{name: "app", body: "one"}, tarEntry{name: "./app", body: "two"}))
	if err := Extract(src, FormatTar, []Member{{Name: "app", Path: filepath.Join(dir, "out")}}, Limits{}); !errors.Is(err, ErrUnsafeEntry) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestExtractSingleFile(t *testing.T) {
	dir := t.TempDir()
	src := writeTemp(t, dir, "f.gz", gzipOf(t, []byte("hello")))
	if err := Extract(src, FormatGzip, []Member{{Path: filepath.Join(dir, "f")}}, Limits{}); err != nil || readFile(t, filepath.Join(dir, "f")) != "hello" {
		t.Fatalf("gzip: %v", err)
	}
	raw := writeTemp(t, dir, "raw", []byte("raw"))
	if err := Extract(raw, FormatRaw, []Member{{Path: filepath.Join(dir, "r")}}, Limits{}); err != nil || readFile(t, filepath.Join(dir, "r")) != "raw" {
		t.Fatalf("raw: %v", err)
	}
	if err := Extract(raw, FormatRaw, nil, Limits{}); err == nil {
		t.Error("raw without member")
	}
	if err := Extract(raw, FormatUnknown, []Member{{Path: filepath.Join(dir, "u")}}, Limits{}); err == nil {
		t.Error("unknown format")
	}
}

func TestExtractBombs(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("A", 1<<20)
	// A file over the per-file limit.
	src := writeTemp(t, dir, "big.tar.gz", tarGz(t, true, tarEntry{name: "app", body: big}))
	if err := Extract(src, FormatTarGzip, []Member{{Name: "app", Path: filepath.Join(dir, "o1")}}, Limits{MaxFileSize: 1000}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("file limit: %v", err)
	}
	// Skipped entries still count towards the total.
	src2 := writeTemp(t, dir, "skip.tar.gz", tarGz(t, true, tarEntry{name: "junk", body: big}, tarEntry{name: "app", body: "x"}))
	if err := Extract(src2, FormatTarGzip, []Member{{Name: "app", Path: filepath.Join(dir, "o2")}}, Limits{MaxTotalSize: 1 << 16}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("total limit: %v", err)
	}
	zsrc := writeTemp(t, dir, "big.zip", zipOf(t, tarEntry{name: "junk", body: big}, tarEntry{name: "app", body: "x"}))
	// Zip entries are read only when selected; then they count.
	if err := Extract(zsrc, FormatZip, []Member{{Name: "app", Path: filepath.Join(dir, "o3")}}, Limits{MaxTotalSize: 1 << 16}); err != nil {
		t.Errorf("zip skipped entry counted: %v", err)
	}
	if err := ExtractDir(zsrc, FormatZip, "", filepath.Join(dir, "o3d"), Limits{MaxTotalSize: 1 << 16}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("zip total limit: %v", err)
	}
	if err := Extract(zsrc, FormatZip, []Member{{Name: "junk", Path: filepath.Join(dir, "o4")}}, Limits{MaxFileSize: 1 << 10}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("zip file limit: %v", err)
	}
	many := make([]tarEntry, 20)
	for i := range many {
		many[i] = tarEntry{name: "f" + string(rune('a'+i))}
	}
	src3 := writeTemp(t, dir, "many.tar", tarGz(t, false, many...))
	if err := Extract(src3, FormatTar, []Member{{Name: "zz", Path: filepath.Join(dir, "o5")}}, Limits{MaxEntries: 10}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("entry limit: %v", err)
	}
	gsrc := writeTemp(t, dir, "bomb.gz", gzipOf(t, bytes.Repeat([]byte{0}, 1<<20)))
	if err := Extract(gsrc, FormatGzip, []Member{{Path: filepath.Join(dir, "o6")}}, Limits{MaxFileSize: 1 << 10}); !errors.Is(err, ErrTooLarge) {
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
		if err := ExtractDir(src, format, "pkg", dst, Limits{}); err != nil {
			t.Fatalf("%v: %v", format, err)
		}
		if readFile(t, filepath.Join(dst, "a.dat")) != "a" || readFile(t, filepath.Join(dst, "sub", "b.dat")) != "b" {
			t.Errorf("%v: wrong content", format)
		}
		if _, err := os.Stat(filepath.Join(dst, "c.dat")); err == nil {
			t.Errorf("%v: extracted outside prefix", format)
		}
		if err := ExtractDir(src, format, "", dst, Limits{}); !errors.Is(err, fs.ErrExist) {
			t.Errorf("%v: reused destination: %v", format, err)
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
			if err := ExtractDir(src, format, "", dst, Limits{}); !errors.Is(err, ErrUnsafeEntry) {
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
	lim := Limits{MaxFileSize: 1 << 16, MaxTotalSize: 1 << 20, MaxEntries: 64}
	_ = Extract(src, format, []Member{{Name: "app", Path: filepath.Join(root, "app")}}, lim)
	dst := filepath.Join(root, "dst")
	if ExtractDir(src, format, "", dst, lim) != nil {
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
	must(t, ExtractDir(src, FormatTar, "", dst, Limits{}))
	for name, want := range map[string]fs.FileMode{"tool": 0o755, "data": 0o644} {
		fi, err := os.Stat(filepath.Join(dst, name))
		must(t, err)
		if fi.Mode() != want {
			t.Errorf("%s: mode %v, want %v", name, fi.Mode(), want)
		}
	}
	gsrc := writeTemp(t, dir, "z.gz", gzipOf(t, bytes.Repeat([]byte{0}, 1<<16)))
	if err := Extract(gsrc, FormatGzip, []Member{{Path: filepath.Join(dir, "g")}}, Limits{MaxTotalSize: 1 << 10}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("gzip total: %v", err)
	}
}
