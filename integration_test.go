package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The integration test uses the test binary itself as the program that
// updates itself: started with helperEnv set, TestMain runs helperMain.
// Each "version" of the program is a copy of the test binary with a
// version marker appended, which executables tolerate.
const (
	helperEnv    = "SELFUPDATE_TEST_HELPER"
	helperMarker = "\nSELFUPDATE-TEST-VERSION="
)

func helperVersion(exe string) (string, error) {
	f, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer closeQuietly(f)
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	tail := make([]byte, min(fi.Size(), 128))
	if _, err := f.ReadAt(tail, fi.Size()-int64(len(tail))); err != nil {
		return "", err
	}
	i := bytes.LastIndex(tail, []byte(helperMarker))
	if i < 0 {
		return "", errors.New("no version marker")
	}
	return strings.TrimSpace(string(tail[i+len(helperMarker):])), nil
}

// helperMain is the updating program: helper <command> [manifest-url
// public-key [report-file]].
func helperMain(args []string) int {
	if err := helperRun(args); err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		return 1
	}
	return 0
}

func helperRun(args []string) error {
	if args[0] == "crash" {
		return helperCrash(args[1:])
	}
	exe, err := executable("")
	if err != nil {
		return err
	}
	version, err := helperVersion(exe)
	if err != nil {
		return err
	}
	j := JournalFor(exe)
	out, err := j.Startup(1)
	if err != nil {
		return err
	}
	report := version + " " + out.Status.String()
	switch args[0] {
	case "version":
	case "commit":
		if out.Status == StatusPending {
			if err := j.Commit(); err != nil {
				return err
			}
			report += " committed"
		}
	case "report":
		if out.Status == StatusPending {
			if err := j.Commit(); err != nil {
				return err
			}
			report += " committed"
		}
		return os.WriteFile(args[1], []byte(report), 0o644)
	case "update", "update-relaunch":
		pub, err := ParsePublicKey(args[2])
		if err != nil {
			return err
		}
		u := &Updater{
			Source:  &HTTPSource{URL: args[1]},
			Trust:   Trust{Keys: []TrustedKey{{Public: pub}}},
			Product: "helper",
			Current: version,
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		c, err := u.Update(ctx)
		if err != nil {
			return err
		}
		report += " applied " + c.Version
		if args[0] == "update-relaunch" {
			return Relaunch(exe, []string{os.Args[0], "report", args[3]})
		}
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	_, err = fmt.Println(report)
	return err
}

func TestSelfReplaceIntegration(t *testing.T) {
	switch runtime.GOOS {
	case "js", "wasip1", "plan9", "ios", "android":
		t.Skip("cannot run child processes here")
	}
	if testing.Short() {
		t.Skip("short")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	selfBin, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	build := func(version string) []byte {
		return append(slices.Clip(selfBin), helperMarker+version+"\n"...)
	}
	name := "helper"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dir := t.TempDir()
	app := filepath.Join(dir, name)
	if err := os.WriteFile(app, build("1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	fs := newFileServer(t)
	key := newTestKey(t)
	publish := func(version string, format Format) {
		data := build(version)
		if format == FormatTarGzip {
			data = tarGz(t, true, tarEntry{name: "README", body: "notes"}, tarEntry{name: name, body: string(data)})
		}
		file := "helper-" + version + "." + format.String()
		fs.put(file, data)
		a := artifactFor("helper", file, format, data)
		a.OS, a.Arch = runtime.GOOS, runtime.GOARCH
		m := &Manifest{Product: "helper", Published: time.Now(), Expires: time.Now().Add(time.Hour),
			Releases: []Release{{Version: version, Artifacts: []Artifact{a}}}}
		fs.put("manifest.json", mustSign(t, m, key))
	}
	manifestURL := fs.srv.URL + "/manifest.json"
	pub := FormatPublicKey(key.pub)
	run := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, app, args...)
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, stderr.String())
		}
		return strings.TrimSpace(string(out))
	}
	expect := func(want string, args ...string) {
		t.Helper()
		if got := run(args...); got != want {
			t.Fatalf("%v: got %q, want %q", args, got, want)
		}
	}
	files := func() []string { return listDir(t, dir) }

	// 1.0.0 replaces itself, while running, with 2.0.0 from a tar.gz.
	publish("2.0.0", FormatTarGzip)
	expect("1.0.0 idle applied 2.0.0", "update", manifestURL, pub)
	// The new version starts pending and confirms itself.
	expect("2.0.0 pending committed", "commit")
	expect("2.0.0 idle", "version")
	if got := files(); !slices.Equal(got, []string{name}) {
		t.Fatalf("after commit: %v", got)
	}
	// An older release is refused.
	publish("1.5.0", FormatRaw)
	older := exec.Command(app, "update", manifestURL, pub)
	older.Env = append(os.Environ(), helperEnv+"=1")
	if out, err := older.CombinedOutput(); err == nil || !strings.Contains(string(out), ErrUpToDate.Error()) {
		t.Fatalf("older release: %v %s", err, out)
	}
	// 3.0.0 (a raw binary) never confirms: its second start rolls back.
	publish("3.0.0", FormatRaw)
	expect("2.0.0 idle applied 3.0.0", "update", manifestURL, pub)
	expect("3.0.0 pending", "version")
	expect("3.0.0 rolled back", "version")
	expect("2.0.0 idle", "version")
	if got := files(); !slices.Equal(got, []string{name}) {
		t.Fatalf("after rollback: %v", got)
	}
	// Update and relaunch into the new version.
	publish("4.0.0", FormatRaw)
	reportFile := filepath.Join(t.TempDir(), "report")
	cmd := exec.Command(app, "update-relaunch", manifestURL, pub, reportFile)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	var report []byte
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if report, err = os.ReadFile(reportFile); err == nil && len(report) > 0 {
			break
		}
	}
	if string(report) != "4.0.0 pending committed" {
		t.Fatalf("relaunched: %q", report)
	}
	// On Windows the relaunched process may still be exiting.
	deadline := time.Now().Add(30 * time.Second)
	for !slices.Equal(files(), []string{name}) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		run("version")
	}
	if got := files(); !slices.Equal(got, []string{name}) {
		t.Fatalf("final: %v", got)
	}
}

// helperCrash runs one journal operation on the files a and b in dir and
// exits abruptly at durable step number n: crash <dir> <op> <n>.
func helperCrash(args []string) error {
	dir, op := args[0], args[1]
	n, err := strconv.Atoi(args[2])
	if err != nil {
		return err
	}
	count := 0
	testHookStep = func(string) {
		if count++; count == n {
			os.Exit(crashExit)
		}
	}
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	j := JournalFor(a)
	switch op {
	case "replace", "install":
		s, err := j.Stage(a, b)
		if err != nil {
			return err
		}
		for _, p := range s.Paths() {
			if err := os.WriteFile(p, []byte("new"), 0o644); err != nil {
				return err
			}
		}
		return s.Replace(ReplaceOptions{Pending: op == "replace"})
	case "commit":
		return j.Commit()
	case "rollback":
		return j.Rollback()
	}
	return fmt.Errorf("unknown op %q", op)
}

const crashExit = 3

// TestCrashInjection kills a process at every durable step of each
// journal operation and checks that the next start recovers either the
// complete old set or the complete new set, and leaves no stray files.
func TestCrashInjection(t *testing.T) {
	switch runtime.GOOS {
	case "js", "wasip1", "plan9", "ios", "android":
		t.Skip("cannot run child processes here")
	}
	self, err := os.Executable()
	must(t, err)
	for _, op := range []string{"replace", "install", "commit", "rollback"} {
		for n := 1; ; n++ {
			dir := t.TempDir()
			a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
			must(t, os.WriteFile(a, []byte("old"), 0o644))
			// b is new in the update: the old set has only a.
			j := JournalFor(a)
			if op == "commit" || op == "rollback" {
				must(t, j.Replace([]Replacement{stage(t, a, "new"), stage(t, b, "new")}, ReplaceOptions{Pending: true}))
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			cmd := exec.CommandContext(ctx, self, "crash", dir, op, strconv.Itoa(n))
			cmd.Env = append(os.Environ(), helperEnv+"=1")
			out, err := cmd.CombinedOutput()
			cancel()
			var exit *exec.ExitError
			crashed := errors.As(err, &exit) && exit.ExitCode() == crashExit
			if err != nil && !crashed {
				t.Fatalf("%s step %d: %v\n%s", op, n, err, out)
			}
			res, err := j.Startup(1)
			if err != nil {
				t.Fatalf("%s step %d: startup: %v", op, n, err)
			}
			_, berr := os.Lstat(b)
			oldSet := readFile(t, a) == "old" && errors.Is(berr, fs.ErrNotExist)
			newSet := readFile(t, a) == "new" && berr == nil && readFile(t, b) == "new"
			want := []string{"a"}
			switch {
			case newSet && res.Status == StatusPending:
				want = []string{"a", "a" + backupSuffix, "a.selfupdate.json", "b"}
			case newSet && res.Status == StatusIdle:
				want = []string{"a", "b"}
			case oldSet && res.Status != StatusPending:
			default:
				t.Fatalf("%s step %d: mixed state: old=%v new=%v %v %v", op, n, oldSet, newSet, res, listDir(t, dir))
			}
			if op == "rollback" && crashed && !oldSet && res.Status != StatusPending {
				t.Fatalf("%s step %d: rollback lost", op, n)
			}
			if got := listDir(t, dir); !slices.Equal(got, want) {
				t.Fatalf("%s step %d (%v): dir %v, want %v", op, n, res.Status, got, want)
			}
			if !crashed {
				t.Logf("%s: %d crash points", op, n-1)
				break
			}
		}
	}
}
