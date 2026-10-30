package selfupdate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func canRunChildren() bool {
	switch runtime.GOOS {
	case "js", "wasip1", "plan9", "ios", "android":
		return false
	}
	return true
}

// helperHold takes the lock at path, reports it on stdout and waits to be
// killed: hold <path>.
func helperHold(path string) error {
	l, err := lockFile(bg, path)
	if err != nil {
		return err
	}
	if _, err := fmt.Println("locked"); err != nil {
		return err
	}
	time.Sleep(time.Hour)
	runtime.KeepAlive(l) // a collected file is closed, which releases its lock
	return errors.New("not killed")
}

// helperTryLock tries the lock at path once and prints "locked" or
// "busy": trylock <path>.
func helperTryLock(path string) error {
	l, err := tryLockFile(path)
	if errors.Is(err, errLocked) {
		_, err = fmt.Println("busy")
		return err
	}
	if err != nil {
		return err
	}
	l.unlock()
	_, err = fmt.Println("locked")
	return err
}

func TestFileLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	l, err := lockFile(bg, p)
	must(t, err)
	if _, err := tryLockFile(p); !errors.Is(err, errLocked) {
		t.Fatalf("second lock: %v", err)
	}
	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	if _, err := lockFile(ctx, p); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait: %v", err)
	}
	l.unlock()
	if _, err := os.Lstat(p); err == nil {
		t.Error("lock file left")
	}
	// Many goroutines take turns; none sees another inside.
	var wg sync.WaitGroup
	var inside, entered int
	var mu sync.Mutex
	for range 16 {
		wg.Go(func() {
			l, err := lockFile(bg, p)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			entered++
			if inside != 1 {
				t.Error("two holders")
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			l.unlock()
		})
	}
	wg.Wait()
	if entered != 16 {
		t.Fatalf("entered %d", entered)
	}
	localLocks.Lock()
	n := len(localLocks.m)
	localLocks.Unlock()
	if n != 0 {
		t.Errorf("%d local locks left", n)
	}
}

// TestLockOfDeadProcess is a regression test: locks and stagings were
// judged alive by process ID, so a process ID reused (always 1 in a
// container) kept them forever. A killed holder's lock is free at once.
func TestLockOfDeadProcess(t *testing.T) {
	if !canRunChildren() {
		t.Skip("cannot run child processes here")
	}
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	must(t, j.Replace(bg, []Replacement{stage(t, a, "new")}, ReplaceOptions{Pending: true}))
	self, err := os.Executable()
	must(t, err)
	cmd := exec.Command(self, "hold", j.opLock())
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	stdout, err := cmd.StdoutPipe()
	must(t, err)
	must(t, cmd.Start())
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("helper: %q %v", line, err)
	}
	ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	_, err = j.Recover(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("recover under another process's lock: %v", err)
	}
	must(t, cmd.Process.Kill())
	_ = cmd.Wait()
	ctx, cancel = context.WithTimeout(bg, time.Minute)
	defer cancel()
	if out, err := j.Startup(ctx, 1); err != nil || out.Status != StatusPending {
		t.Fatalf("after holder died: %+v %v", out, err)
	}
	must(t, j.Commit(ctx))
	if got := listDir(t, dir); !slices.Equal(got, []string{"a"}) {
		t.Errorf("dir %v", got)
	}

	// A process that dies while staging leaves files the next start
	// deletes.
	cmd = exec.CommandContext(ctx, self, "crash", dir, "stage-exit", "0")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	if out, err := cmd.CombinedOutput(); cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != crashExit {
		t.Fatalf("stager: %v %s", err, out)
	}
	if out, err := j.Peek(); err != nil || out.Status != StatusInProgress {
		t.Fatalf("peek: %+v %v", out, err)
	}
	if out, err := j.Startup(ctx, 1); err != nil || out.Status != StatusIdle {
		t.Fatalf("dead stager: %+v %v", out, err)
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"a"}) {
		t.Errorf("after recovery: %v", got)
	}
}

// TestConcurrentRecover is a regression test: concurrent starts failed
// with ErrBusy because the lock did not wait.
func TestConcurrentRecover(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	run := func() {
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				if _, err := j.Recover(bg); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
	}
	run() // no journal
	must(t, j.Replace(bg, []Replacement{stage(t, a, "new")}, ReplaceOptions{Pending: true}))
	run() // pending
	must(t, j.Commit(bg))
}

// TestStartupReadOnly is a regression test: Startup with no journal
// failed in a directory the process may not write to.
func TestStartupReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "js" || runtime.GOOS == "wasip1" || runtime.GOOS == "plan9" || os.Getuid() == 0 {
		t.Skip("needs Unix permissions and no root")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	must(t, os.Mkdir(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	j := JournalFor(filepath.Join(dir, "app"))
	if out, err := j.Startup(bg, 1); err != nil || out.Status != StatusIdle {
		t.Fatalf("startup: %+v %v", out, err)
	}
	if err := j.Commit(bg); !errors.Is(err, ErrNotPending) {
		t.Errorf("commit: %v", err)
	}
}

func TestStaged(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	s, err := j.Stage(bg, a, b)
	must(t, err)
	for _, p := range s.Paths() {
		must(t, os.WriteFile(p, []byte("new"), 0o644))
	}
	// The stager is alive (this process): others see it busy.
	if _, err := j.Recover(bg); !errors.Is(err, ErrBusy) {
		t.Fatalf("recover while staging: %v", err)
	}
	if _, err := j.Stage(bg, a); !errors.Is(err, ErrBusy) {
		t.Fatalf("second stage: %v", err)
	}
	must(t, s.Abort(bg))
	must(t, s.Abort(bg))
	if err := s.Replace(bg, ReplaceOptions{}); !errors.Is(err, ErrStageEnded) {
		t.Fatalf("replace after abort: %v", err)
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("after abort: %v", got)
	}
	// The normal path; Abort after Replace does nothing.
	s, err = j.Stage(bg, a, b)
	must(t, err)
	for _, p := range s.Paths() {
		must(t, os.WriteFile(p, []byte("new"), 0o644))
	}
	must(t, s.Replace(bg, ReplaceOptions{}))
	must(t, s.Abort(bg))
	if readFile(t, a) != "new" || readFile(t, b) != "new" || !slices.Equal(listDir(t, dir), []string{"a", "b"}) {
		t.Fatalf("staged replace: %v", listDir(t, dir))
	}
	// A failed Replace before the swap keeps the staging for Abort.
	s, err = j.Stage(bg, a)
	must(t, err)
	if err := s.Replace(bg, ReplaceOptions{}); err == nil {
		t.Fatal("replaced without staged file")
	}
	must(t, s.Abort(bg))
	if out, err := j.Peek(); err != nil || out.Status != StatusIdle {
		t.Fatalf("peek: %+v %v", out, err)
	}
}

// TestReplaceDirectory swaps a directory tree as a whole.
func TestReplaceDirectory(t *testing.T) {
	dir := t.TempDir()
	web := filepath.Join(dir, "web")
	must(t, os.MkdirAll(filepath.Join(web, "old"), 0o755))
	must(t, os.WriteFile(filepath.Join(web, "old", "index.html"), []byte("v1"), 0o644))
	j := JournalFor(filepath.Join(dir, "app"))
	s, err := j.Stage(bg, web)
	must(t, err)
	data := tarGz(t, true, tarEntry{name: "site/index.html", body: "v2"}, tarEntry{name: "site/css/a.css", body: "c"})
	src := writeTemp(t, t.TempDir(), "site.tar.gz", data)
	must(t, extractDirAt(src, FormatTarGzip, "site", s.Paths()[0], ExtractOptions{}))
	must(t, s.Replace(bg, ReplaceOptions{Pending: true}))
	if readFile(t, filepath.Join(web, "index.html")) != "v2" || readFile(t, filepath.Join(web, "css", "a.css")) != "c" {
		t.Fatal("tree not swapped")
	}
	must(t, j.Rollback(bg))
	if readFile(t, filepath.Join(web, "old", "index.html")) != "v1" {
		t.Fatal("tree not restored")
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"web"}) {
		t.Errorf("dir %v", got)
	}
	// A file cannot replace a directory.
	if err := j.Replace(bg, []Replacement{stage(t, web, "file")}, ReplaceOptions{}); err == nil {
		t.Error("file replaced a directory")
	}
}

// TestStagedAbortContext checks that Abort waits for the journal lock only
// as long as its context allows, and that the update still ends then.
func TestStagedAbortContext(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	j := JournalFor(a)
	s, err := j.Stage(bg, a)
	must(t, err)
	must(t, os.WriteFile(s.Paths()[0], []byte("new"), 0o644))
	l, err := lockFile(bg, j.opLock())
	must(t, err)
	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	if err := s.Abort(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("abort: %v", err)
	}
	l.unlock()
	must(t, s.Abort(bg)) // ended already
	if out, err := j.Recover(bg); err != nil || out.Status != StatusIdle {
		t.Fatalf("recover: %+v %v", out, err)
	}
	if got := listDir(t, dir); len(got) != 0 {
		t.Errorf("left %v", got)
	}
}

// TestSweepDoesNotFailStage is a regression test: Recover swept a stage
// lock file left by a dead stager without the journal lock, so a Stage
// running meanwhile found the stage lock held and failed with ErrBusy.
func TestSweepDoesNotFailStage(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	j := JournalFor(a)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			// A dead stager's lock file, which every Recover sweeps.
			if f, err := os.OpenFile(j.stageLock(), os.O_CREATE|os.O_RDWR, 0o600); err == nil {
				closeQuietly(f)
			}
			if _, err := j.Recover(bg); err != nil && !errors.Is(err, ErrBusy) {
				t.Error(err)
			}
		}
	})
	for range 300 {
		s, err := j.Stage(bg, a)
		if err != nil {
			t.Error(err)
			break
		}
		must(t, s.Abort(bg))
	}
	close(stop)
	wg.Wait()
}

// TestLockFileIdentity checks that two paths to one lock file (here a
// hard link) exclude each other within one process, also where locks
// belong to the process (fcntl).
func TestLockFileIdentity(t *testing.T) {
	switch runtime.GOOS {
	case "js", "wasip1", "plan9":
		t.Skip("no file locks")
	}
	dir := t.TempDir()
	p, q := filepath.Join(dir, "x.lock"), filepath.Join(dir, "y.lock")
	l, err := lockFile(bg, p)
	must(t, err)
	if err := os.Link(p, q); err != nil {
		l.unlock()
		t.Skip(err)
	}
	if _, err := tryLockFile(q); !errors.Is(err, errLocked) {
		t.Fatalf("lock through a second path: %v", err)
	}
	// Closing the file of the failed attempt must not have dropped the
	// lock, which fcntl does to every lock of the process on the file.
	if canRunChildren() {
		self, err := os.Executable()
		must(t, err)
		cmd := exec.Command(self, "trylock", p)
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		out, err := cmd.Output()
		if err != nil || strings.TrimSpace(string(out)) != "busy" {
			t.Errorf("other process: %q %v", out, err)
		}
	}
	l.unlock()
	l2, err := tryLockFile(q)
	must(t, err)
	l2.unlock()
}
