package selfupdate

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func stage(t testing.TB, target, content string) Replacement {
	t.Helper()
	staged := StagingPath(target)
	if err := os.WriteFile(staged, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return Replacement{Staged: staged, Target: target}
}

func listDir(t testing.TB, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestJournalCommit(t *testing.T) {
	dir := t.TempDir()
	app, lib := filepath.Join(dir, "app"), filepath.Join(dir, "lib.dat")
	if err := os.WriteFile(app, []byte("old app"), 0o755); err != nil {
		t.Fatal(err)
	}
	j := JournalFor(app)
	set := []Replacement{stage(t, app, "new app"), stage(t, lib, "new lib")}
	if err := j.Replace(set, ReplaceOptions{Version: "2", Previous: "1", Pending: true}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, app) != "new app" || readFile(t, lib) != "new lib" {
		t.Fatal("not replaced")
	}
	if fi, err := os.Stat(app); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755) {
		t.Errorf("mode not kept: %v %v", fi, err)
	}
	third := stage(t, app, "third")
	if err := j.Replace([]Replacement{third}, ReplaceOptions{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second update: %v", err)
	}
	must(t, os.Remove(third.Staged))
	out, err := j.Startup(1)
	if err != nil || out.Status != StatusPending || out.Version != "2" || out.Previous != "1" {
		t.Fatalf("startup: %+v %v", out, err)
	}
	if err := j.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := j.Commit(); !errors.Is(err, ErrNotPending) {
		t.Errorf("second commit: %v", err)
	}
	if out, err := j.Startup(1); err != nil || out.Status != StatusIdle {
		t.Fatalf("after commit: %+v %v", out, err)
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"app", "lib.dat"}) {
		t.Errorf("left behind: %v", got)
	}
}

func TestJournalRollbackAfterBoots(t *testing.T) {
	dir := t.TempDir()
	app, lib := filepath.Join(dir, "app"), filepath.Join(dir, "lib.dat")
	must(t, os.WriteFile(app, []byte("old app"), 0o755))
	j := JournalFor(app)
	if err := j.Replace([]Replacement{stage(t, app, "new app"), stage(t, lib, "new lib")}, ReplaceOptions{Pending: true}); err != nil {
		t.Fatal(err)
	}
	for boot := 1; boot <= 2; boot++ {
		if out, err := j.Startup(2); err != nil || out.Status != StatusPending {
			t.Fatalf("boot %d: %+v %v", boot, out, err)
		}
	}
	out, err := j.Startup(2)
	if err != nil || out.Status != StatusRolledBack {
		t.Fatalf("third boot: %+v %v", out, err)
	}
	if readFile(t, app) != "old app" {
		t.Error("app not restored")
	}
	if _, err := os.Lstat(lib); err == nil {
		t.Error("new file not removed")
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"app"}) {
		t.Errorf("dir after rollback: %v", got)
	}
	if err := j.Rollback(); !errors.Is(err, ErrNotPending) {
		t.Errorf("rollback without update: %v", err)
	}
}

func TestJournalExplicitRollback(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "app")
	must(t, os.WriteFile(app, []byte("old"), 0o755))
	j := JournalFor(app)
	if err := j.Replace([]Replacement{stage(t, app, "new")}, ReplaceOptions{Pending: true}); err != nil {
		t.Fatal(err)
	}
	if err := j.Rollback(); err != nil {
		t.Fatal(err)
	}
	if readFile(t, app) != "old" || !slices.Equal(listDir(t, dir), []string{"app"}) {
		t.Fatalf("rollback: %v", listDir(t, dir))
	}
}

func TestJournalImmediate(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "rules.db")
	must(t, os.WriteFile(db, []byte("v1"), 0o600))
	j := JournalFor(db)
	if err := j.Replace([]Replacement{stage(t, db, "v2")}, ReplaceOptions{}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, db) != "v2" || !slices.Equal(listDir(t, dir), []string{"rules.db"}) {
		t.Fatalf("immediate: %v", listDir(t, dir))
	}
	if err := j.Commit(); !errors.Is(err, ErrNotPending) {
		t.Errorf("commit: %v", err)
	}
}

// TestJournalCrashRecovery replays every point at which a crash can stop
// Replace and checks that Startup restores the old files.
func TestJournalCrashRecovery(t *testing.T) {
	for crash := 0; crash <= 4; crash++ {
		dir := t.TempDir()
		a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
		must(t, os.WriteFile(a, []byte("old a"), 0o644))
		must(t, os.WriteFile(b, []byte("old b"), 0o644))
		ra, rb := stage(t, a, "new a"), stage(t, b, "new b")
		st := journalState{Phase: phaseApplying, Files: []journalFile{
			{Target: a, Staged: ra.Staged, Backup: a + backupSuffix, Trash: a + ".t", Existed: true},
			{Target: b, Staged: rb.Staged, Backup: b + backupSuffix, Trash: b + ".t", Existed: true},
		}}
		j := JournalFor(a)
		data, err := json.Marshal(&st)
		must(t, err)
		must(t, os.WriteFile(j.Path, data, 0o600))
		steps := []func(){
			func() { must(t, os.Rename(a, a+backupSuffix)) },
			func() { must(t, os.Rename(ra.Staged, a)) },
			func() { must(t, os.Rename(b, b+backupSuffix)) },
			func() { must(t, os.Rename(rb.Staged, b)) },
		}
		for _, s := range steps[:crash] {
			s()
		}
		out, err := j.Startup(1)
		if err != nil || out.Status != StatusRolledBack {
			t.Fatalf("crash %d: %+v %v", crash, out, err)
		}
		if readFile(t, a) != "old a" || readFile(t, b) != "old b" {
			t.Errorf("crash %d: not restored", crash)
		}
		if got := listDir(t, dir); !slices.Equal(got, []string{"a", "b"}) {
			t.Errorf("crash %d: dir %v", crash, got)
		}
	}
	// Journals are only replaced by rename, so a damaged one is damage
	// from outside: fail closed.
	dir := t.TempDir()
	j := JournalFor(filepath.Join(dir, "x"))
	for _, bad := range []string{"", "\x00\x00", "{bad", "{}"} {
		must(t, os.WriteFile(j.Path, []byte(bad), 0o600))
		if _, err := j.Startup(1); !errors.Is(err, ErrCorruptJournal) {
			t.Fatalf("corrupt journal %q: %v", bad, err)
		}
	}
	if err := j.Replace([]Replacement{stage(t, filepath.Join(dir, "x"), "n")}, ReplaceOptions{}); err == nil {
		t.Fatal("update over corrupt journal")
	}
}

func TestJournalCleanup(t *testing.T) {
	dir := t.TempDir()
	trash := filepath.Join(dir, "x.selfupdate-trash-1")
	must(t, os.WriteFile(trash, nil, 0o600))
	j := JournalFor(filepath.Join(dir, "x"))
	data, err := json.Marshal(&journalState{Phase: phaseCleanup, Files: []journalFile{{Trash: trash}}})
	must(t, err)
	must(t, os.WriteFile(j.Path, data, 0o600))
	// A new update finishes the cleanup first.
	if err := j.Replace([]Replacement{stage(t, filepath.Join(dir, "x"), "n")}, ReplaceOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"x"}) {
		t.Errorf("dir %v", got)
	}
}

func TestReplaceValidates(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	target := filepath.Join(dir, "app")
	j := JournalFor(target)
	staged := filepath.Join(other, "new")
	must(t, os.WriteFile(staged, nil, 0o600))
	cases := map[string][]Replacement{
		"empty":       nil,
		"other dir":   {{Staged: staged, Target: target}},
		"missing":     {{Staged: target + ".nope", Target: target}},
		"twice":       {stage(t, target, "1"), stage(t, target, "2")},
		"not regular": {stage(t, dir, "d")},
	}
	for name, set := range cases {
		if err := j.Replace(set, ReplaceOptions{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Lstat(j.Path); err == nil {
			t.Fatalf("%s: journal left", name)
		}
	}
}

func TestStatusString(t *testing.T) {
	for s, want := range map[Status]string{StatusIdle: "idle", StatusPending: "pending", StatusRolledBack: "rolled back", Status(9): "Status(9)"} {
		if s.String() != want {
			t.Errorf("%d: %s", int(s), s)
		}
	}
	if err := CheckWritable(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing dir writable")
	}
}

// TestRestoreIdempotent interrupts a rollback half-way and retries it.
func TestRestoreIdempotent(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	must(t, os.WriteFile(a, []byte("oldA"), 0o644))
	must(t, os.WriteFile(b, []byte("oldB"), 0o644))
	j := JournalFor(a)
	must(t, j.Replace([]Replacement{stage(t, a, "newA"), stage(t, b, "newB")}, ReplaceOptions{Pending: true}))
	// Restoring b (done first) fails while its backup is unavailable.
	must(t, os.Rename(b+backupSuffix, b+".hidden"))
	if err := j.Rollback(); err == nil {
		t.Fatal("rollback without backup succeeded")
	}
	must(t, os.Rename(b+".hidden", b+backupSuffix))
	for range 2 { // a retry, then a later start, must both be harmless
		if _, err := j.Startup(1); err != nil {
			t.Fatal(err)
		}
	}
	if readFile(t, a) != "oldA" || readFile(t, b) != "oldB" {
		t.Fatalf("a=%q b=%q", readFile(t, a), readFile(t, b))
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("dir %v", got)
	}
}

// TestPrepareTouchesNothing checks that planning a replacement outside the
// lock cannot harm an update in flight.
func TestPrepareTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	must(t, j.Replace([]Replacement{stage(t, a, "v1")}, ReplaceOptions{Pending: true}))
	if _, err := newJournalFile(a, stage(t, a, "v2").Staged); err != nil {
		t.Fatal(err)
	}
	if err := j.Replace([]Replacement{stage(t, a, "v3")}, ReplaceOptions{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second update: %v", err)
	}
	must(t, j.Rollback())
	if readFile(t, a) != "old" {
		t.Fatal("original lost")
	}
}

func TestJournalLock(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	l, err := acquireLock(j.Path + ".lock")
	must(t, err)
	if _, err := j.Startup(1); !errors.Is(err, ErrBusy) {
		t.Errorf("startup under lock: %v", err)
	}
	if err := j.Replace([]Replacement{stage(t, a, "n")}, ReplaceOptions{}); !errors.Is(err, ErrBusy) {
		t.Errorf("replace under lock: %v", err)
	}
	must(t, l.release())
	// A lock left by a dead process is broken.
	dead, err := json.Marshal(owner{Token: "x", PID: deadPID(t)})
	must(t, err)
	must(t, os.WriteFile(j.Path+".lock", dead, 0o600))
	if out, err := j.Startup(1); err != nil || out.Status != StatusIdle {
		t.Fatalf("stale lock: %+v %v", out, err)
	}
	// An unreadable lock is respected for a while.
	must(t, os.WriteFile(j.Path+".lock", nil, 0o600))
	if _, err := j.Recover(); !errors.Is(err, ErrBusy) {
		t.Errorf("fresh unowned lock: %v", err)
	}
	old := time.Now().Add(-2 * unownedGrace)
	must(t, os.Chtimes(j.Path+".lock", old, old))
	if _, err := j.Recover(); err != nil {
		t.Errorf("old unowned lock: %v", err)
	}
}

// deadPID returns the ID of a process that has exited, or a value no
// process has where processes cannot be started.
func deadPID(t *testing.T) int {
	t.Helper()
	switch runtime.GOOS {
	case "js", "wasip1", "plan9", "ios", "android":
		return os.Getpid() + 1
	}
	self, err := os.Executable()
	must(t, err)
	cmd := exec.Command(self, "-test.run=^$")
	must(t, cmd.Run())
	return cmd.Process.Pid
}

func TestRecoverDoesNotCountBoots(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	must(t, j.Replace([]Replacement{stage(t, a, "new")}, ReplaceOptions{Pending: true}))
	for range 3 {
		if out, err := j.Recover(); err != nil || out.Status != StatusPending || out.Boots != 0 {
			t.Fatalf("recover: %+v %v", out, err)
		}
	}
	if out, err := j.Startup(1); err != nil || out.Status != StatusPending || out.Boots != 1 {
		t.Fatalf("startup: %+v %v", out, err)
	}
	must(t, j.Commit())
}

func TestStagedRecovery(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	s, err := j.Stage(a, b)
	must(t, err)
	for _, p := range s.Paths() {
		must(t, os.WriteFile(p, []byte("new"), 0o644))
	}
	// The stager is alive (this process): others wait.
	if _, err := j.Recover(); !errors.Is(err, ErrBusy) {
		t.Fatalf("recover while staging: %v", err)
	}
	if _, err := j.Stage(a); !errors.Is(err, ErrBusy) {
		t.Fatalf("second stage: %v", err)
	}
	must(t, s.Abort())
	if got := listDir(t, dir); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("after abort: %v", got)
	}
	// A stager that died leaves files that the next start deletes.
	s, err = j.Stage(a, b)
	must(t, err)
	for _, p := range s.Paths() {
		must(t, os.WriteFile(p, []byte("new"), 0o644))
	}
	st, _, err := j.load()
	must(t, err)
	st.Owner.PID = deadPID(t)
	must(t, j.save(&st))
	if out, err := j.Startup(1); err != nil || out.Status != StatusIdle {
		t.Fatalf("dead stager: %+v %v", out, err)
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("after recovery: %v", got)
	}
	if err := s.Replace(ReplaceOptions{}); err == nil {
		t.Fatal("replaced a staging taken over")
	}
	// The normal path.
	s, err = j.Stage(a, b)
	must(t, err)
	for _, p := range s.Paths() {
		must(t, os.WriteFile(p, []byte("new"), 0o644))
	}
	must(t, s.Replace(ReplaceOptions{}))
	if readFile(t, a) != "new" || readFile(t, b) != "new" || !slices.Equal(listDir(t, dir), []string{"a", "b"}) {
		t.Fatalf("staged replace: %v", listDir(t, dir))
	}
}

// TestRestoreRefusesAmbiguity leaves a file at the trash path of a swapped
// file, which no update writes there: rollback must stop, not guess.
func TestRestoreRefusesAmbiguity(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	must(t, j.Replace([]Replacement{stage(t, a, "new")}, ReplaceOptions{Pending: true}))
	st, _, err := j.load()
	must(t, err)
	must(t, os.WriteFile(st.Files[0].Trash, []byte("?"), 0o644))
	if err := j.Rollback(); err == nil {
		t.Fatal("ambiguous rollback went ahead")
	}
	if readFile(t, a) != "new" || readFile(t, a+backupSuffix) != "old" {
		t.Fatal("files touched")
	}
}
