package selfupdate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
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
	if err := j.Replace(bg, set, ReplaceOptions{Version: "2", Previous: "1", Pending: true}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, app) != "new app" || readFile(t, lib) != "new lib" {
		t.Fatal("not replaced")
	}
	if fi, err := os.Stat(app); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755) {
		t.Errorf("mode not kept: %v %v", fi, err)
	}
	third := stage(t, app, "third")
	if err := j.Replace(bg, []Replacement{third}, ReplaceOptions{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second update: %v", err)
	}
	must(t, os.Remove(third.Staged))
	out, err := j.Startup(bg, 1)
	if err != nil || out.Status != StatusPending || out.Version != "2" || out.Previous != "1" {
		t.Fatalf("startup: %+v %v", out, err)
	}
	if err := j.Commit(bg); err != nil {
		t.Fatal(err)
	}
	if err := j.Commit(bg); !errors.Is(err, ErrNotPending) {
		t.Errorf("second commit: %v", err)
	}
	if out, err := j.Startup(bg, 1); err != nil || out.Status != StatusIdle {
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
	if err := j.Replace(bg, []Replacement{stage(t, app, "new app"), stage(t, lib, "new lib")}, ReplaceOptions{Pending: true}); err != nil {
		t.Fatal(err)
	}
	for boot := 1; boot <= 2; boot++ {
		if out, err := j.Startup(bg, 2); err != nil || out.Status != StatusPending {
			t.Fatalf("boot %d: %+v %v", boot, out, err)
		}
	}
	out, err := j.Startup(bg, 2)
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
	if err := j.Rollback(bg); !errors.Is(err, ErrNotPending) {
		t.Errorf("rollback without update: %v", err)
	}
}

func TestJournalExplicitRollback(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "app")
	must(t, os.WriteFile(app, []byte("old"), 0o755))
	j := JournalFor(app)
	if err := j.Replace(bg, []Replacement{stage(t, app, "new")}, ReplaceOptions{Pending: true}); err != nil {
		t.Fatal(err)
	}
	if err := j.Rollback(bg); err != nil {
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
	if err := j.Replace(bg, []Replacement{stage(t, db, "v2")}, ReplaceOptions{}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, db) != "v2" || !slices.Equal(listDir(t, dir), []string{"rules.db"}) {
		t.Fatalf("immediate: %v", listDir(t, dir))
	}
	if err := j.Commit(bg); !errors.Is(err, ErrNotPending) {
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
		out, err := j.Startup(bg, 1)
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
		if _, err := j.Startup(bg, 1); !errors.Is(err, ErrCorruptJournal) {
			t.Fatalf("corrupt journal %q: %v", bad, err)
		}
	}
	if err := j.Replace(bg, []Replacement{stage(t, filepath.Join(dir, "x"), "n")}, ReplaceOptions{}); err == nil {
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
	if err := j.Replace(bg, []Replacement{stage(t, filepath.Join(dir, "x"), "n")}, ReplaceOptions{}); err != nil {
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
		if err := j.Replace(bg, set, ReplaceOptions{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Lstat(j.Path); err == nil {
			t.Fatalf("%s: journal left", name)
		}
	}
}

func TestStatusString(t *testing.T) {
	for s, want := range map[Status]string{StatusIdle: "idle", StatusPending: "pending", StatusRolledBack: "rolled back", StatusInProgress: "in progress", StatusCleanup: "cleaning up", Status(9): "Status(9)"} {
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
	must(t, j.Replace(bg, []Replacement{stage(t, a, "newA"), stage(t, b, "newB")}, ReplaceOptions{Pending: true}))
	// Restoring b (done first) fails while its backup is unavailable.
	must(t, os.Rename(b+backupSuffix, b+".hidden"))
	if err := j.Rollback(bg); err == nil {
		t.Fatal("rollback without backup succeeded")
	}
	must(t, os.Rename(b+".hidden", b+backupSuffix))
	for range 2 { // a retry, then a later start, must both be harmless
		if _, err := j.Startup(bg, 1); err != nil {
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
	must(t, j.Replace(bg, []Replacement{stage(t, a, "v1")}, ReplaceOptions{Pending: true}))
	if _, err := newJournalFile(a, stage(t, a, "v2").Staged); err != nil {
		t.Fatal(err)
	}
	if err := j.Replace(bg, []Replacement{stage(t, a, "v3")}, ReplaceOptions{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second update: %v", err)
	}
	must(t, j.Rollback(bg))
	if readFile(t, a) != "old" {
		t.Fatal("original lost")
	}
}

func TestRecoverDoesNotCountBoots(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	must(t, j.Replace(bg, []Replacement{stage(t, a, "new")}, ReplaceOptions{Pending: true}))
	for range 3 {
		if out, err := j.Recover(bg); err != nil || out.Status != StatusPending || out.Boots != 0 {
			t.Fatalf("recover: %+v %v", out, err)
		}
	}
	if out, err := j.Startup(bg, 1); err != nil || out.Status != StatusPending || out.Boots != 1 {
		t.Fatalf("startup: %+v %v", out, err)
	}
	must(t, j.Commit(bg))
}

// TestRestoreRefusesAmbiguity leaves a file at the trash path of a swapped
// file, which no update writes there: rollback must stop, not guess.
func TestRestoreRefusesAmbiguity(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	must(t, os.WriteFile(a, []byte("old"), 0o644))
	j := JournalFor(a)
	must(t, j.Replace(bg, []Replacement{stage(t, a, "new")}, ReplaceOptions{Pending: true}))
	st, _, err := j.load()
	must(t, err)
	must(t, os.WriteFile(st.Files[0].Trash, []byte("?"), 0o644))
	if err := j.Rollback(bg); err == nil {
		t.Fatal("ambiguous rollback went ahead")
	}
	if readFile(t, a) != "new" || readFile(t, a+backupSuffix) != "old" {
		t.Fatal("files touched")
	}
}

// errInjected is the failure injected by tests.
var errInjected = errors.New("injected failure")

// crash is the panic value of a simulated crash.
type crash struct{}

// TestRollbackFailureInjection is a regression test: a rollback that
// failed after restoring a target that was never swapped deleted its
// staged copy, and every later recovery then took the target for one
// whose backup was lost. An update of three files fails while swapping
// the last one; then every rename of the rollback fails, or the process
// crashes after every durable step, once each. Recovery must always end
// with the old files and nothing else.
func TestRollbackFailureInjection(t *testing.T) {
	t.Cleanup(func() { testHookStep, testHookRename = nil, nil })
	// run reports whether the failure was injected, that is, whether the
	// rollback took that many renames or steps.
	run := func(t *testing.T, failRename, crashStep int) (injected bool) {
		dir := t.TempDir()
		names := []string{"a", "b", "c"}
		var set []Replacement
		for _, n := range names {
			p := filepath.Join(dir, n)
			must(t, os.WriteFile(p, []byte("old "+n), 0o644))
			set = append(set, stage(t, p, "new "+n))
		}
		j := JournalFor(set[0].Target)
		renames, steps := 0, 0
		swapping := true
		testHookRename = func(from, to string) error {
			if swapping && from == set[2].Staged {
				swapping = false // c's swap fails: the rollback starts
				return errInjected
			}
			if !swapping {
				if renames++; renames == failRename {
					injected = true
					return errInjected
				}
			}
			return nil
		}
		testHookStep = func(string) {
			if !swapping {
				if steps++; steps == crashStep {
					injected = true
					panic(crash{})
				}
			}
		}
		func() {
			defer func() {
				if r := recover(); r != nil && r != (crash{}) {
					panic(r)
				}
			}()
			if err := j.Replace(bg, set, ReplaceOptions{Pending: true}); err == nil {
				t.Fatal("replace succeeded")
			}
		}()
		testHookStep, testHookRename = nil, nil
		if _, err := j.Startup(bg, 1); err != nil {
			t.Fatalf("recovery: %v", err)
		}
		for _, n := range names {
			if got := readFile(t, filepath.Join(dir, n)); got != "old "+n {
				t.Errorf("%s = %q", n, got)
			}
		}
		if got := listDir(t, dir); !slices.Equal(got, names) {
			t.Errorf("dir %v", got)
		}
		return injected
	}
	for n, more := 1, true; more; n++ {
		t.Run(fmt.Sprint("rename", n), func(t *testing.T) { more = run(t, n, 0) })
	}
	for n, more := 1, true; more; n++ {
		t.Run(fmt.Sprint("crash", n), func(t *testing.T) { more = run(t, 0, n) })
	}
}

// TestPeekCleanup checks that leftovers of a finished update are reported,
// since they keep a new update from starting.
func TestPeekCleanup(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	must(t, os.WriteFile(a+".t", []byte("left"), 0o644))
	j := JournalFor(a)
	must(t, j.save(&journalState{Phase: phaseCleanup, Files: []journalFile{{Target: a, Staged: a + ".s", Backup: a + backupSuffix, Trash: a + ".t"}}}))
	if out, err := j.Peek(); err != nil || out.Status != StatusCleanup {
		t.Fatalf("peek: %+v %v", out, err)
	}
	if out, err := j.Recover(bg); err != nil || out.Status != StatusIdle {
		t.Fatalf("recover: %+v %v", out, err)
	}
	if out, err := j.Peek(); err != nil || out.Status != StatusIdle {
		t.Fatalf("peek after: %+v %v", out, err)
	}
}
