package selfupdate

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Errors returned by [Journal] operations.
var (
	ErrBusy           = errors.New("selfupdate: another update is in progress or awaits confirmation")
	ErrNotPending     = errors.New("selfupdate: no update awaits confirmation")
	ErrCorruptJournal = errors.New("selfupdate: corrupt journal")
	ErrStageEnded     = errors.New("selfupdate: staged update has ended")
)

// Status is what [Journal.Recover], [Journal.Startup] and [Journal.Peek]
// found.
type Status int

// The journal states.
const (
	// StatusIdle means no update was in flight; run normally.
	StatusIdle Status = iota
	// StatusPending means a new version is installed but not confirmed.
	// Check its health, then call [Journal.Commit].
	StatusPending
	// StatusRolledBack means a failed or unconfirmed update was undone and
	// the previous files are back in place. This process still runs the
	// code that was rolled back, so restart it (see [Relaunch]).
	StatusRolledBack
	// StatusInProgress means an update is being staged or swapped right
	// now, or was interrupted and awaits recovery. Only [Journal.Peek]
	// reports it.
	StatusInProgress
	// StatusCleanup means an update finished but left files that could
	// not be deleted yet, such as a replaced executable that still runs on
	// Windows. No new update can start until a [Journal.Recover] (or the
	// start of the next update) deletes them. Only [Journal.Peek] reports
	// it.
	StatusCleanup
)

// String returns "idle", "pending", "rolled back", "in progress" or
// "cleaning up".
func (s Status) String() string {
	switch s {
	case StatusIdle:
		return "idle"
	case StatusPending:
		return "pending"
	case StatusRolledBack:
		return "rolled back"
	case StatusInProgress:
		return "in progress"
	case StatusCleanup:
		return "cleaning up"
	}
	return fmt.Sprintf("Status(%d)", int(s))
}

// Outcome describes the update recorded in a journal.
type Outcome struct {
	// Version is the version that was installed by the update, as passed
	// in [ReplaceOptions]. After a rollback it names the version that
	// failed; see [Updater.Skip].
	Version string
	// Previous is the version that was replaced.
	Previous string
	// Boots counts the starts of a pending update so far.
	Boots int
	// Status says what happened.
	Status Status
}

// Replacement pairs a staged file or directory with the one it replaces.
type Replacement struct {
	// Staged is the new file or directory. It must be in the same
	// directory as Target, so the swap is a rename; see [StagingPath].
	Staged string
	// Target is what to replace. It need not exist yet; if it does, it
	// must be of the same kind (regular file or directory) as Staged.
	// Resolve symlinks first if the link itself must be kept.
	Target string
}

// ReplaceOptions controls how a replacement is recorded.
type ReplaceOptions struct {
	// Version and Previous are recorded for [Outcome].
	Version, Previous string
	// Pending keeps the backups and leaves the update awaiting
	// [Journal.Commit]; otherwise the replacement is final at once.
	Pending bool
}

// Journal records an update in a small file so that it can be committed or
// rolled back, also by a later process after a crash or power loss. All
// files replaced in one update share one journal.
//
// Every move is made recoverable before it happens: the journal names each
// target's staged, backup and trash path up front and is written
// atomically, and recovery decides each target's state from which of those
// paths exist, so it can be repeated after any interruption. While a
// journal exists no other update can start.
//
// Operations on one journal are serialized across goroutines and processes
// by a lock held only while the operation runs: an operating system file
// lock (next to the journal, deleted when released) where the system has
// one, which the kernel drops when its process dies. On js/wasm, wasip1
// and plan9, which have none, the lock covers this process only. The
// context of each method bounds only the wait for that lock; a swap that
// has started is never abandoned half-way.
type Journal struct {
	// Path is the journal file.
	Path string
	// RenameRetry is how long a rename is retried while another process
	// holds the file open, which blocks renames on Windows (virus
	// scanners do this to new executables). Zero means 10 seconds.
	RenameRetry time.Duration
}

// JournalFor returns the journal kept next to the file target.
func JournalFor(target string) Journal {
	return Journal{Path: target + ".selfupdate.json"}
}

// ExecutableJournal returns the journal next to the running executable,
// with symlinks resolved. It is the journal of an [Updater] whose Journal
// is not set.
func ExecutableJournal() (Journal, error) {
	exe, err := executable("")
	if err != nil {
		return Journal{}, err
	}
	return JournalFor(exe), nil
}

// StagingPath returns a fresh path next to target for a staged copy.
func StagingPath(target string) string {
	return target + ".selfupdate-new-" + rand.Text()[:12]
}

const (
	phaseStaging   = "staging"
	phaseApplying  = "applying"
	phasePending   = "pending"
	phaseRestoring = "restoring"
	phaseCleanup   = "cleanup"
	backupSuffix   = ".selfupdate-old"
)

type journalFile struct {
	Target  string `json:"target"`
	Staged  string `json:"staged"`
	Backup  string `json:"backup"`
	Trash   string `json:"trash"`
	Existed bool   `json:"existed"`
}

type journalState struct {
	Phase    string        `json:"phase"`
	Version  string        `json:"version,omitempty"`
	Previous string        `json:"previous,omitempty"`
	Files    []journalFile `json:"files"`
	Boots    int           `json:"boots"`
}

// testHookStep, when set by a test, is called after every durable step.
// testHookRename, when set, is called before every rename of a file and
// may fail it.
var (
	testHookStep   func(step string)
	testHookRename func(from, to string) error
)

func step(name string) {
	if testHookStep != nil {
		testHookStep(name)
	}
}

// opLock serializes operations on the journal; stageLock is held by a
// [Staged] for its whole life, so that recovery can tell a live stager
// from a dead one.
func (j Journal) opLock() string    { return j.Path + ".lock" }
func (j Journal) stageLock() string { return j.Path + ".stage.lock" }

func (j Journal) withLock(ctx context.Context, fn func() error) error {
	l, err := lockFile(ctx, j.opLock())
	if err != nil {
		return err
	}
	defer l.unlock()
	step("locked")
	return fn()
}

// exists reports whether the journal file exists. Errors other than
// absence count as existence, so the caller goes on to report them.
func (j Journal) exists() bool {
	_, err := os.Lstat(j.Path)
	return !errors.Is(err, fs.ErrNotExist)
}

// sweepLocks deletes lock files left by a process that died holding them,
// if there are any. A lock somebody holds is left alone. The stage lock is
// swept under the journal lock, under which alone [Journal.Stage] takes
// it, so a sweep never makes Stage fail.
func (j Journal) sweepLocks() {
	if !lockFileExists(j.opLock()) && !lockFileExists(j.stageLock()) {
		return
	}
	l, err := tryLockFile(j.opLock())
	if err != nil {
		return // somebody is working on the journal and sweeps after
	}
	j.sweepStageLock()
	l.unlock()
}

// sweepStageLock deletes a stage lock file left by a dead stager. The
// caller holds the journal lock.
func (j Journal) sweepStageLock() {
	if !lockFileExists(j.stageLock()) {
		return
	}
	if l, err := tryLockFile(j.stageLock()); err == nil {
		l.unlock()
	}
}

func lockFileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// load reads the journal; ok is false when there is none.
func (j Journal) load() (st journalState, ok bool, err error) {
	data, err := os.ReadFile(j.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	if err := json.Unmarshal(data, &st); err != nil || st.Phase == "" {
		// The journal is only ever replaced by rename, so this is damage
		// from outside; refuse to guess.
		return st, false, fmt.Errorf("%w: %s", ErrCorruptJournal, j.Path)
	}
	return st, true, nil
}

// save replaces the journal atomically and durably.
func (j Journal) save(st *journalState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := j.Path + ".tmp"
	if err := writeSynced(tmp, data); err != nil {
		return err
	}
	if err := j.rename(tmp, j.Path); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(j.Path)); err != nil {
		return err
	}
	step("saved " + st.Phase)
	return nil
}

func (j Journal) remove() error {
	if err := errors.Join(removeIfExists(j.Path+".tmp"), removeIfExists(j.Path)); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(j.Path)); err != nil {
		return err
	}
	step("removed journal")
	return nil
}

func writeSynced(p string, data []byte) (err error) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// rename renames from to to, retrying for a while when the failure looks
// like another process holding the file open.
func (j Journal) rename(from, to string) error {
	retry := j.RenameRetry
	if retry <= 0 {
		retry = 10 * time.Second
	}
	deadline := time.Now().Add(retry)
	for {
		var err error
		if testHookRename != nil {
			err = testHookRename(from, to)
		}
		if err == nil {
			err = os.Rename(from, to)
		}
		if err == nil || !transientRename(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// transientRename reports whether a rename failed only for a moment and
// is worth retrying; see the platform's transientRenameErrors.
func transientRename(err error) bool {
	for _, t := range transientRenameErrors {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

// move renames from to to and makes the rename durable.
func (j Journal) move(from, to string) error {
	if err := j.rename(from, to); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(to)); err != nil {
		return err
	}
	step("moved " + filepath.Base(from))
	return nil
}

// Replace swaps every staged file or directory into place, keeping the
// replaced ones as backups. If any step fails, the ones already swapped
// are restored. With [ReplaceOptions.Pending] the update then awaits
// [Journal.Commit]; otherwise the backups are removed at once.
//
// The staged files are recorded only from this call on; to have staged
// files cleaned up after a crash before the swap, use [Journal.Stage].
// The new files take the permission bits (setuid, setgid and sticky bits
// are dropped) and, where the process may set them, the owner and group
// of the files they replace; for a directory this applies to the
// directory itself.
func (j Journal) Replace(ctx context.Context, set []Replacement, opts ReplaceOptions) error {
	if len(set) == 0 {
		return errors.New("selfupdate: nothing to replace")
	}
	return j.withLock(ctx, func() error {
		if err := j.idle(); err != nil {
			return err
		}
		files := make([]journalFile, 0, len(set))
		for _, r := range set {
			f, err := newJournalFile(r.Target, r.Staged)
			if err != nil {
				return err
			}
			files = append(files, f)
		}
		return j.apply(&journalState{Files: files}, opts)
	})
}

// Staged is an update whose paths are recorded before the new files are
// written, so that a crash while preparing them leaves nothing behind:
// the next [Journal.Recover] deletes them. A Staged holds a lock until
// [Staged.Replace] succeeds or [Staged.Abort] is called, and recovery
// treats the update as in progress meanwhile, so always end it; deferring
// Abort is the simplest way. Its methods may be called from any
// goroutine.
type Staged struct {
	lock     *fileLock // nil once ended
	j        Journal
	files    []journalFile
	mu       sync.Mutex
	replaced bool
}

// Stage records an update of targets (files or directories) and returns
// the paths to write the new ones to, in the order of targets. The paths
// do not exist yet. Call [Staged.Replace] when they are written, or
// [Staged.Abort].
func (j Journal) Stage(ctx context.Context, targets ...string) (*Staged, error) {
	if len(targets) == 0 {
		return nil, errors.New("selfupdate: nothing to stage")
	}
	var s *Staged
	err := j.withLock(ctx, func() error {
		if err := j.idle(); err != nil {
			return err
		}
		files := make([]journalFile, 0, len(targets))
		for _, t := range targets {
			f, err := planFile(t, "")
			if err != nil {
				return err
			}
			if slices.ContainsFunc(files, func(o journalFile) bool { return o.Target == f.Target }) {
				return fmt.Errorf("selfupdate: %s replaced twice", f.Target)
			}
			files = append(files, f)
		}
		// Stage locks are taken, and swept, only under the journal lock,
		// so with no staging recorded nobody alive holds it.
		sl, err := tryLockFile(j.stageLock())
		if errors.Is(err, errLocked) {
			return ErrBusy
		}
		if err != nil {
			return err
		}
		if err := j.save(&journalState{Phase: phaseStaging, Files: files}); err != nil {
			sl.unlock()
			return err
		}
		s = &Staged{lock: sl, j: j, files: files}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Paths returns the staging paths, in the order of the targets.
func (s *Staged) Paths() []string {
	out := make([]string, len(s.files))
	for i, f := range s.files {
		out[i] = f.Staged
	}
	return out
}

// Replace swaps the staged files into place like [Journal.Replace]. If it
// fails before anything was swapped, the update stays staged and Abort
// deletes it; once swapping started, a failure restores the old files and
// ends the update.
func (s *Staged) Replace(ctx context.Context, opts ReplaceOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return ErrStageEnded
	}
	return s.j.withLock(ctx, func() error {
		if err := s.owned(); err != nil {
			s.end()
			return err
		}
		files := make([]journalFile, len(s.files))
		for i, f := range s.files {
			nf, err := newJournalFile(f.Target, f.Staged)
			if err != nil {
				return err
			}
			nf.Trash = f.Trash
			files[i] = nf
		}
		err := s.j.apply(&journalState{Files: files}, opts)
		if err == nil {
			s.replaced = true
			s.end()
			return nil
		}
		if s.owned() != nil {
			s.end() // the swap started and was undone, or awaits recovery
		}
		return err
	})
}

// Abort deletes the staged files and ends the update. After a successful
// [Staged.Replace] it does nothing, so it can be deferred right after
// [Journal.Stage].
//
// ctx bounds the wait for another operation on the journal. If it ends
// first, the update still ends but stays recorded, and the next
// [Journal.Recover] or [Journal.Startup] deletes the staged files.
func (s *Staged) Abort(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	defer s.end() // also when the wait fails: recovery then sees a dead stager
	return s.j.withLock(ctx, func() error {
		defer s.end()
		if s.owned() != nil {
			// The journal was removed from outside: delete what is ours.
			return removeStaged(s.files)
		}
		return s.j.dropStaging(s.files)
	})
}

// end releases the stage lock, normally under the journal lock.
func (s *Staged) end() {
	if s.lock != nil {
		s.lock.unlock()
		s.lock = nil
	}
}

// owned checks that the journal still records this staging.
func (s *Staged) owned() error {
	st, ok, err := s.j.load()
	if err != nil {
		return err
	}
	same := func(a, b journalFile) bool { return a.Target == b.Target && a.Staged == b.Staged }
	if !ok || st.Phase != phaseStaging || !slices.EqualFunc(st.Files, s.files, same) {
		return ErrStageEnded
	}
	return nil
}

func removeStaged(files []journalFile) error {
	for _, f := range files {
		if err := os.RemoveAll(f.Staged); err != nil {
			return err
		}
	}
	return nil
}

func (j Journal) dropStaging(files []journalFile) error {
	if err := removeStaged(files); err != nil {
		return err
	}
	return j.remove()
}

// idle returns nil when no update is in flight, finishing a cleanup left
// by an earlier one if needed. The caller holds the lock.
func (j Journal) idle() error {
	st, ok, err := j.load()
	if err != nil || !ok {
		return err
	}
	if st.Phase != phaseCleanup {
		return ErrBusy
	}
	if err := j.cleanup(&st); err != nil {
		return err
	}
	if _, ok, err := j.load(); err != nil || ok {
		return errors.Join(err, ErrBusy)
	}
	return nil
}

// planFile fills in the paths of a target in an update.
func planFile(target, staged string) (journalFile, error) {
	target, err := filepath.Abs(target)
	if err != nil {
		return journalFile{}, err
	}
	if staged == "" {
		staged = StagingPath(target)
	}
	if staged, err = filepath.Abs(staged); err != nil {
		return journalFile{}, err
	}
	if filepath.Dir(staged) != filepath.Dir(target) {
		return journalFile{}, fmt.Errorf("selfupdate: %s is not staged next to %s", staged, target)
	}
	return journalFile{
		Target: target,
		Staged: staged,
		Backup: target + backupSuffix,
		Trash:  target + ".selfupdate-trash-" + rand.Text()[:12],
	}, nil
}

// newJournalFile plans a replacement and checks its files. It changes
// nothing but the staged file's permissions and owner.
func newJournalFile(target, staged string) (journalFile, error) {
	f, err := planFile(target, staged)
	if err != nil {
		return journalFile{}, err
	}
	return f, prepare(&f)
}

func prepare(f *journalFile) error {
	sfi, err := os.Lstat(f.Staged)
	if err != nil {
		return err
	}
	if !sfi.Mode().IsRegular() && !sfi.IsDir() {
		return fmt.Errorf("selfupdate: staged %s is neither a regular file nor a directory", f.Staged)
	}
	fi, err := os.Lstat(f.Target)
	switch {
	case err == nil:
		if fi.Mode().Type() != sfi.Mode().Type() {
			return fmt.Errorf("selfupdate: %s and %s are not of the same kind", f.Target, f.Staged)
		}
		f.Existed = true
		if err := os.Chmod(f.Staged, fi.Mode().Perm()); err != nil {
			return err
		}
		return copyOwner(f.Staged, fi)
	case errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return err
}

// apply records st as applying and swaps its files. The caller holds the
// lock and has checked that no update is in flight.
func (j Journal) apply(st *journalState, opts ReplaceOptions) error {
	for i, f := range st.Files {
		if slices.ContainsFunc(st.Files[:i], func(o journalFile) bool { return o.Target == f.Target }) {
			return fmt.Errorf("selfupdate: %s replaced twice", f.Target)
		}
		// A backup with no journal is stale: an earlier cleanup could not
		// delete it. Nobody else can own it while the lock is held.
		if err := os.RemoveAll(f.Backup); err != nil {
			return fmt.Errorf("selfupdate: stale backup: %w", err)
		}
	}
	st.Phase, st.Version, st.Previous = phaseApplying, opts.Version, opts.Previous
	if err := j.save(st); err != nil {
		return err
	}
	for _, f := range st.Files {
		if err := j.swap(f); err != nil {
			return errors.Join(err, j.restore(st))
		}
	}
	if opts.Pending {
		st.Phase = phasePending
		return j.save(st)
	}
	return j.cleanup(st)
}

// swap moves the target to its backup and the staged file to the target.
// A running executable may be renamed on every supported system.
func (j Journal) swap(f journalFile) error {
	if f.Existed {
		if err := j.move(f.Target, f.Backup); err != nil {
			return err
		}
	}
	return j.move(f.Staged, f.Target)
}

func exists(p string) (bool, error) {
	_, err := os.Lstat(p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// restore undoes the swaps recorded in st, in reverse order, and ends the
// journal. It may be repeated any number of times after an interruption.
func (j Journal) restore(st *journalState) error {
	if st.Phase != phaseRestoring {
		st.Phase = phaseRestoring
		if err := j.save(st); err != nil {
			return err
		}
	}
	for i := len(st.Files) - 1; i >= 0; i-- {
		if err := j.restoreFile(st.Files[i]); err != nil {
			return err // the journal stays in restoring; retry later
		}
	}
	return j.cleanup(st)
}

// restoreFile brings one target back to its state before the update.
// Which of the recorded paths exist tells how far the swap and any earlier
// restore got, so it can be repeated after an interruption:
//
//   - a target that existed is moved away exactly while its backup
//     exists; the new one at the target, if any, first goes to the trash
//     path;
//   - without a backup it was never moved (the staged one is still there)
//     or is restored already (the new one is in the trash); anything else
//     means the backup was lost, and nothing is touched;
//   - a target that did not exist was swapped in exactly when the staged
//     path is gone and the target exists.
func (j Journal) restoreFile(f journalFile) error {
	var have [4]bool
	for i, p := range []string{f.Backup, f.Target, f.Staged, f.Trash} {
		ok, err := exists(p)
		if err != nil {
			return err
		}
		have[i] = ok
	}
	backup, target, staged, trash := have[0], have[1], have[2], have[3]
	switch {
	case f.Existed && backup:
		if target {
			if staged || trash {
				return fmt.Errorf("selfupdate: cannot tell old from new at %s", f.Target)
			}
			if err := j.move(f.Target, f.Trash); err != nil {
				return err
			}
		}
		if err := j.move(f.Backup, f.Target); err != nil {
			return err
		}
	case f.Existed && !staged && !trash:
		return fmt.Errorf("selfupdate: backup %s is missing", f.Backup)
	case !f.Existed && !staged && target:
		return j.move(f.Target, f.Trash)
	}
	// The staged copy of a target that was never swapped stays until
	// cleanup: its presence is what tells a later retry so.
	return nil
}

// cleanup marks the update as finished and deletes what it left: backups
// (after a commit), trash and staged files. What cannot be deleted yet,
// such as a running executable on Windows, stays listed and is deleted by
// a later call.
func (j Journal) cleanup(st *journalState) error {
	if st.Phase != phaseCleanup {
		st.Phase = phaseCleanup
		if err := j.save(st); err != nil {
			return err
		}
	}
	left := false
	for _, f := range st.Files {
		for _, p := range []string{f.Backup, f.Trash, f.Staged} {
			if p == "" {
				continue
			}
			if os.RemoveAll(p) != nil {
				left = true
			} else {
				step("removed " + filepath.Base(p))
			}
		}
	}
	if left {
		return nil
	}
	return j.remove()
}

// Peek reports the state of the journal without changing it or taking
// its lock: [StatusIdle], [StatusCleanup], [StatusPending] or
// [StatusInProgress]. It suits status displays and checks before starting
// expensive work.
func (j Journal) Peek() (Outcome, error) {
	st, ok, err := j.load()
	if err != nil || !ok {
		return Outcome{Status: StatusIdle}, err
	}
	out := Outcome{Version: st.Version, Previous: st.Previous, Boots: st.Boots}
	switch st.Phase {
	case phaseCleanup:
		return Outcome{Status: StatusCleanup}, nil
	case phasePending:
		out.Status = StatusPending
	case phaseStaging, phaseApplying, phaseRestoring:
		out.Status = StatusInProgress
	default:
		return Outcome{Status: StatusIdle}, fmt.Errorf("%w: %s: unknown phase %q", ErrCorruptJournal, j.Path, st.Phase)
	}
	return out, nil
}

// Recover finishes or undoes whatever an earlier update left, without
// counting a start of a pending update:
//
//   - an update interrupted while files were being swapped or restored is
//     undone (StatusRolledBack);
//   - files staged by a process that died before swapping them are deleted;
//   - leftovers from finished updates are deleted;
//   - a pending update is reported (StatusPending) and left alone.
//
// It returns [ErrBusy] while a live [Staged] (in this or another process)
// holds the journal. With no journal it only looks for it and for lock
// files left by a dead process, which it tries to delete; it needs no
// write access then, so it is cheap on every start.
func (j Journal) Recover(ctx context.Context) (Outcome, error) {
	return j.recover(ctx, 0)
}

// Startup is [Journal.Recover] for a real start of the program, the kind
// that may confirm an update: it also counts the start of a pending
// update, and rolls the update back once maxBoots counted starts passed
// without [Journal.Commit] (zero means one: the first counted start must
// commit). Use Recover instead for runs that do not exercise the program,
// such as printing its version, so they do not use up the allowance.
func (j Journal) Startup(ctx context.Context, maxBoots int) (Outcome, error) {
	return j.recover(ctx, max(maxBoots, 1))
}

func (j Journal) recover(ctx context.Context, maxBoots int) (Outcome, error) {
	if !j.exists() {
		j.sweepLocks()
		return Outcome{Status: StatusIdle}, nil
	}
	var out Outcome
	err := j.withLock(ctx, func() error {
		defer j.sweepStageLock() // a stage lock file left by a dead stager
		st, ok, err := j.load()
		if err != nil || !ok {
			return err
		}
		out = Outcome{Version: st.Version, Previous: st.Previous, Boots: st.Boots}
		switch st.Phase {
		case phaseCleanup:
			out = Outcome{}
			return j.cleanup(&st)
		case phaseStaging:
			sl, err := tryLockFile(j.stageLock())
			if errors.Is(err, errLocked) {
				return ErrBusy
			}
			if err != nil {
				return err
			}
			defer sl.unlock()
			out = Outcome{}
			return j.dropStaging(st.Files)
		case phasePending:
			if maxBoots == 0 {
				out.Status = StatusPending
				return nil
			}
			if st.Boots < maxBoots {
				st.Boots++
				out.Boots, out.Status = st.Boots, StatusPending
				return j.save(&st)
			}
		case phaseApplying, phaseRestoring:
		default:
			return fmt.Errorf("%w: %s: unknown phase %q", ErrCorruptJournal, j.Path, st.Phase)
		}
		if err := j.restore(&st); err != nil {
			return err
		}
		out.Status = StatusRolledBack
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			// Leftovers of a finished update that this process may not
			// delete are left to a process that may.
			if peek, perr := j.Peek(); perr == nil && (peek.Status == StatusIdle || peek.Status == StatusCleanup) {
				return Outcome{Status: StatusIdle}, nil
			}
		}
		return Outcome{Status: StatusIdle}, err
	}
	return out, nil
}

// Commit confirms a pending update: the backups are deleted and the
// update can no longer be rolled back.
func (j Journal) Commit(ctx context.Context) error {
	if !j.exists() {
		return ErrNotPending
	}
	return j.withLock(ctx, func() error {
		st, ok, err := j.load()
		if err != nil {
			return err
		}
		if !ok || st.Phase != phasePending {
			return ErrNotPending
		}
		return j.cleanup(&st)
	})
}

// Rollback undoes a pending or interrupted update now, restoring the
// replaced files. The running process still runs the code it started
// with; restart it.
func (j Journal) Rollback(ctx context.Context) error {
	if !j.exists() {
		return ErrNotPending
	}
	return j.withLock(ctx, func() error {
		st, ok, err := j.load()
		if err != nil {
			return err
		}
		if !ok || (st.Phase != phasePending && st.Phase != phaseApplying && st.Phase != phaseRestoring) {
			return ErrNotPending
		}
		return j.restore(&st)
	})
}

func removeIfExists(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// CheckWritable reports whether files can be created and renamed in dir,
// as replacing a file there requires.
func CheckWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".selfupdate-probe-*")
	if err != nil {
		return fmt.Errorf("selfupdate: directory %s is not writable: %w", dir, err)
	}
	name := f.Name()
	err = f.Close()
	moved := name + ".renamed"
	if rerr := os.Rename(name, moved); rerr != nil {
		_ = os.Remove(name)
		return fmt.Errorf("selfupdate: cannot rename in %s: %w", dir, rerr)
	}
	return errors.Join(err, os.Remove(moved))
}
