package selfupdate

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// Errors returned by [Journal] operations.
var (
	ErrBusy           = errors.New("selfupdate: another update is in progress or awaits confirmation")
	ErrNotPending     = errors.New("selfupdate: no update awaits confirmation")
	ErrCorruptJournal = errors.New("selfupdate: corrupt journal")
)

// Status is what [Journal.Recover] and [Journal.Startup] found.
type Status int

// The startup outcomes.
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
)

// String returns "idle", "pending" or "rolled back".
func (s Status) String() string {
	switch s {
	case StatusIdle:
		return "idle"
	case StatusPending:
		return "pending"
	case StatusRolledBack:
		return "rolled back"
	}
	return fmt.Sprintf("Status(%d)", int(s))
}

// Outcome is the result of [Journal.Recover] and [Journal.Startup].
type Outcome struct {
	// Version is the version that was installed by the update, as passed
	// in [ReplaceOptions].
	Version string
	// Previous is the version that was replaced.
	Previous string
	// Boots counts the starts of a pending update so far.
	Boots int
	// Status says what happened.
	Status Status
}

// Replacement pairs a staged file with the file it replaces.
type Replacement struct {
	// Staged is the new file. It must be in the same directory as Target,
	// so the swap is a rename; see [StagingPath].
	Staged string
	// Target is the file to replace. It need not exist yet. Resolve
	// symlinks first if the link itself must be kept.
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
// files replaced in one update share one journal; the [Updater] keeps it
// next to the executable (see [JournalFor]).
//
// Every file move is made recoverable before it happens: the journal names
// each file's staged, backup and trash path up front and is written
// atomically, and recovery decides each file's state from which of those
// paths exist, so it can be repeated after any interruption. While a
// journal exists no other update can start. Operations on one journal are
// serialized across processes by a lock file next to it; a lock left by a
// dead process is broken automatically.
type Journal struct {
	// Path is the journal file.
	Path string
}

// JournalFor returns the journal kept next to the file target.
func JournalFor(target string) Journal {
	return Journal{Path: target + ".selfupdate.json"}
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
	Owner    owner         `json:"owner"`
	Phase    string        `json:"phase"`
	Version  string        `json:"version,omitempty"`
	Previous string        `json:"previous,omitempty"`
	Files    []journalFile `json:"files"`
	Boots    int           `json:"boots"`
}

// testHookStep, when set by a test, is called after every durable step.
var testHookStep func(step string)

func step(name string) {
	if testHookStep != nil {
		testHookStep(name)
	}
}

func (j Journal) withLock(fn func() error) error {
	l, err := acquireLock(j.Path + ".lock")
	if err != nil {
		return err
	}
	step("locked")
	return errors.Join(fn(), l.release())
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
	if err := writeSynced(tmp, data, os.O_TRUNC); err != nil {
		return err
	}
	if err := renameFile(tmp, j.Path); err != nil {
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

func writeSynced(p string, data []byte, flag int) (err error) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|flag, 0o600)
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

// move renames from to to and makes the rename durable.
func move(from, to string) error {
	if err := renameFile(from, to); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(to)); err != nil {
		return err
	}
	step("moved " + filepath.Base(from))
	return nil
}

// Replace swaps every staged file into place, keeping the replaced files
// as backups. If any step fails, the files already swapped are restored.
// With [ReplaceOptions.Pending] the update then awaits [Journal.Commit];
// otherwise the backups are removed at once.
//
// The staged files are recorded only from this call on; to have staged
// files cleaned up after a crash before the swap, use [Journal.Stage].
// The new files take the permission bits (setuid, setgid and sticky bits
// are dropped) and, where the process may set them, the owner and group
// of the files they replace.
func (j Journal) Replace(set []Replacement, opts ReplaceOptions) error {
	if len(set) == 0 {
		return errors.New("selfupdate: nothing to replace")
	}
	return j.withLock(func() error {
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

// Staged is an update whose file paths are recorded before the files are
// written, so that a crash while preparing them leaves nothing behind:
// the next [Journal.Recover] deletes them.
type Staged struct {
	j     Journal
	files []journalFile
	me    owner
}

// Stage records an update of targets and returns the paths to write the
// new files to, in the order of targets. The paths do not exist yet. Call
// [Staged.Replace] when they are written, or [Staged.Abort].
func (j Journal) Stage(targets ...string) (*Staged, error) {
	if len(targets) == 0 {
		return nil, errors.New("selfupdate: nothing to stage")
	}
	s := &Staged{j: j, me: newOwner()}
	err := j.withLock(func() error {
		if err := j.idle(); err != nil {
			return err
		}
		for _, t := range targets {
			f, err := planFile(t, "")
			if err != nil {
				return err
			}
			if slices.ContainsFunc(s.files, func(o journalFile) bool { return o.Target == f.Target }) {
				return fmt.Errorf("selfupdate: %s replaced twice", f.Target)
			}
			s.files = append(s.files, f)
		}
		return j.save(&journalState{Owner: s.me, Phase: phaseStaging, Files: s.files})
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

// Replace swaps the staged files into place like [Journal.Replace].
func (s *Staged) Replace(opts ReplaceOptions) error {
	return s.j.withLock(func() error {
		if err := s.owned(); err != nil {
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
		return s.j.apply(&journalState{Files: files}, opts)
	})
}

// Abort deletes the staged files and ends the update. After a failed
// [Staged.Replace], which has already restored and ended it, Abort only
// makes sure no staged file is left.
func (s *Staged) Abort() error {
	return s.j.withLock(func() error {
		st, ok, err := s.j.load()
		switch {
		case err != nil:
			return err
		case ok && st.Phase == phaseStaging && st.Owner == s.me:
			return s.j.dropStaging(s.files)
		case ok && st.Owner == s.me:
			return errors.New("selfupdate: staged update already replaced")
		}
		for _, f := range s.files {
			if err := removeIfExists(f.Staged); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Staged) owned() error {
	st, ok, err := s.j.load()
	if err != nil {
		return err
	}
	if !ok || st.Phase != phaseStaging || st.Owner != s.me {
		return errors.New("selfupdate: staged update was taken over or ended")
	}
	return nil
}

func (j Journal) dropStaging(files []journalFile) error {
	for _, f := range files {
		if err := removeIfExists(f.Staged); err != nil {
			return err
		}
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

// planFile fills in the paths of a file in an update.
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
	if !sfi.Mode().IsRegular() {
		return fmt.Errorf("selfupdate: staged %s is not a regular file", f.Staged)
	}
	fi, err := os.Lstat(f.Target)
	switch {
	case err == nil:
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("selfupdate: %s is not a regular file", f.Target)
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
		if err := removeIfExists(f.Backup); err != nil {
			return fmt.Errorf("selfupdate: stale backup: %w", err)
		}
	}
	st.Phase, st.Version, st.Previous, st.Owner = phaseApplying, opts.Version, opts.Previous, owner{}
	if err := j.save(st); err != nil {
		return err
	}
	for _, f := range st.Files {
		if err := swap(f); err != nil {
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
func swap(f journalFile) error {
	if f.Existed {
		if err := move(f.Target, f.Backup); err != nil {
			return err
		}
	}
	return move(f.Staged, f.Target)
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
		if err := restoreFile(st.Files[i]); err != nil {
			return err // the journal stays in restoring; retry later
		}
	}
	return j.cleanup(st)
}

// restoreFile brings one file back to its state before the update. Which
// of the recorded paths exist tells how far the swap and any earlier
// restore got, so it can be repeated after an interruption:
//
//   - a file that existed is moved away exactly while its backup exists;
//     the new file at the target, if any, first goes to the trash path;
//   - without a backup it was never moved (the staged file is still
//     there) or is restored already (the new file is in the trash);
//     anything else means the backup was lost, and nothing is touched;
//   - a file that did not exist was swapped in exactly when the staged
//     file is gone and the target exists.
func restoreFile(f journalFile) error {
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
			if err := move(f.Target, f.Trash); err != nil {
				return err
			}
		}
		if err := move(f.Backup, f.Target); err != nil {
			return err
		}
	case f.Existed && !staged && !trash:
		return fmt.Errorf("selfupdate: backup %s is missing", f.Backup)
	case !f.Existed && !staged && target:
		if err := move(f.Target, f.Trash); err != nil {
			return err
		}
	}
	return removeIfExists(f.Staged)
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
			if removeIfExists(p) != nil {
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

// Recover finishes or undoes whatever an earlier update left, without
// counting a start of a pending update:
//
//   - an update interrupted while files were being swapped or restored is
//     undone (StatusRolledBack);
//   - files staged by a process that died before swapping them are deleted;
//   - leftovers from finished updates are deleted;
//   - a pending update is reported (StatusPending) and left alone.
//
// It returns [ErrBusy] while another live process stages an update.
func (j Journal) Recover() (Outcome, error) {
	return j.recover(0)
}

// Startup is [Journal.Recover] for a real start of the program, the kind
// that may confirm an update: it also counts the start of a pending
// update, and rolls the update back once maxBoots counted starts passed
// without [Journal.Commit] (zero means one: the first counted start must
// commit). Use Recover instead for runs that do not exercise the program,
// such as printing its version, so they do not use up the allowance.
func (j Journal) Startup(maxBoots int) (Outcome, error) {
	return j.recover(max(maxBoots, 1))
}

func (j Journal) recover(maxBoots int) (out Outcome, err error) {
	err = j.withLock(func() error {
		st, ok, err := j.load()
		if err != nil || !ok {
			return err
		}
		out = Outcome{Version: st.Version, Previous: st.Previous, Boots: st.Boots}
		switch st.Phase {
		case phaseCleanup:
			return j.cleanup(&st)
		case phaseStaging:
			if st.Owner.alive() {
				return ErrBusy
			}
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
		return Outcome{Status: StatusIdle}, err
	}
	return out, nil
}

// Commit confirms a pending update: the backups are deleted and the
// update can no longer be rolled back.
func (j Journal) Commit() error {
	return j.withLock(func() error {
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
func (j Journal) Rollback() error {
	return j.withLock(func() error {
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
