package selfupdate

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// owner identifies the process (and the call within it) holding a lock or
// a staged update.
type owner struct {
	Token string `json:"token"`
	PID   int    `json:"pid"`
}

func newOwner() owner { return owner{Token: rand.Text(), PID: os.Getpid()} }

// alive reports whether the owner may still be working. A process that
// cannot be inspected counts as alive, so the lock fails closed.
func (o owner) alive() bool { return o.PID == os.Getpid() || processAlive(o.PID) }

// fileLock is a short-lived cross-process mutex: a file created
// atomically with its owner inside. A lock whose owner process has died is
// broken by the next caller.
type fileLock struct {
	path string
	me   owner
}

// unownedGrace is how long a lock file without readable owner (possible
// only where hard links are unsupported and the creator crashed between
// creating and writing it) is respected.
const unownedGrace = time.Minute

func acquireLock(p string) (*fileLock, error) {
	me := newOwner()
	data, err := json.Marshal(me)
	if err != nil {
		return nil, err
	}
	for attempt := range 2 {
		err := createExclusive(p, data)
		if err == nil {
			return &fileLock{path: p, me: me}, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if attempt == 1 || !breakStaleLock(p) {
			break
		}
	}
	return nil, ErrBusy
}

// createExclusive creates p holding data, failing with fs.ErrExist if p
// exists. The content is complete before p appears where hard links work.
func createExclusive(p string, data []byte) error {
	tmp := p + ".tmp-" + rand.Text()[:12]
	if err := writeSynced(tmp, data, os.O_EXCL); err != nil {
		return err
	}
	err := os.Link(tmp, p)
	_ = os.Remove(tmp)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		// No hard links on this file system: create in place.
		err = writeSynced(p, data, os.O_EXCL)
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(p))
}

func readOwner(p string) (owner, fs.FileInfo, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return owner{}, nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return owner{}, fi, err
	}
	var o owner
	if json.Unmarshal(data, &o) != nil || o.Token == "" {
		return owner{}, fi, nil
	}
	return o, fi, nil
}

// breakStaleLock removes the lock at p if its owner is gone and reports
// whether it did.
func breakStaleLock(p string) bool {
	o, fi, err := readOwner(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true // released meanwhile
	case err != nil:
		return false
	case o.Token == "" && time.Since(fi.ModTime()) < unownedGrace:
		return false
	case o.Token != "" && o.alive():
		return false
	}
	// Move it aside first, then check that what was moved is the stale
	// lock and not one taken meanwhile by somebody else.
	aside := p + ".stale-" + rand.Text()[:12]
	if os.Rename(p, aside) != nil {
		return false
	}
	moved, _, err := readOwner(aside)
	if err != nil || moved != o {
		_ = os.Link(aside, p) // put the fresh lock back
		_ = os.Remove(aside)
		return false
	}
	return os.Remove(aside) == nil
}

func (l *fileLock) release() error {
	o, _, err := readOwner(l.path)
	if err != nil {
		return err
	}
	if o != l.me {
		return errors.New("selfupdate: lock was broken by another process")
	}
	return removeIfExists(l.path)
}
