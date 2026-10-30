package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// errLocked reports that a lock taken without waiting is held elsewhere.
var errLocked = errors.New("selfupdate: lock is held")

// fileLock is a mutex shared by the goroutines of this process and, where
// the system has file locks, by all processes: flock or fcntl on Unix
// systems and LockFileEx on Windows. The kernel drops the lock of a
// process that dies, so no lock is ever stale. Within a process, locks
// exclude each other by lock path and, through the system lock, by the
// file itself, whatever path led to it.
//
// The lock file exists only while somebody uses it: its holder deletes it
// before unlocking, and whoever locks a file that is no longer the one at
// the path (it was deleted meanwhile) tries again.
type fileLock struct {
	local *localLock
	f     *os.File // nil where the system has no file locks
	path  string
}

// lockFile takes the lock at path, waiting until ctx ends.
func lockFile(ctx context.Context, path string) (*fileLock, error) {
	return takeLock(ctx, path, true)
}

// tryLockFile takes the lock at path or fails at once with errLocked.
func tryLockFile(path string) (*fileLock, error) {
	return takeLock(context.Background(), path, false)
}

func takeLock(ctx context.Context, path string, wait bool) (*fileLock, error) {
	local, err := acquireLocal(ctx, lockKey(path), wait)
	if err != nil {
		return nil, err
	}
	f, err := acquireSystem(ctx, path, wait)
	if err != nil {
		local.release()
		return nil, err
	}
	return &fileLock{local: local, f: f, path: path}, nil
}

// unlock deletes the lock file and releases the lock. A lock file that
// cannot be deleted does no harm: the next holder reuses it.
func (l *fileLock) unlock() {
	if l.f != nil {
		removeLocked(l.f, l.path)
		unlockSystem(l.f)
		closeLockFile(l.f)
	}
	l.local.release()
}

// acquireSystem takes the system lock on the file at path, polling while
// another process holds it.
func acquireSystem(ctx context.Context, path string, wait bool) (*os.File, error) {
	delay := time.Millisecond
	for {
		f, err := openLockFile(path)
		if err != nil {
			return nil, fmt.Errorf("selfupdate: lock: %w", err)
		}
		if f == nil {
			return nil, nil // no file locks here
		}
		ok, err := tryLockSystem(f)
		switch {
		case err != nil:
			closeLockFile(f)
			return nil, fmt.Errorf("selfupdate: lock %s: %w", path, err)
		case ok && isCurrent(f, path):
			return f, nil
		case ok:
			// Locked a file its holder deleted before unlocking: try the
			// one at the path now.
			unlockSystem(f)
			closeLockFile(f)
			continue
		}
		closeLockFile(f)
		if !wait {
			return nil, errLocked
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
		delay = min(2*delay, 50*time.Millisecond)
	}
}

// isCurrent reports whether f is still the file at path.
func isCurrent(f *os.File, path string) bool {
	a, err := f.Stat()
	if err != nil {
		return false
	}
	b, err := os.Stat(path)
	return err == nil && os.SameFile(a, b)
}

// lockKey names the lock of path within this process.
func lockKey(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return filepath.Join(dir, filepath.Base(abs))
	}
	return abs
}

// localLock serializes the goroutines of this process on one lock path.
// Entries live only while somebody holds or waits for them.
type localLock struct {
	ch   chan struct{}
	key  string
	refs int
}

var localLocks = struct {
	m map[string]*localLock
	sync.Mutex
}{m: map[string]*localLock{}}

func acquireLocal(ctx context.Context, key string, wait bool) (*localLock, error) {
	localLocks.Lock()
	l := localLocks.m[key]
	if l == nil {
		l = &localLock{ch: make(chan struct{}, 1), key: key}
		localLocks.m[key] = l
	}
	l.refs++
	localLocks.Unlock()
	if !wait {
		select {
		case l.ch <- struct{}{}:
			return l, nil
		default:
			l.drop()
			return nil, errLocked
		}
	}
	if err := ctx.Err(); err != nil {
		l.drop()
		return nil, err
	}
	select {
	case l.ch <- struct{}{}:
		return l, nil
	case <-ctx.Done():
		l.drop()
		return nil, ctx.Err()
	}
}

func (l *localLock) release() {
	<-l.ch
	l.drop()
}

func (l *localLock) drop() {
	localLocks.Lock()
	defer localLocks.Unlock()
	if l.refs--; l.refs == 0 {
		delete(localLocks.m, l.key)
	}
}
