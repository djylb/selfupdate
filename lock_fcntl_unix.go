//go:build solaris || aix || selfupdate_fcntl

package selfupdate

import (
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
)

func openLockFile(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
}

// fcntl locks belong to the process, not to the open file: a second open
// of the same file in this process would get the lock too, and closing
// any descriptor of the file drops it. fcntlFiles therefore tracks, by
// file identity (whatever path led to the file), which files this process
// holds locked; other descriptors of a held file are closed only once it
// is unlocked.
var fcntlFiles = struct {
	sync.Mutex
	m map[fileID]*fcntlEntry
}{m: map[fileID]*fcntlEntry{}}

type fileID struct{ dev, ino uint64 }

type fcntlEntry struct {
	holder *os.File
	strays []*os.File
}

func identity(f *os.File) (fileID, error) {
	fi, err := f.Stat()
	if err != nil {
		return fileID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, errors.New("selfupdate: no file identity")
	}
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, nil // the field types differ per system
}

func tryLockSystem(f *os.File) (bool, error) {
	id, err := identity(f)
	if err != nil {
		return false, err
	}
	fcntlFiles.Lock()
	defer fcntlFiles.Unlock()
	if fcntlFiles.m[id] != nil {
		return false, nil // held in this process through another descriptor
	}
	err = fcntlLock(f, syscall.F_WRLCK)
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	fcntlFiles.m[id] = &fcntlEntry{holder: f}
	return true, nil
}

func unlockSystem(f *os.File) {
	fcntlFiles.Lock()
	defer fcntlFiles.Unlock()
	_ = fcntlLock(f, syscall.F_UNLCK)
	for id, e := range fcntlFiles.m {
		if e.holder == f {
			for _, s := range e.strays {
				closeQuietly(s)
			}
			delete(fcntlFiles.m, id)
			return
		}
	}
}

// closeLockFile closes f, unless another descriptor of the same file
// holds the lock: then closing f would drop that lock, so f is closed
// when it is unlocked.
func closeLockFile(f *os.File) {
	fcntlFiles.Lock()
	defer fcntlFiles.Unlock()
	if id, err := identity(f); err == nil {
		if e := fcntlFiles.m[id]; e != nil && e.holder != f {
			e.strays = append(e.strays, f)
			return
		}
	}
	closeQuietly(f)
}

func fcntlLock(f *os.File, typ int16) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) {
		lk := syscall.Flock_t{Type: typ, Whence: io.SeekStart}
		for {
			ferr = syscall.FcntlFlock(fd, syscall.F_SETLK, &lk)
			if !errors.Is(ferr, syscall.EINTR) {
				return
			}
		}
	}); err != nil {
		return err
	}
	return ferr
}

// removeLocked deletes the lock file while it is still locked.
func removeLocked(_ *os.File, p string) { _ = os.Remove(p) }
