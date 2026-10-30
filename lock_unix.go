//go:build unix && !solaris && !aix && !selfupdate_fcntl

package selfupdate

import (
	"errors"
	"os"
	"syscall"
)

func openLockFile(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
}

// tryLockSystem takes an flock lock, which belongs to the open file, so
// that two opens in one process exclude each other too.
func tryLockSystem(f *os.File) (bool, error) {
	return flockControl(f, syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockSystem(f *os.File) { _, _ = flockControl(f, syscall.LOCK_UN) }

func flockControl(f *os.File, how int) (bool, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) {
		for {
			ferr = syscall.Flock(int(fd), how)
			if !errors.Is(ferr, syscall.EINTR) {
				return
			}
		}
	}); err != nil {
		return false, err
	}
	if errors.Is(ferr, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return ferr == nil, ferr
}

// removeLocked deletes the lock file while it is still locked.
func removeLocked(_ *os.File, p string) { _ = os.Remove(p) }

// closeLockFile closes a lock file.
func closeLockFile(f *os.File) { closeQuietly(f) }
