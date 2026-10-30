//go:build windows

package selfupdate

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"
)

const (
	errorSharingViolation syscall.Errno = 32
	errorLockViolation    syscall.Errno = 33
)

// renameFile retries for a short while when another process, such as a
// virus scanner, briefly holds the file open.
func renameFile(from, to string) error {
	var err error
	for range 20 {
		err = os.Rename(from, to)
		if !transient(err) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

func transient(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED) || errors.Is(err, errorSharingViolation) || errors.Is(err, errorLockViolation)
}

// copyOwner is a no-op: a new file inherits the ACL of its directory.
func copyOwner(string, fs.FileInfo) error { return nil }

// syncDir is a no-op: NTFS journals renames itself.
func syncDir(string) error { return nil }
