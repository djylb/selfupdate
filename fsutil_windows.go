//go:build windows

package selfupdate

import (
	"io/fs"
	"syscall"
)

const (
	errorSharingViolation syscall.Errno = 32
	errorLockViolation    syscall.Errno = 33
)

// transientRenameErrors are the rename failures caused by another
// process, such as a virus scanner, holding the file open for a moment.
var transientRenameErrors = []error{syscall.ERROR_ACCESS_DENIED, errorSharingViolation, errorLockViolation}

// copyOwner is a no-op: a new file inherits the ACL of its directory.
func copyOwner(string, fs.FileInfo) error { return nil }

// syncDir is a no-op: NTFS journals renames itself.
func syncDir(string) error { return nil }
