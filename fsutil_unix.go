//go:build unix

package selfupdate

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// transientRenameErrors is empty: renames here fail for good or not at all.
var transientRenameErrors []error

// copyOwner gives p the owner and group of fi where the process may set
// them; an unprivileged process keeps its own.
func copyOwner(p string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	err := os.Lchown(p, int(st.Uid), int(st.Gid))
	if errors.Is(err, fs.ErrPermission) {
		return nil
	}
	return err
}

// syncDir makes renames in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, errors.ErrUnsupported) {
		err = nil // file systems that cannot sync directories
	}
	return errors.Join(err, d.Close())
}
