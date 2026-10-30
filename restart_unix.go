//go:build unix

package selfupdate

import (
	"os"
	"syscall"
)

func relaunch(exe string, argv []string) error {
	return syscall.Exec(exe, argv, os.Environ())
}
