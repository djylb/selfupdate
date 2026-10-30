//go:build unix

package selfupdate

import (
	"os"
	"syscall"
)

func relaunch(exe string, argv []string) error {
	exe, argv, err := relaunchArgs(exe, argv)
	if err != nil {
		return err
	}
	return syscall.Exec(exe, argv, os.Environ())
}
