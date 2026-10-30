//go:build windows

package selfupdate

import (
	"os"
	"os/exec"
)

func relaunch(exe string, argv []string) error {
	exe, argv, err := relaunchArgs(exe, argv)
	if err != nil {
		return err
	}
	cmd := exec.Command(exe)
	cmd.Args = argv
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
