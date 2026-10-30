//go:build !unix && !windows

package selfupdate

import "errors"

func relaunch(string, []string) error { return errors.ErrUnsupported }
