//go:build !unix && !windows

package selfupdate

import (
	"io/fs"
	"os"
)

func renameFile(from, to string) error { return os.Rename(from, to) }

func copyOwner(string, fs.FileInfo) error { return nil }

func syncDir(string) error { return nil }
