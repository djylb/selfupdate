//go:build !unix && !windows

package selfupdate

import "io/fs"

// transientRenameErrors is empty: renames here fail for good or not at all.
var transientRenameErrors []error

func copyOwner(string, fs.FileInfo) error { return nil }

func syncDir(string) error { return nil }
