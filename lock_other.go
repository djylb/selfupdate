//go:build !unix && !windows

package selfupdate

import "os"

// openLockFile returns no file: these systems (js/wasm, wasip1, plan9)
// have no file locks usable here, so locks exclude the goroutines of this
// process only. Run one updating instance of a program at a time there.
func openLockFile(string) (*os.File, error) { return nil, nil }

func tryLockSystem(*os.File) (bool, error) { return true, nil }

func unlockSystem(*os.File) {}

func removeLocked(*os.File, string) {}

// closeLockFile closes a lock file.
func closeLockFile(f *os.File) { closeQuietly(f) }
