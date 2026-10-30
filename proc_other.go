//go:build !unix && !windows

package selfupdate

// processAlive reports false for every other process: these systems run
// one process per program instance, so a lock left by another process ID
// was left by an earlier, finished run.
func processAlive(int) bool { return false }
