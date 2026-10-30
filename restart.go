package selfupdate

import "os"

// Relaunch runs exe with the argument vector argv (argv[0] included, as in
// [os.Args]) and the current environment, so that the process runs the
// code now on disk. An empty exe means the running executable, with
// symlinks resolved as for [ExecutableJournal]; never pass os.Args[0],
// which may be a bare name resolved against the working directory. A nil
// argv means [os.Args], so Relaunch("", nil) restarts the program as it
// was started.
//
// On Unix systems the current process image is replaced (execve): on
// success Relaunch does not return, the process ID stays the same and a
// service manager does not notice. File descriptors opened without
// close-on-exec, which Go never does by itself, are inherited.
//
// On Windows a new process is started with the same standard handles and
// Relaunch returns nil: the caller must then exit promptly with status
// zero. The two processes overlap briefly, so the new one should retry
// resources such as listening ports for a moment.
//
// Under a service manager that restarts the program when it exits, it is
// usually simpler to exit instead and let the manager start the new
// version. On systems without process control Relaunch returns
// [errors.ErrUnsupported].
func Relaunch(exe string, argv []string) error {
	return relaunch(exe, argv)
}

// relaunchArgs fills in the defaults of [Relaunch].
func relaunchArgs(exe string, argv []string) (string, []string, error) {
	if exe == "" {
		var err error
		if exe, err = executable(""); err != nil {
			return "", nil, err
		}
	}
	if argv == nil {
		argv = os.Args
	}
	if len(argv) == 0 {
		argv = []string{exe}
	}
	return exe, argv, nil
}
