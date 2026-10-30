package selfupdate

// Relaunch runs exe with the argument vector argv (argv[0] included, as in
// [os.Args]; empty means exe alone) and the current environment, so that
// the process runs the code now on disk.
//
// On Unix systems the current process image is replaced (execve): on
// success Relaunch does not return, the process ID stays the same and a
// service manager does not notice. File descriptors opened without
// close-on-exec, which Go never does by itself, are inherited.
//
// On Windows a new process is started with the same standard handles and
// Relaunch returns nil: the caller must then exit promptly. The two
// processes overlap briefly, so the new one should retry resources such as
// listening ports for a moment.
//
// Under a service manager that restarts the program when it exits, it is
// usually simpler to exit instead and let the manager start the new
// version. On systems without process control Relaunch returns
// [errors.ErrUnsupported].
func Relaunch(exe string, argv []string) error {
	if len(argv) == 0 {
		argv = []string{exe}
	}
	return relaunch(exe, argv)
}
