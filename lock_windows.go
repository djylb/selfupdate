//go:build windows

package selfupdate

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	accessDelete            = 0x10000

	fileDispositionInfoEx         = 21
	fileDispositionDelete         = 0x1
	fileDispositionPosixSemantics = 0x2
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx                 = kernel32.NewProc("LockFileEx")
	procUnlockFileEx               = kernel32.NewProc("UnlockFileEx")
	procSetFileInformationByHandle = kernel32.NewProc("SetFileInformationByHandle")
)

// openLockFile opens the lock file sharing everything, delete included,
// so that its holder can delete it while others have it open.
func openLockFile(p string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	h, err := syscall.CreateFile(name,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE|accessDelete,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	return os.NewFile(uintptr(h), p), nil
}

func tryLockSystem(f *os.File) (bool, error) {
	err := handleCall(f, func(h uintptr) error {
		var ol syscall.Overlapped
		r, _, e := procLockFileEx.Call(h, lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
		if r == 0 {
			return e
		}
		return nil
	})
	if errors.Is(err, errorLockViolation) {
		return false, nil
	}
	return err == nil, err
}

func unlockSystem(f *os.File) {
	_ = handleCall(f, func(h uintptr) error {
		var ol syscall.Overlapped
		r, _, e := procUnlockFileEx.Call(h, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
		if r == 0 {
			return e
		}
		return nil
	})
}

// removeLocked deletes the lock file through its handle with POSIX
// semantics: the name goes at once, while open handles stay valid. File
// systems without them keep the file, which does no harm; a classic
// delete would instead leave a name nobody can open until every handle
// is closed.
func removeLocked(f *os.File, _ string) {
	_ = handleCall(f, func(h uintptr) error {
		info := uint32(fileDispositionDelete | fileDispositionPosixSemantics)
		r, _, e := procSetFileInformationByHandle.Call(h, fileDispositionInfoEx, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
		if r == 0 {
			return e
		}
		return nil
	})
}

func handleCall(f *os.File, fn func(h uintptr) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var cerr error
	if err := rc.Control(func(h uintptr) { cerr = fn(h) }); err != nil {
		return err
	}
	return cerr
}

// closeLockFile closes a lock file.
func closeLockFile(f *os.File) { closeQuietly(f) }
