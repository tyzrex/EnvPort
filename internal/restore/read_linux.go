//go:build linux

package restore

import (
	"golang.org/x/sys/unix"
	"os"
)

// openat2 atomically rejects every symlink component and prevents FIFO blocking.
func readHandle(r *os.Root, rel string) (*os.File, error) {
	dir, e := r.Open(".")
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	fd, e := unix.Openat2(int(dir.Fd()), rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), rel), nil
}
