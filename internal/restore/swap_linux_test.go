//go:build linux

package restore

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentDirectorySymlinkSwapCannotEscape(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	real, swapped := filepath.Join(root, "real"), filepath.Join(root, "swapped")
	if e := os.Mkdir(real, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, swapped); e != nil {
		t.Skip(e)
	}
	if e := unix.Renameat2(unix.AT_FDCWD, real, unix.AT_FDCWD, swapped, unix.RENAME_EXCHANGE); e != nil {
		t.Skip("atomic exchange unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			_ = unix.Renameat2(unix.AT_FDCWD, real, unix.AT_FDCWD, swapped, unix.RENAME_EXCHANGE)
		}
	}()
	for i := 0; i < 200; i++ {
		_ = Write(root, fmt.Sprintf("swapped/.env.%d", i), []byte("FIXTURE=synthetic-swap-test\n"))
	}
	cancel()
	wg.Wait()
	files, e := os.ReadDir(outside)
	if e != nil {
		t.Fatal(e)
	}
	if len(files) != 0 {
		t.Fatal("restore escaped approved root during directory/symlink race")
	}
}
