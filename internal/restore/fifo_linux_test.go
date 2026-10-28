//go:build linux

package restore

import (
	"golang.org/x/sys/unix"
	"path/filepath"
	"testing"
)

func TestFIFORejectedWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	if e := unix.Mkfifo(filepath.Join(root, ".env"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(root, ".env"); e == nil {
		t.Fatal("FIFO accepted")
	}
}
