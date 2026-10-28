//go:build !linux

package restore

import "os"

func readHandle(r *os.Root, rel string) (*os.File, error) { return r.Open(rel) }
