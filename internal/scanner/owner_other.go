//go:build !linux

package scanner

import "os"

func fileOwner(fi os.FileInfo) (uint32, uint32, bool) { return 0, 0, false }
