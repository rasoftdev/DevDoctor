//go:build !linux

package main

import "os"

func fileOwner(fi os.FileInfo) (uint32, uint32, bool) { return 0, 0, false }
