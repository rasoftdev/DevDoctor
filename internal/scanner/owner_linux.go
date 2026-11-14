//go:build linux

package scanner

import (
	"os"
	"syscall"
)

func fileOwner(fi os.FileInfo) (uint32, uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
