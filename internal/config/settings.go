package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	MaxRoots = 30
)

// NormalizeRoots valida y limpia la lista de carpetas extra donde buscar proyectos.
func NormalizeRoots(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\r\n") {
			return nil, fmt.Errorf("invalid folder (must be an absolute path): %s", short(p))
		}
		p = filepath.Clean(p)
		if p == "/" {
			return nil, errors.New("invalid folder: scanning the whole filesystem (/) is not allowed")
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) > MaxRoots {
		return nil, fmt.Errorf("too many folders (maximum %d)", MaxRoots)
	}
	return out, nil
}

func short(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
