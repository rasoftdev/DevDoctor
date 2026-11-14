package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

const (
	MaxRoots = 30
	MaxURLs  = 30
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

// NormalizeURLs valida la lista de sitios a vigilar: sólo http/https, sin credenciales ni metadatos de nube.
func NormalizeURLs(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "://") {
			s = "https://" + s
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || len(s) > 300 {
			return nil, fmt.Errorf("invalid URL (use http:// or https://): %s", short(raw))
		}
		if u.User != nil {
			return nil, fmt.Errorf("invalid URL (credentials are not allowed): %s", short(raw))
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return nil, fmt.Errorf("invalid URL (address not allowed): %s", short(raw))
		}
		if !seen[u.String()] {
			seen[u.String()] = true
			out = append(out, u.String())
		}
	}
	if len(out) > MaxURLs {
		return nil, fmt.Errorf("too many URLs (maximum %d)", MaxURLs)
	}
	return out, nil
}

func short(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
