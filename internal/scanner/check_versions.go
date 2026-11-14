package scanner

import (
	"devdoctor/internal/sh"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func d(y int, m time.Month, day int) time.Time { return time.Date(y, m, day, 0, 0, 0, 0, time.UTC) }

// Fin de soporte de seguridad (se refrescan desde endoflife.date cuando hay conexión).
var eolMu sync.RWMutex

var phpEOL = map[string]time.Time{
	"7.4": d(2022, 11, 28), "8.0": d(2023, 11, 26), "8.1": d(2025, 12, 31),
	"8.2": d(2026, 12, 31), "8.3": d(2027, 12, 31), "8.4": d(2028, 12, 31), "8.5": d(2029, 12, 31),
}
var nodeEOL = map[int]time.Time{
	16: d(2023, 9, 11), 18: d(2025, 4, 30), 20: d(2026, 4, 30), 22: d(2027, 4, 30), 24: d(2028, 4, 30),
}

type tool struct {
	name string
	cmd  []string
	re   string
}

var tools = []tool{
	{"Node.js", []string{"node", "-v"}, `v(\d+\.\d+\.\d+)`},
	{"npm", []string{"npm", "-v"}, `(\d+\.\d+\.\d+)`},
	{"Composer", []string{"composer", "--version", "--no-ansi"}, `(\d+\.\d+\.\d+)`},
	{"Python", []string{"python3", "-V"}, `(\d+\.\d+\.\d+)`},
	{"Nginx", []string{"nginx", "-v"}, `nginx/(\d+\.\d+\.\d+)`},
	{"Apache", []string{"apache2", "-v"}, `Apache/(\d+\.\d+\.\d+)`},
	{"Apache (httpd)", []string{"httpd", "-v"}, `Apache/(\d+\.\d+\.\d+)`},
	{"MySQL/MariaDB", []string{"mysql", "--version"}, `(\d+\.\d+\.\d+)`},
	{"PostgreSQL", []string{"psql", "--version"}, `(\d+\.\d+)`},
	{"Redis", []string{"redis-server", "--version"}, `v=(\d+\.\d+\.\d+)`},
	{"Docker", []string{"docker", "--version"}, `(\d+\.\d+\.\d+)`},
	{"Git", []string{"git", "--version"}, `(\d+\.\d+\.\d+)`},
	{"OpenSSL", []string{"openssl", "version"}, `OpenSSL (\d+\.\d+\.\d+)`},
	{"OpenSSH", []string{"ssh", "-V"}, `OpenSSH_(\d+\.\d+(?:p\d+)?)`},
	{"sudo", []string{"sudo", "-V"}, `Sudo version (\d+\.\d+\.\d+(?:p\d+)?)`},
}

func detectVersion(cmd []string, re string) string {
	if !sh.Have(cmd[0]) {
		return ""
	}
	out, _ := sh.Run(8*time.Second, cmd[0], cmd[1:]...)
	if m := regexp.MustCompile(re).FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

func checkVersions(c *Collector) {
	add := func(v VersionInfo) {
		c.mu.Lock()
		c.R.Versions = append(c.R.Versions, v)
		c.mu.Unlock()
	}

	// PHP: binario por defecto + versiones instaladas en paralelo (php8.1, php8.3...)
	seen := map[string]bool{}
	bins := []string{"php"}
	for _, dir := range []string{"/usr/bin", "/usr/local/bin"} {
		m, _ := filepath.Glob(filepath.Join(dir, "php[0-9].[0-9]"))
		bins = append(bins, m...)
	}
	for i, b := range bins {
		v := detectVersion([]string{b, "-v"}, `PHP (\d+\.\d+\.\d+)`)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		label := "PHP"
		if i > 0 {
			label = "PHP (" + filepath.Base(b) + ")"
		}
		st, note := phpStatus(v)
		add(mkVer(label, v, st, note))
		if st == "crit" || st == "warn" {
			sev := st
			c.add("Versions", sev, M("%s %s: %s", label, v, note), "", "Upgrade to a supported branch (e.g. PHP 8.3/8.4) and test your apps before switching.")
		}
	}

	for _, t := range tools {
		v := detectVersion(t.cmd, t.re)
		if v == "" {
			continue
		}
		name := t.name
		if name == "MySQL/MariaDB" {
			name = "MySQL"
			if out, _ := sh.Run(8*time.Second, t.cmd[0], t.cmd[1:]...); strings.Contains(out, "MariaDB") {
				name = "MariaDB"
			}
		}
		st, note := "ok", Msg{}
		if t.name == "Node.js" {
			st, note = nodeStatus(v)
			if st == "crit" || st == "warn" {
				c.add("Versions", st, M("Node.js %s: %s", v, note), "", "Install a current LTS release (nvm install --lts or NodeSource).")
			}
		}
		add(mkVer(name, v, st, note))
	}
}

// setEOLTables sustituye las tablas de fin de soporte por datos frescos de endoflife.date.
func setEOLTables(php map[string]time.Time, node map[int]time.Time) {
	eolMu.Lock()
	defer eolMu.Unlock()
	for k, v := range php {
		phpEOL[k] = v
	}
	for k, v := range node {
		nodeEOL[k] = v
	}
}

func phpStatus(v string) (string, Msg) {
	pv, _ := parseVer(v)
	key := fmt.Sprintf("%d.%d", pv[0], pv[1])
	eolMu.RLock()
	eol, ok := phpEOL[key]
	eolMu.RUnlock()
	if !ok {
		if pv[0] < 8 || (pv[0] == 8 && pv[1] < 1) {
			return "crit", M("unsupported version (EOL)")
		}
		return "ok", Msg{}
	}
	days := int(time.Until(eol).Hours() / 24)
	switch {
	case days < 0:
		return "crit", M("no support since %s", eol.Format("2006-01-02"))
	case days < 180:
		return "warn", M("end of support in %d days (%s)", days, eol.Format("2006-01-02"))
	}
	return "ok", M("supported until %s", eol.Format("2006-01-02"))
}

func nodeStatus(v string) (string, Msg) {
	pv, _ := parseVer(v)
	maj := pv[0]
	if maj%2 == 1 {
		return "warn", M("odd-numbered release (not LTS), not recommended in production")
	}
	eolMu.RLock()
	eol, ok := nodeEOL[maj]
	eolMu.RUnlock()
	if !ok {
		if maj < 16 {
			return "crit", M("unsupported version (EOL)")
		}
		return "ok", Msg{}
	}
	days := int(time.Until(eol).Hours() / 24)
	switch {
	case days < 0:
		return "crit", M("no support since %s", eol.Format("2006-01-02"))
	case days < 180:
		return "warn", M("end of support in %d days (%s)", days, eol.Format("2006-01-02"))
	}
	return "ok", M("supported until %s", eol.Format("2006-01-02"))
}

func atoi(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }
