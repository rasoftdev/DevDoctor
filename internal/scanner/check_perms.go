package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"devdoctor/internal/config"
	"devdoctor/internal/sh"
)

var webUsers = map[string]bool{"www-data": true, "nginx": true, "apache": true, "http": true, "www": true}

func scanRoots(cfg config.Config) []string {
	roots := []string{"/var/www", "/srv", "/home", "/opt"}
	return append(roots, cfg.ScanRoots...)
}

var skipDirs = map[string]bool{"node_modules": true, "vendor": true, ".cache": true, ".npm": true, "snap": true, ".nvm": true, ".composer": true, ".local": true}

func checkPermissions(c *Collector) {
	type sysFile struct {
		path   string
		maxMod os.FileMode
		sev    string
	}
	for _, sf := range []sysFile{
		{"/etc/shadow", 0o640, "crit"}, {"/etc/gshadow", 0o640, "crit"},
		{"/etc/passwd", 0o644, "crit"}, {"/etc/sudoers", 0o440, "crit"},
		{"/etc/ssh/sshd_config", 0o644, "warn"}, {"/root/.ssh/authorized_keys", 0o644, "warn"},
	} {
		fi, err := os.Stat(sf.path)
		if err != nil {
			continue
		}
		if fi.Mode().Perm()&^sf.maxMod != 0 {
			c.add("Permissions", sf.sev, M("%s has overly open permissions (%04o)", sf.path, fi.Mode().Perm()), "",
				fmt.Sprintf("chmod %04o %s", sf.maxMod, sf.path))
		}
	}
	if m, _ := filepath.Glob("/root/.ssh/id_*"); m != nil {
		for _, p := range m {
			if strings.HasSuffix(p, ".pub") {
				continue
			}
			if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
				c.add("Permissions", "crit", M("SSH private key accessible by others (%04o): %s", fi.Mode().Perm(), p), "", "chmod 600 "+p)
			}
		}
	}
	if fi, err := os.Stat("/tmp"); err == nil && fi.Mode()&os.ModeSticky == 0 {
		c.add("Permissions", "warn", "/tmp has no sticky bit", "Any user could delete other users' files.", "chmod 1777 /tmp")
	}

	// Web roots: world-writable files, readable secrets, exposed backups.
	var wwFiles, wwDirs, envs, dumps, gits []string
	count := 0
	for _, root := range scanRoots(c.cfg) {
		if root == "/home" || root == "/opt" {
			continue // only web roots for this deep scan
		}
		base := strings.Count(root, "/")
		filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			count++
			if count > 40000 {
				return filepath.SkipAll
			}
			if de.IsDir() {
				if strings.Count(p, "/")-base > 6 || skipDirs[de.Name()] {
					return filepath.SkipDir
				}
				if de.Name() == ".git" {
					gits = append(gits, filepath.Dir(p))
					return filepath.SkipDir
				}
				if fi, e := de.Info(); e == nil && fi.Mode().Perm()&0o002 != 0 && fi.Mode()&os.ModeSticky == 0 {
					wwDirs = append(wwDirs, p)
				}
				return nil
			}
			fi, e := de.Info()
			if e != nil || !fi.Mode().IsRegular() {
				return nil
			}
			n := strings.ToLower(de.Name())
			if fi.Mode().Perm()&0o002 != 0 && (strings.HasSuffix(n, ".php") || strings.HasSuffix(n, ".js") || n == ".env") {
				wwFiles = append(wwFiles, p)
			}
			if n == ".env" && fi.Mode().Perm()&0o004 != 0 {
				envs = append(envs, p)
			}
			if n == "wp-config.php" && fi.Mode().Perm()&0o007 != 0 {
				envs = append(envs, p)
			}
			for _, ext := range []string{".sql", ".sql.gz", ".bak", ".old", ".dump", ".tar.gz", ".zip"} {
				if strings.HasSuffix(n, ext) && fi.Size() > 4096 && !strings.Contains(p, "/storage/") {
					dumps = append(dumps, p)
					break
				}
			}
			return nil
		})
	}
	sample := func(l []string) string {
		if len(l) > 5 {
			return strings.Join(l[:5], "\n") + fmt.Sprintf("\n… +%d", len(l)-5)
		}
		return strings.Join(l, "\n")
	}
	if len(wwFiles) > 0 {
		c.add("Permissions", "crit", M("%d code files writable by any user (777/666)", len(wwFiles)), sample(wwFiles),
			"find /var/www -type f -perm -o+w -exec chmod o-w {} +")
	}
	if len(wwDirs) > 0 {
		c.add("Permissions", "warn", M("%d directories writable by any user", len(wwDirs)), sample(wwDirs),
			"chmod o-w <dir>  (use the right owner/group instead of 777)")
	}
	if len(envs) > 0 {
		c.add("Permissions", "warn", M("%d secret files readable by everyone (.env / wp-config.php)", len(envs)), sample(envs),
			"chmod 640 <file> and chown user:web-group")
	}
	if len(dumps) > 0 {
		c.add("Permissions", "warn", M("%d backups/dumps inside web roots", len(dumps)),
			M("%s\nIf they sit in a public docroot they can be downloaded.", sample(dumps)), "Move them outside the public directory.")
	}
	if len(gits) > 0 {
		c.add("Permissions", "info", M("%d .git repositories in web roots", len(gits)),
			M("%s\nMake sure /.git is not reachable over HTTP.", sample(gits)), "nginx: location ~ /\\.git { deny all; }")
	}
}

// laravelWritable checks that storage/ and bootstrap/cache are writable by the web user.
func laravelWritable(c *Collector, proj string) {
	for _, sub := range []string{"storage", "bootstrap/cache"} {
		p := filepath.Join(proj, sub)
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		uid, gid, ok := fileOwner(fi)
		if !ok {
			return
		}
		m := fi.Mode().Perm()
		okW := m&0o002 != 0
		if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil && webUsers[u.Username] && m&0o200 != 0 {
			okW = true
		}
		if g, err := user.LookupGroupId(strconv.Itoa(int(gid))); err == nil && webUsers[g.Name] && m&0o020 != 0 {
			okW = true
		}
		if !okW {
			c.add("Permissions", "warn", M("Laravel: %s is not writable by the web user", p),
				"This will cause 500 errors (logs, cache, sessions).", fmt.Sprintf("chown -R www-data:www-data %s && chmod -R ug+rwX %s", p, p))
		}
	}
}

var _ = sh.Trunc
