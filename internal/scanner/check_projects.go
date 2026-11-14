package scanner

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"devdoctor/internal/config"
	"devdoctor/internal/sh"
)

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}
type packageJSON struct {
	Engines map[string]string `json:"engines"`
}

// docroots lee la configuración de Nginx/Apache para encontrar dónde viven realmente los sitios.
var (
	nginxRootRe  = regexp.MustCompile(`(?m)^s*roots+"?([^;"s]+)"?s*;`)
	apacheRootRe = regexp.MustCompile(`(?mi)^s*DocumentRoots+"?([^"s]+)"?`)
)

func webDocroots() map[string]bool {
	out := map[string]bool{}
	for _, root := range []string{"/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/caddy"} {
		filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
			if err != nil || de.IsDir() {
				return nil
			}
			if fi, e := de.Info(); e != nil || fi.Size() > 1<<20 {
				return nil
			}
			txt := sh.ReadFile(p)
			for _, re := range []*regexp.Regexp{nginxRootRe, apacheRootRe} {
				for _, m := range re.FindAllStringSubmatch(txt, -1) {
					if d := filepath.Clean(m[1]); strings.HasPrefix(d, "/") && strings.Count(d, "/") >= 2 {
						out[d] = true
					}
				}
			}
			return nil
		})
	}
	return out
}

// dockerBindSources devuelve las carpetas del anfitrión que montan los contenedores (donde suele estar el código).
func dockerBindSources() []string {
	if !sh.Have("docker") {
		return nil
	}
	ids, _ := sh.Run(8*time.Second, "docker", "ps", "-q")
	list := strings.Fields(ids)
	if len(list) == 0 {
		return nil
	}
	raw, err := sh.RunStdout(15*time.Second, "", "docker", append([]string{"inspect", "--format", "{{range .Mounts}}{{if eq .Type \"bind\"}}{{.Source}}\n{{end}}{{end}}"}, list...)...)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.Count(l, "/") < 2 {
			continue
		}
		skip := false
		for _, bad := range []string{"/var/run", "/run", "/etc", "/proc", "/sys", "/dev", "/var/lib/docker", "/var/log", "/tmp", "/usr", "/lib", "/boot"} {
			if l == bad || strings.HasPrefix(l, bad+"/") {
				skip = true
			}
		}
		if !skip {
			out = append(out, l)
		}
	}
	return out
}

// projectRoots reúne todos los directorios donde buscar proyectos (sólo los que existen).
func projectRoots(cfg config.Config, docroots map[string]bool) []string {
	seen := map[string]bool{}
	var roots []string
	add := func(p string) {
		p = filepath.Clean(p)
		if !seen[p] && sh.Exists(p) {
			seen[p] = true
			roots = append(roots, p)
		}
	}
	for _, r := range scanRoots(cfg) {
		add(r)
	}
	for d := range docroots {
		add(d)
		if parent := filepath.Dir(d); strings.Count(parent, "/") >= 2 { // raíz del proyecto (p. ej. .../app/public -> .../app)
			add(parent)
		}
	}
	for _, d := range dockerBindSources() {
		add(d)
	}
	sort.Strings(roots)
	return roots
}

func isWebPath(p string, docroots map[string]bool) bool {
	if docroots[p] {
		return true
	}
	for _, pre := range []string{"/var/www/", "/srv/", "/usr/share/nginx/"} {
		if strings.HasPrefix(p+"/", pre) {
			return true
		}
	}
	return false
}

func discoverProjects(roots []string, docroots map[string]bool) []string {
	seen := map[string]bool{}
	var found []string
	for _, root := range roots {
		base := strings.Count(root, "/")
		filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
			if err != nil || !de.IsDir() {
				return nil
			}
			if strings.Count(p, "/")-base > 4 || skipDirs[de.Name()] || (strings.HasPrefix(de.Name(), ".") && p != root) {
				return filepath.SkipDir
			}
			isProj := sh.Exists(filepath.Join(p, "composer.json")) || sh.Exists(filepath.Join(p, "package.json")) || sh.Exists(filepath.Join(p, "wp-config.php"))
			if !isProj && isWebPath(p, docroots) {
				for _, idx := range []string{"index.php", "index.html", "index.htm"} {
					if sh.Exists(filepath.Join(p, idx)) {
						isProj = true
						break
					}
				}
			}
			if isProj {
				if !seen[p] {
					seen[p] = true
					found = append(found, p)
				}
				if len(found) >= 60 {
					return filepath.SkipAll
				}
				return filepath.SkipDir
			}
			return nil
		})
	}
	sort.Strings(found)
	return found
}

func checkProjects(c *Collector, s *Scanner) {
	docroots := webDocroots()
	roots := projectRoots(c.cfg, docroots)
	c.mu.Lock()
	c.R.ScanRoots = roots
	c.mu.Unlock()
	projects := discoverProjects(roots, docroots)
	if len(projects) == 0 {
		return
	}
	var phpV, nodeV ver
	var phpOK, nodeOK bool
	if v := detectVersion([]string{"php", "-v"}, `PHP (\d+\.\d+\.\d+)`); v != "" {
		phpV, _ = parseVer(v)
		phpOK = true
	}
	if v := detectVersion([]string{"node", "-v"}, `v(\d+\.\d+\.\d+)`); v != "" {
		nodeV, _ = parseVer(v)
		nodeOK = true
	}
	phpMods := map[string]bool{}
	if phpOK {
		out, _ := sh.Run(8*time.Second, "php", "-m")
		for _, l := range strings.Split(out, "\n") {
			phpMods[strings.ToLower(strings.TrimSpace(l))] = true
		}
	}

	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for _, p := range projects {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem; recover() }()
			analyzeProject(c, s, p, phpV, phpOK, nodeV, nodeOK, phpMods)
		}(p)
	}
	wg.Wait()
	c.mu.Lock()
	sort.Slice(c.R.Projects, func(i, j int) bool { return c.R.Projects[i].Path < c.R.Projects[j].Path })
	c.mu.Unlock()
}

func analyzeProject(c *Collector, s *Scanner, p string, phpV ver, phpOK bool, nodeV ver, nodeOK bool, phpMods map[string]bool) {
	pi := ProjectInfo{Path: p, Vulns: map[string]int{}}
	issue := func(sev string, title Msg, detail, fix any) {
		pi.Issues++
		c.add("Dependencies", sev, M("%s — %s", title, p), detail, fix)
	}
	switch {
	case sh.Exists(filepath.Join(p, "artisan")):
		pi.Framework = "Laravel"
		laravelWritable(c, p)
	case sh.Exists(filepath.Join(p, "wp-config.php")):
		pi.Framework = "WordPress"
	case sh.Exists(filepath.Join(p, "symfony.lock")):
		pi.Framework = "Symfony"
	case sh.Exists(filepath.Join(p, "next.config.js")) || sh.Exists(filepath.Join(p, "next.config.mjs")):
		pi.Framework = "Next.js"
	case sh.Exists(filepath.Join(p, "nuxt.config.ts")) || sh.Exists(filepath.Join(p, "nuxt.config.js")):
		pi.Framework = "Nuxt"
	case !sh.Exists(filepath.Join(p, "composer.json")) && !sh.Exists(filepath.Join(p, "package.json")):
		pi.Framework = "Site"
	}

	// ---------- PHP / Composer ----------
	if b, err := os.ReadFile(filepath.Join(p, "composer.json")); err == nil {
		var cj composerJSON
		if json.Unmarshal(b, &cj) != nil {
			issue("crit", M("Invalid composer.json (malformed JSON)"), "", "composer validate")
		} else {
			if req := cj.Require["php"]; req != "" {
				pi.PHPReq = req
				if phpOK && !satisfies(req, phpV) {
					issue("crit", M("Requires PHP %s but the server has %d.%d", req, phpV[0], phpV[1]),
						"composer install will fail or the app will break at runtime.",
						"Install the required PHP version or adjust the 'php' constraint after testing compatibility.")
				}
			}
			var missing []string
			for k := range cj.Require {
				if strings.HasPrefix(k, "ext-") && phpOK && !phpMods[strings.ToLower(strings.TrimPrefix(k, "ext-"))] {
					missing = append(missing, k)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				issue("crit", M("Missing PHP extensions: %s", strings.Join(missing, ", ")), "",
					"apt install "+strings.ReplaceAll(strings.Join(missing, " "), "ext-", "php-"))
			}
		}
		lock := filepath.Join(p, "composer.lock")
		li, lerr := os.Stat(lock)
		switch {
		case lerr != nil:
			issue("warn", M("No composer.lock (non-reproducible versions)"), "", "composer install  (and commit the lock file)")
		default:
			if ji, _ := os.Stat(filepath.Join(p, "composer.json")); ji != nil && ji.ModTime().After(li.ModTime().Add(time.Minute)) {
				issue("warn", M("composer.json is newer than composer.lock"), "The lock file may be out of date.", "composer update --lock")
			}
			if !sh.Exists(filepath.Join(p, "vendor", "autoload.php")) {
				issue("crit", M("PHP dependencies not installed (vendor/ missing)"), "", "composer install --no-dev --optimize-autoloader")
			} else if sh.Have("composer") {
				if n, titles, ok := s.auditComposer(p, li); ok {
					pi.Vulns["composer"] = n
					if n > 0 {
						issue("crit", M("%d known vulnerabilities in Composer dependencies", n), strings.Join(titles, "\n"), "composer audit  ·  composer update <package>")
					}
				}
			}
		}
	}

	// ---------- Node / npm ----------
	if b, err := os.ReadFile(filepath.Join(p, "package.json")); err == nil {
		var pj packageJSON
		if json.Unmarshal(b, &pj) != nil {
			issue("crit", M("Invalid package.json (malformed JSON)"), "", "")
		} else if req := pj.Engines["node"]; req != "" {
			pi.NodeReq = req
			if nodeOK && !satisfies(req, nodeV) {
				issue("crit", M("Requires Node %s but the server has %d.%d", req, nodeV[0], nodeV[1]), "", "Use nvm/n to install the required version.")
			}
		}
		lock := filepath.Join(p, "package-lock.json")
		li, lerr := os.Stat(lock)
		hasLock := lerr == nil || sh.Exists(filepath.Join(p, "yarn.lock")) || sh.Exists(filepath.Join(p, "pnpm-lock.yaml"))
		if !hasLock {
			issue("info", M("No Node lockfile"), "", "npm install  (and commit package-lock.json)")
		}
		if hasLock && !sh.Exists(filepath.Join(p, "node_modules")) && !sh.Exists(filepath.Join(p, ".next")) && !sh.Exists(filepath.Join(p, "dist")) && !sh.Exists(filepath.Join(p, "build")) {
			issue("warn", M("node_modules missing (dependencies not installed)"), "", "npm ci")
		}
		if lerr == nil && sh.Have("npm") {
			if v, ok := s.auditNPM(p, li); ok {
				for k, n := range v {
					pi.Vulns["npm_"+k] = n
				}
				tot := v["critical"] + v["high"] + v["moderate"] + v["low"]
				pi.Vulns["npm"] = tot
				if v["critical"]+v["high"] > 0 {
					issue("crit", M("npm audit: %d critical, %d high, %d moderate", v["critical"], v["high"], v["moderate"]), "",
						"npm audit fix  ·  review breaking changes before npm audit fix --force")
				} else if tot > 0 {
					issue("warn", M("npm audit: %d moderate, %d low", v["moderate"], v["low"]), "", "npm audit fix")
				}
			}
		}
	}
	if len(pi.Vulns) == 0 {
		pi.Vulns = nil
	}
	c.mu.Lock()
	c.R.Projects = append(c.R.Projects, pi)
	c.mu.Unlock()
}

type composerAuditRes struct {
	n      int
	titles []string
	ok     bool
}

func (s *Scanner) auditComposer(p string, li os.FileInfo) (int, []string, bool) {
	key := fmt.Sprintf("composer|%s|%d|%d", p, li.ModTime().Unix(), time.Now().Unix()/3600)
	if v, ok := s.audits.Load(key); ok {
		r := v.(composerAuditRes)
		return r.n, r.titles, r.ok
	}
	out, _ := sh.RunStdout(40*time.Second, p, "composer", "audit", "--locked", "--format=json", "--no-interaction")
	var parsed struct {
		Advisories json.RawMessage `json:"advisories"`
	}
	res := composerAuditRes{}
	if json.Unmarshal([]byte(out), &parsed) == nil {
		res.ok = true
		var m map[string][]struct {
			Title string `json:"title"`
			CVE   string `json:"cve"`
		}
		if json.Unmarshal(parsed.Advisories, &m) == nil {
			for pkg, list := range m {
				for _, a := range list {
					res.n++
					if len(res.titles) < 6 {
						res.titles = append(res.titles, fmt.Sprintf("%s — %s %s", pkg, a.Title, a.CVE))
					}
				}
			}
		}
	}
	s.audits.Store(key, res)
	return res.n, res.titles, res.ok
}

func (s *Scanner) auditNPM(p string, li os.FileInfo) (map[string]int, bool) {
	key := fmt.Sprintf("npm|%s|%d|%d", p, li.ModTime().Unix(), time.Now().Unix()/3600)
	if v, ok := s.audits.Load(key); ok {
		m, _ := v.(map[string]int)
		return m, m != nil
	}
	out, _ := sh.RunStdout(45*time.Second, p, "npm", "audit", "--json", "--package-lock-only", "--no-fund", "--no-update-notifier")
	var parsed struct {
		Metadata struct {
			Vulnerabilities map[string]int `json:"vulnerabilities"`
		} `json:"metadata"`
	}
	var res map[string]int
	if json.Unmarshal([]byte(out), &parsed) == nil && parsed.Metadata.Vulnerabilities != nil {
		res = parsed.Metadata.Vulnerabilities
	}
	s.audits.Store(key, res)
	return res, res != nil
}
