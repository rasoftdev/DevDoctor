package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}
type packageJSON struct {
	Engines map[string]string `json:"engines"`
}

func discoverProjects(roots []string) []string {
	var found []string
	for _, root := range roots {
		base := strings.Count(root, "/")
		filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !de.IsDir() {
				return nil
			}
			if strings.Count(p, "/")-base > 4 || skipDirs[de.Name()] || (strings.HasPrefix(de.Name(), ".") && p != root) {
				return filepath.SkipDir
			}
			if exists(filepath.Join(p, "composer.json")) || exists(filepath.Join(p, "package.json")) || exists(filepath.Join(p, "wp-config.php")) {
				found = append(found, p)
				if len(found) >= 40 {
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
	projects := discoverProjects(scanRoots(c.cfg))
	if len(projects) == 0 {
		return
	}
	// versiones instaladas
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
		out, _ := run(8*time.Second, "php", "-m")
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
	issue := func(sev, title, detail, fix string) {
		pi.Issues++
		c.add("Dependencias", sev, title+" — "+p, detail, fix)
	}
	switch {
	case exists(filepath.Join(p, "artisan")):
		pi.Framework = "Laravel"
		laravelWritable(c, p)
	case exists(filepath.Join(p, "wp-config.php")):
		pi.Framework = "WordPress"
	case exists(filepath.Join(p, "symfony.lock")):
		pi.Framework = "Symfony"
	case exists(filepath.Join(p, "next.config.js")) || exists(filepath.Join(p, "next.config.mjs")):
		pi.Framework = "Next.js"
	case exists(filepath.Join(p, "nuxt.config.ts")) || exists(filepath.Join(p, "nuxt.config.js")):
		pi.Framework = "Nuxt"
	}

	// ---------- PHP / Composer ----------
	if b, err := os.ReadFile(filepath.Join(p, "composer.json")); err == nil {
		var cj composerJSON
		if json.Unmarshal(b, &cj) != nil {
			issue("crit", "composer.json inválido (JSON mal formado)", "", "composer validate")
		} else {
			if req := cj.Require["php"]; req != "" {
				pi.PHPReq = req
				if phpOK && !satisfies(req, phpV) {
					issue("crit", fmt.Sprintf("Requiere PHP %s pero el servidor tiene %d.%d", req, phpV[0], phpV[1]),
						"composer install fallará o la app dará errores en runtime.", "Instala la versión de PHP requerida o ajusta la constraint de 'php' tras probar compatibilidad.")
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
				issue("crit", "Extensiones PHP faltantes: "+strings.Join(missing, ", "), "",
					"apt install "+strings.ReplaceAll(strings.Join(missing, " "), "ext-", "php-"))
			}
		}
		lock := filepath.Join(p, "composer.lock")
		li, lerr := os.Stat(lock)
		switch {
		case lerr != nil:
			issue("warn", "Sin composer.lock (versiones no reproducibles)", "", "composer install  (y versiona el lock)")
		default:
			if ji, _ := os.Stat(filepath.Join(p, "composer.json")); ji != nil && ji.ModTime().After(li.ModTime().Add(time.Minute)) {
				issue("warn", "composer.json es más nuevo que composer.lock", "El lock puede estar desactualizado.", "composer update --lock")
			}
			if !exists(filepath.Join(p, "vendor", "autoload.php")) {
				issue("crit", "Dependencias PHP sin instalar (vendor/ ausente)", "", "composer install --no-dev --optimize-autoloader")
			} else if have("composer") {
				if n, titles, ok := s.auditComposer(p, li); ok {
					pi.Vulns["composer"] = n
					if n > 0 {
						issue("crit", fmt.Sprintf("%d vulnerabilidades conocidas en dependencias Composer", n), strings.Join(titles, "\n"), "composer audit  ·  composer update <paquete>")
					}
				}
			}
		}
	}

	// ---------- Node / npm ----------
	if b, err := os.ReadFile(filepath.Join(p, "package.json")); err == nil {
		var pj packageJSON
		if json.Unmarshal(b, &pj) != nil {
			issue("crit", "package.json inválido (JSON mal formado)", "", "")
		} else if req := pj.Engines["node"]; req != "" {
			pi.NodeReq = req
			if nodeOK && !satisfies(req, nodeV) {
				issue("crit", fmt.Sprintf("Requiere Node %s pero el servidor tiene %d.%d", req, nodeV[0], nodeV[1]), "", "Usa nvm/n para instalar la versión requerida.")
			}
		}
		lock := filepath.Join(p, "package-lock.json")
		li, lerr := os.Stat(lock)
		hasLock := lerr == nil || exists(filepath.Join(p, "yarn.lock")) || exists(filepath.Join(p, "pnpm-lock.yaml"))
		if !hasLock {
			issue("info", "Sin lockfile de Node", "", "npm install  (y versiona package-lock.json)")
		}
		if hasLock && !exists(filepath.Join(p, "node_modules")) && !exists(filepath.Join(p, ".next")) && !exists(filepath.Join(p, "dist")) && !exists(filepath.Join(p, "build")) {
			issue("warn", "node_modules ausente (dependencias sin instalar)", "", "npm ci")
		}
		if lerr == nil && have("npm") {
			if v, ok := s.auditNPM(p, li); ok {
				for k, n := range v {
					pi.Vulns["npm_"+k] = n
				}
				tot := v["critical"] + v["high"] + v["moderate"] + v["low"]
				pi.Vulns["npm"] = tot
				if v["critical"]+v["high"] > 0 {
					issue("crit", fmt.Sprintf("npm audit: %d críticas, %d altas, %d moderadas", v["critical"], v["high"], v["moderate"]), "", "npm audit fix  ·  revisa cambios mayores con npm audit fix --force (con cuidado)")
				} else if tot > 0 {
					issue("warn", fmt.Sprintf("npm audit: %d moderadas, %d bajas", v["moderate"], v["low"]), "", "npm audit fix")
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
	out, _ := runStdout(40*time.Second, p, "composer", "audit", "--locked", "--format=json", "--no-interaction")
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
	out, _ := runStdout(45*time.Second, p, "npm", "audit", "--json", "--package-lock-only", "--no-fund", "--no-update-notifier")
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
