package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"devdoctor/internal/config"
	"devdoctor/internal/intel"
	"devdoctor/internal/sh"
	"devdoctor/internal/version"
)

// IntelInfo resume el estado de las consultas a fuentes públicas de seguridad.
type IntelInfo struct {
	Enabled   bool           `json:"enabled"`
	Sources   []intel.Status `json:"sources"`
	CheckedAt time.Time      `json:"checked_at"`
}

type osRelease struct{ ID, VersionID, Codename, Pretty string }

func readOSRelease() osRelease {
	var o osRelease
	for _, l := range strings.Split(sh.ReadFile("/etc/os-release"), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			o.ID = v
		case "VERSION_ID":
			o.VersionID = v
		case "VERSION_CODENAME":
			o.Codename = v
		case "PRETTY_NAME":
			o.Pretty = v
		}
	}
	return o
}

// inst es un programa instalado en el servidor (no en contenedores).
type inst struct {
	Name, Version, Bin string
	Managed            bool   // lo instaló el gestor de paquetes de la distribución
	Pkg                string // paquete de la distribución (si Managed)
}

var binFor = map[string]string{
	"Node.js": "node", "Nginx": "nginx", "Apache": "apache2", "Apache (httpd)": "httpd", "MySQL": "mysql", "MariaDB": "mysql",
	"PostgreSQL": "psql", "Redis": "redis-server", "Python": "python3", "Git": "git", "OpenSSL": "openssl", "OpenSSH": "ssh", "sudo": "sudo",
}

// distroPkg indica si un binario pertenece a un paquete de la distribución (dpkg/rpm).
func distroPkg(bin string) (string, bool) {
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", false
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	if sh.Have("dpkg") {
		if out, err := sh.Run(5*time.Second, "dpkg", "-S", p); err == nil {
			if pkg, _, ok := strings.Cut(strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]), ":"); ok {
				return strings.TrimSpace(strings.Split(pkg, ",")[0]), true
			}
		}
	} else if sh.Have("rpm") {
		if out, err := sh.Run(5*time.Second, "rpm", "-qf", p, "--qf", "%{NAME}"); err == nil && !strings.Contains(out, "not owned") {
			return strings.TrimSpace(out), true
		}
	}
	return "", false
}

// thirdPartyRepo detecta paquetes que vienen de repositorios de terceros (PPA de PHP, NodeSource...).
func thirdPartyRepo(pkg string) bool {
	out, err := sh.Run(5*time.Second, "dpkg-query", "-W", "-f=${Version}", pkg)
	if err != nil {
		return false
	}
	v := strings.ToLower(out)
	for _, m := range []string{"sury", "ppa", "nodesource", "deb.sury.org", "mariadb.org", "percona", "docker", "pgdg"} {
		if strings.Contains(v, m) {
			return true
		}
	}
	return false
}

func installedSoftware(c *Collector) []inst {
	c.mu.Lock()
	vs := append([]VersionInfo(nil), c.R.Versions...)
	c.mu.Unlock()
	var out []inst
	for _, v := range vs {
		bin := binFor[v.Name]
		switch {
		case v.Name == "PHP":
			bin = "php"
		case strings.HasPrefix(v.Name, "PHP ("):
			bin = strings.Trim(strings.TrimPrefix(v.Name, "PHP ("), ")")
		}
		if bin == "" {
			continue
		}
		i := inst{Name: v.Name, Version: v.Version, Bin: bin}
		i.Pkg, i.Managed = distroPkg(bin)
		if i.Managed && thirdPartyRepo(i.Pkg) {
			i.Managed = false // PPA/NodeSource/sury...: siguen la versión upstream, no hay backports de la distro
		}
		out = append(out, i)
	}
	return out
}

func runIntel(c *Collector, s *Scanner) IntelInfo {
	dir := ""
	if p := s.cfg.Path(); p != "" {
		dir = filepath.Join(filepath.Dir(p), "cache")
	}
	cl := intel.New(dir, "DevDoctor/"+version.Version+" (security feeds)", c.cfg.NVDAPIKey)
	sw := installedSoftware(c)
	osr := readOSRelease()

	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { recover() }()
			f()
		}()
	}
	run(func() { intelPHP(c, cl, sw) })
	run(func() { intelNode(c, cl, sw) })
	run(func() { intelEOL(c, cl, sw, osr) })
	run(func() { intelKEV(c, cl, sw) })
	run(func() { intelOSV(c, cl) })
	run(func() { intelNVD(c, cl, sw) })
	run(func() { intelUbuntu(c, cl, sw, osr) })
	run(func() { intelGH(c, cl, sw) })
	wg.Wait()

	return IntelInfo{Enabled: true, Sources: cl.Statuses(), CheckedAt: time.Now()}
}

// ---------------------------------------------------------------- PHP / Node: versiones de seguridad

func dateOnly(s string) string {
	if len(s) >= 10 && s[4] == '-' {
		return s[:10]
	}
	return s
}

func releaseList(rs []intel.Release) string {
	var p []string
	for i, r := range rs {
		if i == 4 {
			p = append(p, fmt.Sprintf("+%d", len(rs)-4))
			break
		}
		p = append(p, strings.TrimPrefix(r.Version, "v"))
	}
	return strings.Join(p, ", ")
}

func intelPHP(c *Collector, cl *intel.Client, sw []inst) {
	for _, s := range sw {
		if !strings.HasPrefix(s.Name, "PHP") {
			continue
		}
		pv, _ := parseVer(s.Version)
		branch := fmt.Sprintf("%d.%d", pv[0], pv[1])
		rels, err := cl.PHPReleases(branch)
		if err != nil || len(rels) == 0 {
			continue
		}
		latest := rels[0]
		if intel.CompareVersions(s.Version, latest.Version) >= 0 {
			continue
		}
		var missed []intel.Release
		for _, r := range rels {
			if r.Security && intel.CompareVersions(r.Version, s.Version) > 0 {
				missed = append(missed, r)
			}
		}
		if len(missed) == 0 {
			c.addL("Advisories", "info", M("%s %s: a newer patch release %s is available", s.Name, s.Version, latest.Version), "",
				"Update to the latest patch release to get the fixes and improvements.", "https://www.php.net/releases/")
			continue
		}
		sev := "crit"
		var detail Msg
		if s.Managed {
			sev = "info" // los paquetes de la distribución suelen traer los parches con otra numeración
			detail = M("Installed from your distribution package (%s), which usually backports security fixes without changing the version number. Run apt update && apt upgrade to get them.", s.Pkg)
		} else {
			detail = M("Your PHP branch %s has %d security release(s) you are missing: %s", branch, len(missed), releaseList(missed))
		}
		c.addL("Advisories", sev, M("%s %s: security release %s is available (%s)", s.Name, s.Version, latest.Version, dateOnly(latest.Date)), detail,
			M("Update PHP to %s (your package manager or the vendor repository, e.g. ondrej/php).", latest.Version), "https://www.php.net/releases/")
	}
}

func intelNode(c *Collector, cl *intel.Client, sw []inst) {
	for _, s := range sw {
		if s.Name != "Node.js" {
			continue
		}
		pv, _ := parseVer(s.Version)
		rels, err := cl.NodeReleases()
		if err != nil {
			return
		}
		prefix := fmt.Sprintf("v%d.", pv[0])
		var line []intel.Release
		for _, r := range rels {
			if strings.HasPrefix(r.Version, prefix) {
				line = append(line, r)
			}
		}
		if len(line) == 0 {
			return
		}
		latest := line[0] // el índice de nodejs.org viene de más nuevo a más viejo
		if intel.CompareVersions(s.Version, latest.Version) >= 0 {
			return
		}
		var missed []intel.Release
		for _, r := range line {
			if r.Security && intel.CompareVersions(r.Version, s.Version) > 0 {
				missed = append(missed, r)
			}
		}
		lv := strings.TrimPrefix(latest.Version, "v")
		if len(missed) == 0 {
			c.addL("Advisories", "info", M("%s %s: a newer patch release %s is available", s.Name, s.Version, lv), "",
				"Update to the latest patch release to get the fixes and improvements.", "https://nodejs.org/en/blog/vulnerability")
			return
		}
		sev := "crit"
		var detail Msg
		if s.Managed {
			sev = "info"
			detail = M("Installed from your distribution package (%s), which usually backports security fixes without changing the version number. Run apt update && apt upgrade to get them.", s.Pkg)
		} else {
			detail = M("Your Node.js line %d has %d security release(s) you are missing: %s", pv[0], len(missed), releaseList(missed))
		}
		c.addL("Advisories", sev, M("%s %s: security release %s is available (%s)", s.Name, s.Version, lv, latest.Date), detail,
			M("Update Node.js to %s (nvm install %s, or your package source).", lv, lv), "https://nodejs.org/en/blog/vulnerability")
		return
	}
}

// ---------------------------------------------------------------- endoflife.date

func cycleOf(name, ver string) (slug, cycle string) {
	pv, _ := parseVer(ver)
	mm := fmt.Sprintf("%d.%d", pv[0], pv[1])
	switch {
	case strings.HasPrefix(name, "PHP"):
		return "php", mm
	case name == "Node.js":
		return "nodejs", strconv.Itoa(pv[0])
	case name == "Nginx":
		return "nginx", mm
	case name == "Apache" || name == "Apache (httpd)":
		return "apache-http-server", mm
	case name == "MySQL":
		return "mysql", mm
	case name == "MariaDB":
		return "mariadb", mm
	case name == "PostgreSQL":
		return "postgresql", strconv.Itoa(pv[0])
	case name == "Redis":
		return "redis", mm
	case name == "Python":
		return "python", mm
	case name == "OpenSSL":
		return "openssl", mm
	}
	return "", ""
}

func findCycle(cs []intel.EOLCycle, want string) *intel.EOLCycle {
	for i := range cs {
		if cs[i].Cycle == want {
			return &cs[i]
		}
	}
	if major, _, ok := strings.Cut(want, "."); ok {
		for i := range cs {
			if cs[i].Cycle == major {
				return &cs[i]
			}
		}
	}
	return nil
}

func parseDay(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", s)
	return t, err == nil
}

func intelEOL(c *Collector, cl *intel.Client, sw []inst, osr osRelease) {
	cache := map[string][]intel.EOLCycle{}
	get := func(slug string) []intel.EOLCycle {
		if v, ok := cache[slug]; ok {
			return v
		}
		cs, _ := cl.EOL(slug)
		cache[slug] = cs
		return cs
	}

	// 1) Tablas de PHP y Node siempre al día (las usa la comprobación de versiones).
	phpT, nodeT := map[string]time.Time{}, map[int]time.Time{}
	for _, cy := range get("php") {
		if t, ok := parseDay(cy.EOL); ok {
			phpT[cy.Cycle] = t
		}
	}
	for _, cy := range get("nodejs") {
		if t, ok := parseDay(cy.EOL); ok {
			if n, err := strconv.Atoi(cy.Cycle); err == nil {
				nodeT[n] = t
			}
		}
	}
	if len(phpT) > 0 || len(nodeT) > 0 {
		setEOLTables(phpT, nodeT)
	}

	// 2) Resto del software instalado (PHP y Node ya los cubre la comprobación de versiones).
	seen := map[string]bool{}
	for _, s := range sw {
		slug, want := cycleOf(s.Name, s.Version)
		if slug == "" || slug == "php" || slug == "nodejs" || seen[slug+want] {
			continue
		}
		seen[slug+want] = true
		cy := findCycle(get(slug), want)
		if cy == nil {
			continue
		}
		eol, ok := parseDay(cy.EOL)
		if !ok {
			continue
		}
		days := int(time.Until(eol).Hours() / 24)
		link := "https://endoflife.date/" + slug
		switch {
		case days < 0:
			sev := "crit"
			var detail Msg
			if s.Managed {
				sev = "warn"
				detail = M("Installed from your distribution package: it may still receive backported security fixes until the distribution itself reaches end of life.")
			}
			c.addL("Advisories", sev, M("%s %s reached end of life on %s", s.Name, s.Version, cy.EOL), detail, "Upgrade to a supported release.", link)
		case days < 180:
			c.addL("Advisories", "warn", M("%s %s reaches end of life in %d days (%s)", s.Name, s.Version, days, cy.EOL), "", "Upgrade to a supported release.", link)
		}
	}

	// 3) El sistema operativo.
	slug := map[string]string{"ubuntu": "ubuntu", "debian": "debian", "rhel": "rhel", "almalinux": "almalinux", "rocky": "rocky-linux", "centos": "centos", "fedora": "fedora", "amzn": "amazon-linux"}[osr.ID]
	if slug == "" || osr.VersionID == "" {
		return
	}
	want := osr.VersionID
	if slug != "ubuntu" && slug != "amazon-linux" {
		want, _, _ = strings.Cut(osr.VersionID, ".")
	}
	cy := findCycle(get(slug), want)
	if cy == nil {
		return
	}
	eol, ok := parseDay(cy.EOL)
	if !ok {
		return
	}
	days := int(time.Until(eol).Hours() / 24)
	link := "https://endoflife.date/" + slug
	name := osr.Pretty
	if name == "" {
		name = osr.ID + " " + osr.VersionID
	}
	switch {
	case days < 0:
		if ext, ok := parseDay(cy.Extended); ok && time.Until(ext) > 0 {
			c.addL("Advisories", "info", M("%s is in extended security maintenance until %s", name, cy.Extended), "",
				"Upgrade the operating system to a supported release (do-release-upgrade on Ubuntu) or enable extended security maintenance.", link)
		} else {
			c.addL("Advisories", "crit", M("The operating system %s reached end of life on %s", name, cy.EOL), "",
				"Upgrade the operating system to a supported release (do-release-upgrade on Ubuntu) or enable extended security maintenance.", link)
		}
	case days < 180:
		c.addL("Advisories", "warn", M("The operating system %s reaches end of life in %d days (%s)", name, days, cy.EOL), "",
			"Upgrade the operating system to a supported release (do-release-upgrade on Ubuntu) or enable extended security maintenance.", link)
	}
}

// ---------------------------------------------------------------- CISA KEV

var kevWords = map[string][]string{
	"PHP": {"php"}, "Node.js": {"node.js"}, "Nginx": {"nginx"}, "Apache": {"http server"}, "Apache (httpd)": {"http server"},
	"MySQL": {"mysql"}, "MariaDB": {"mariadb"}, "PostgreSQL": {"postgresql"}, "Redis": {"redis"}, "OpenSSL": {"openssl"},
	"Python": {"python"}, "Git": {"git"}, "OpenSSH": {"openssh"}, "sudo": {"sudo"},
}

func intelKEV(c *Collector, cl *intel.Client, sw []inst) {
	list, err := cl.KEV()
	if err != nil {
		return
	}
	// producto -> palabras clave
	type prod struct {
		name  string
		words []*regexp.Regexp
	}
	var prods []prod
	seen := map[string]bool{}
	add := func(name string, words []string) {
		if seen[name] {
			return
		}
		seen[name] = true
		p := prod{name: name}
		for _, w := range words {
			p.words = append(p.words, regexp.MustCompile(`\b`+regexp.QuoteMeta(w)+`\b`))
		}
		prods = append(prods, p)
	}
	for _, s := range sw {
		if w, ok := kevWords[s.Name]; ok {
			n := strings.SplitN(s.Name, " (", 2)[0]
			add(n, w)
		}
	}
	add("Linux kernel", []string{"linux kernel"})
	cut := time.Now().AddDate(0, 0, -120)
	for _, p := range prods {
		var hits []intel.KEV
		for _, k := range list {
			t, ok := parseDay(k.Added)
			if !ok || t.Before(cut) {
				continue
			}
			hay := strings.ToLower(k.Vendor + " " + k.Product)
			for _, re := range p.words {
				if re.MatchString(hay) {
					hits = append(hits, k)
					break
				}
			}
		}
		if len(hits) == 0 {
			continue
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].Added > hits[j].Added })
		var lines []string
		for i, k := range hits {
			if i == 3 {
				lines = append(lines, fmt.Sprintf("+%d", len(hits)-3))
				break
			}
			ran := ""
			if k.Ransomware == "Known" {
				ran = " [ransomware]"
			}
			lines = append(lines, fmt.Sprintf("%s — %s (%s)%s", k.CVE, k.Name, k.Added, ran))
		}
		c.addL("Advisories", "warn", M("Actively exploited vulnerabilities (CISA KEV) recently added for %s", p.name),
			M("%s\nThe catalog does not say which versions are affected: verify that your version is patched.", strings.Join(lines, "\n")),
			M("Check the vendor advisory for each CVE and update %s to a patched version (apt update && apt upgrade).", p.name),
			"https://nvd.nist.gov/vuln/detail/"+hits[0].CVE)
	}
}

// ---------------------------------------------------------------- OSV.dev (dependencias sin composer/npm audit)

type lockPkg struct{ name, ver string }

func parseComposerLock(path string) []lockPkg {
	var lock struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out []lockPkg
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		if p.Name != "" && p.Version != "" {
			out = append(out, lockPkg{p.Name, strings.TrimPrefix(p.Version, "v")})
		}
	}
	return out
}

func parseNPMLock(path string) []lockPkg {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &lock) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []lockPkg
	add := func(n, v string) {
		if n != "" && v != "" && !seen[n+"@"+v] {
			seen[n+"@"+v] = true
			out = append(out, lockPkg{n, v})
		}
	}
	if len(lock.Packages) > 0 {
		for k, p := range lock.Packages {
			if k == "" || p.Link {
				continue
			}
			if i := strings.LastIndex(k, "node_modules/"); i >= 0 {
				add(k[i+len("node_modules/"):], p.Version)
			}
		}
	} else {
		for n, d := range lock.Dependencies {
			add(n, d.Version)
		}
	}
	return out
}

func intelOSV(c *Collector, cl *intel.Client) {
	c.mu.Lock()
	projects := append([]ProjectInfo(nil), c.R.Projects...)
	c.mu.Unlock()

	for _, p := range projects {
		for _, eco := range []struct{ tool, lock, ecosystem string }{{"composer", "composer.lock", "Packagist"}, {"npm", "package-lock.json", "npm"}} {
			if _, audited := p.Vulns[eco.tool]; audited {
				continue // ya lo auditó composer/npm
			}
			path := filepath.Join(p.Path, eco.lock)
			var pkgs []lockPkg
			if eco.tool == "composer" {
				pkgs = parseComposerLock(path)
			} else {
				pkgs = parseNPMLock(path)
			}
			if len(pkgs) == 0 {
				continue
			}
			if len(pkgs) > 1500 {
				pkgs = pkgs[:1500]
			}
			qs := make([]intel.OSVQuery, len(pkgs))
			for i, k := range pkgs {
				qs[i] = intel.OSVQuery{Ecosystem: eco.ecosystem, Name: k.name, Version: k.ver}
			}
			res, err := cl.OSVBatch(qs)
			if err != nil {
				return
			}
			n, shown := 0, 0
			var lines []string
			high := false
			for i, ids := range res {
				if len(ids) == 0 {
					continue
				}
				n += len(ids)
				if shown < 6 {
					d, _ := cl.OSVVuln(ids[0])
					shown++
					lines = append(lines, fmt.Sprintf("%s — %s (%s)", pkgs[i].name, strings.TrimSpace(d.Summary), ids[0]))
					if d.Severity == "CRITICAL" || d.Severity == "HIGH" {
						high = true
					}
				}
			}
			c.mu.Lock()
			for i := range c.R.Projects {
				if c.R.Projects[i].Path == p.Path {
					if c.R.Projects[i].Vulns == nil {
						c.R.Projects[i].Vulns = map[string]int{}
					}
					c.R.Projects[i].Vulns[eco.tool] = n
					if n > 0 {
						c.R.Projects[i].Issues++
					}
				}
			}
			c.mu.Unlock()
			if n == 0 {
				continue
			}
			sev := "warn"
			if high {
				sev = "crit"
			}
			var title Msg
			if eco.tool == "composer" {
				title = M("%d known vulnerabilities in Composer dependencies", n)
			} else {
				title = M("%d known vulnerabilities in npm dependencies", n)
			}
			c.addL("Dependencies", sev, M("%s — %s", title, p.Path), strings.Join(lines, "\n"),
				"Update the affected packages and rebuild (composer update <package> / npm update <package>).", "https://osv.dev/list?ecosystem="+eco.ecosystem)
		}
	}
}

// ---------------------------------------------------------------- NVD (CVE por producto y versión exacta)

func cpeFor(name, ver string) string {
	vendor, product := "", ""
	switch {
	case strings.HasPrefix(name, "PHP"):
		vendor, product = "php", "php"
	case name == "Node.js":
		vendor, product = "nodejs", "node.js"
	case name == "Nginx":
		vendor, product = "f5", "nginx"
	case name == "Apache" || name == "Apache (httpd)":
		vendor, product = "apache", "http_server"
	case name == "MySQL":
		vendor, product = "oracle", "mysql"
	case name == "MariaDB":
		vendor, product = "mariadb", "mariadb"
	case name == "PostgreSQL":
		vendor, product = "postgresql", "postgresql"
	case name == "Redis":
		vendor, product = "redis", "redis"
	case name == "OpenSSL":
		vendor, product = "openssl", "openssl"
	case name == "Python":
		vendor, product = "python", "python"
	case name == "Git":
		vendor, product = "git-scm", "git"
	case name == "OpenSSH":
		vendor, product = "openbsd", "openssh"
	case name == "sudo":
		vendor, product = "sudo_project", "sudo"
	default:
		return ""
	}
	update := "*"
	if m := regexp.MustCompile(`^(\d+(?:\.\d+)*)(p\d+)$`).FindStringSubmatch(ver); m != nil { // 9.6p1 -> 9.6 + p1
		ver, update = m[1], m[2]
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:%s:*:*:*:*:*:*", vendor, product, ver, update)
}

func intelNVD(c *Collector, cl *intel.Client, sw []inst) {
	done := map[string]bool{}
	n := 0
	for _, s := range sw {
		cpe := cpeFor(s.Name, s.Version)
		if cpe == "" || done[cpe] || n >= 6 || s.Managed { // el software de la distro se cubre con su propio rastreador (Ubuntu)
			continue
		}
		done[cpe] = true
		n++
		res, err := cl.NVD(cpe)
		if err != nil {
			continue
		}
		if res.Total == 0 && strings.Contains(cpe, ":f5:nginx:") { // NVD aún usa el vendor antiguo en algunas CVE de nginx
			if r2, err := cl.NVD(strings.Replace(cpe, ":f5:nginx:", ":nginx:nginx:", 1)); err == nil {
				res = r2
			}
		}
		var crit, high int
		var top []intel.NVDCVE
		for _, cv := range res.CVEs {
			switch cv.Severity {
			case "CRITICAL":
				crit++
			case "HIGH":
				high++
			default:
				continue
			}
			if len(top) < 3 {
				top = append(top, cv)
			}
		}
		if crit+high == 0 {
			continue
		}
		var lines []string
		for _, cv := range top {
			lines = append(lines, fmt.Sprintf("%s (%s %.1f, %s)", cv.ID, cv.Severity, cv.Score, dateOnly(cv.Published)))
		}
		list := strings.Join(lines, "\n")
		sev := "warn"
		if crit > 0 {
			sev = "crit"
		}
		var detail Msg = Msg{Tpl: list}
		fix := M("Upgrade %s to the latest patched release.", s.Name)
		if s.Managed {
			sev = "info" // los paquetes de la distribución llevan parches con la misma numeración de versión
			detail = M("%s\nThis software comes from your distribution package, which usually backports security fixes without changing the version number, so some of these may already be fixed. Check your distribution's security tracker.", list)
			fix = M("apt update && apt upgrade")
		}
		c.addL("Advisories", sev, M("%s %s: %d known HIGH/CRITICAL CVEs match this exact version (%d critical)", s.Name, s.Version, crit+high, crit),
			detail, fix, "https://nvd.nist.gov/vuln/detail/"+top[0].ID)
	}
}

// ---------------------------------------------------------------- Ubuntu Security (teniendo en cuenta backports)

func debSource(pkg string) string {
	if out, err := sh.Run(5*time.Second, "dpkg-query", "-W", "-f=${source:Package}", pkg); err == nil && strings.TrimSpace(out) != "" {
		return strings.TrimSpace(out)
	}
	return pkg
}

func intelUbuntu(c *Collector, cl *intel.Client, sw []inst, osr osRelease) {
	if osr.ID != "ubuntu" || osr.Codename == "" || !sh.Have("dpkg-query") {
		return
	}
	done := map[string]bool{}
	for _, s := range sw {
		if !s.Managed || s.Pkg == "" {
			continue
		}
		src := debSource(s.Pkg)
		if done[src] || len(done) >= 8 {
			continue
		}
		done[src] = true
		cves, total, err := cl.UbuntuUnpatched(src, osr.Codename)
		if err != nil || len(cves) == 0 {
			continue
		}
		var hi, crit int
		for _, v := range cves {
			switch v.Priority {
			case "critical":
				crit++
			case "high":
				hi++
			}
		}
		sort.SliceStable(cves, func(i, j int) bool { return cves[i].CVSS > cves[j].CVSS })
		var lines []string
		for i, v := range cves {
			if i == 3 {
				break
			}
			lines = append(lines, fmt.Sprintf("%s (%s)", v.ID, v.Priority))
		}
		sev := "info"
		if crit > 0 {
			sev = "crit"
		} else if hi > 0 {
			sev = "warn"
		}
		c.addL("Advisories", sev, M("Ubuntu has %d unpatched CVEs for %s (%d high or critical)", total, src, hi+crit), strings.Join(lines, "\n"),
			"No fixed package is available yet: apply the mitigations from the Ubuntu CVE page and keep the system updated (apt update && apt upgrade).",
			"https://ubuntu.com/security/"+cves[0].ID)
	}
}

// ---------------------------------------------------------------- GitHub Security Advisories de PHP

func intelGH(c *Collector, cl *intel.Client, sw []inst) {
	var phps []inst
	for _, s := range sw {
		if strings.HasPrefix(s.Name, "PHP") {
			phps = append(phps, s)
		}
	}
	if len(phps) == 0 {
		return
	}
	advs, err := cl.PHPAdvisories()
	if err != nil {
		return
	}
	cut := time.Now().AddDate(0, 0, -150)
	for _, s := range phps {
		pv, _ := parseVer(s.Version)
		var hits []intel.GHSA
		worst := 3 // 0 crítica, 1 alta, 2 media, 3 baja
		for _, a := range advs {
			if t, err := time.Parse(time.RFC3339, a.Published); err != nil || t.Before(cut) {
				continue
			}
			for _, r := range a.Ranges {
				if r.Range != "" && satisfies(r.Range, pv) {
					hits = append(hits, a)
					if rk := map[string]int{"critical": 0, "high": 1, "medium": 2}[a.Severity]; a.Severity != "low" && rk < worst {
						worst = rk
					}
					break
				}
			}
		}
		if len(hits) == 0 {
			continue
		}
		sev := "warn"
		switch {
		case worst <= 1 && !s.Managed:
			sev = "crit"
		case worst == 3:
			sev = "info"
		}
		var lines []string
		for i, a := range hits {
			if i == 5 {
				lines = append(lines, fmt.Sprintf("+%d", len(hits)-5))
				break
			}
			id := a.CVE
			if id == "" {
				id = a.ID
			}
			lines = append(lines, fmt.Sprintf("%s (%s) — %s", id, a.Severity, a.Summary))
		}
		c.addL("Advisories", sev, M("%d recent PHP security advisories affect your %s %s", len(hits), s.Name, s.Version), strings.Join(lines, "\n"),
			"Update PHP to the latest patch release of your branch (see the PHP releases page).", "https://github.com/php/php-src/security/advisories")
	}
}

var _ = config.Config{}
