package scanner

import (
	"devdoctor/internal/config"
	"devdoctor/internal/sysinfo"
	"sort"
	"sync"
	"time"
)

type Finding struct {
	Category string `json:"category"`
	Severity string `json:"severity"` // crit, warn, info, ok
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
	Link     string `json:"link,omitempty"` // referencia externa (aviso oficial)

	t, d, f Msg // originales traducibles
}

type PortInfo struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
	Exposed bool   `json:"exposed"`
	Note    string `json:"note,omitempty"`

	noteM Msg
}

type ServiceInfo struct {
	Name    string `json:"name"`
	Active  string `json:"active"`
	Enabled string `json:"enabled"`
}

type CertInfo struct {
	Path       string    `json:"path"`
	Subject    string    `json:"subject"`
	DNS        []string  `json:"dns"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"not_after"`
	DaysLeft   int       `json:"days_left"`
	SelfSigned bool      `json:"self_signed"`
}

type VersionInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Status  string `json:"status"`
	Note    string `json:"note,omitempty"`

	noteM Msg
}

type ProjectInfo struct {
	Path      string         `json:"path"`
	Framework string         `json:"framework"`
	PHPReq    string         `json:"php_req,omitempty"`
	NodeReq   string         `json:"node_req,omitempty"`
	Vulns     map[string]int `json:"vulns,omitempty"` // composer / npm
	Issues    int            `json:"issues"`
}

type Attacker struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type Report struct {
	Started    time.Time       `json:"started"`
	DurationMs int64           `json:"duration_ms"`
	Score      int             `json:"score"`
	Counts     map[string]int  `json:"counts"`
	Findings   []Finding       `json:"findings"`
	Ports      []PortInfo      `json:"ports"`
	Services   []ServiceInfo   `json:"services"`
	Certs      []CertInfo      `json:"certs"`
	Versions   []VersionInfo   `json:"versions"`
	Projects   []ProjectInfo   `json:"projects"`
	Attackers  []Attacker      `json:"attackers"`
	ScanRoots  []string        `json:"scan_roots"`
	URLs       []URLCheck      `json:"urls"`
	Intel      *IntelInfo      `json:"intel"`
	Containers []ContainerInfo `json:"containers"`
}

type Collector struct {
	mu  sync.Mutex
	R   Report
	cfg config.Config
	sam *sysinfo.Sampler
}

// add registra un hallazgo. title/detail/fix pueden ser Msg o string (literal traducible).
func (c *Collector) add(cat, sev string, title, detail, fix any) {
	c.addL(cat, sev, title, detail, fix, "")
}

// addL es add con un enlace a la referencia oficial.
func (c *Collector) addL(cat, sev string, title, detail, fix any, link string) {
	t, d, f := msgOf(title), msgOf(detail), msgOf(fix)
	c.mu.Lock()
	c.R.Findings = append(c.R.Findings, Finding{Category: cat, Severity: sev, Title: t.Render("en"), Detail: d.Render("en"), Fix: f.Render("en"), t: t, d: d, f: f, Link: link})
	c.mu.Unlock()
}

// mkVer construye un VersionInfo con nota traducible.
func mkVer(name, version, status string, note Msg) VersionInfo {
	return VersionInfo{Name: name, Version: version, Status: status, Note: note.Render("en"), noteM: note}
}

type Scanner struct {
	mu      sync.RWMutex
	last    *Report
	running bool
	rerun   bool // se pidió otro escaneo mientras había uno en curso
	cfg     *config.Store
	OnDone  func(*Report) // se llama al terminar cada escaneo (p. ej. para enviar notificaciones)
	sam     *sysinfo.Sampler
	audits  sync.Map // caché de auditorías por proyecto
}

func (s *Scanner) Last() (*Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.last, s.running
}

// Start lanza un escaneo asíncrono. Si ya hay uno en curso devuelve false y encola otro al terminar,
// para que los cambios de configuración (carpetas, URLs) no se pierdan.
func (s *Scanner) Start() bool {
	s.mu.Lock()
	if s.running {
		s.rerun = true
		s.mu.Unlock()
		return false
	}
	s.running = true
	s.mu.Unlock()
	go func() {
		r := s.RunSync()
		s.mu.Lock()
		s.last, s.running = r, false
		again := s.rerun
		s.rerun = false
		s.mu.Unlock()
		if s.OnDone != nil {
			go func() { defer func() { recover() }(); s.OnDone(r) }()
		}
		if again {
			s.Start()
		}
	}()
	return true
}

var sevRank = map[string]int{"crit": 0, "warn": 1, "info": 2, "ok": 3}

func (s *Scanner) RunSync() *Report {
	s.cfg.Refresh() // recoge cambios hechos con "devdoctor paths" sin reiniciar
	c := &Collector{cfg: s.cfg.Get(), sam: s.sam}
	c.R.Started = time.Now()
	checks := []func(){
		func() { checkVersions(c) },
		func() { checkPortsServices(c) },
		func() { checkSSL(c) },
		func() { checkPermissions(c) },
		func() { checkProjects(c, s) },
		func() { checkSecurity(c) },
		func() { checkResources(c) },
		func() { checkURLs(c) },
		func() { checkDocker(c, s) },
	}
	var wg sync.WaitGroup
	for _, f := range checks {
		wg.Add(1)
		go func(f func()) {
			defer wg.Done()
			defer func() { recover() }()
			f()
		}(f)
	}
	wg.Wait()
	if !c.cfg.IntelDisabled {
		checkIntel(c, s) // necesita los resultados de los demás chequeos (versiones, proyectos)
	} else {
		c.R.Intel = &IntelInfo{Enabled: false}
	}

	r := &c.R
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		return a.Category < b.Category
	})
	r.Counts = map[string]int{}
	penalty := map[string]int{} // descuento acotado por categoría (máx. 35)
	for _, f := range r.Findings {
		r.Counts[f.Severity]++
		switch f.Severity {
		case "crit":
			penalty[f.Category] += 12
		case "warn":
			penalty[f.Category] += 4
		}
	}
	total := 0
	for _, p := range penalty {
		if p > 35 {
			p = 35
		}
		total += p
	}
	r.Score = int(100 / (1 + float64(total)/60)) // 0 puntos = 100, 60 = 50, nunca cae de golpe a 0
	sort.Slice(r.Ports, func(i, j int) bool { return r.Ports[i].Port < r.Ports[j].Port })
	sort.Slice(r.Certs, func(i, j int) bool { return r.Certs[i].DaysLeft < r.Certs[j].DaysLeft })
	r.DurationMs = time.Since(r.Started).Milliseconds()
	return r
}

// New crea un Scanner que lee su configuración del Store y recursos del Sampler.
func New(cs *config.Store, sam *sysinfo.Sampler) *Scanner { return &Scanner{cfg: cs, sam: sam} }

// Localize devuelve una copia del informe con los textos en el idioma pedido ("en" o "es").
func (r *Report) Localize(lang string) *Report {
	c := *r
	c.Findings = make([]Finding, len(r.Findings))
	for i, f := range r.Findings {
		f.Title, f.Detail, f.Fix = f.t.Render(lang), f.d.Render(lang), f.f.Render(lang)
		c.Findings[i] = f
	}
	c.Versions = localizeVersions(r.Versions, lang)
	c.Ports = make([]PortInfo, len(r.Ports))
	for i, p := range r.Ports {
		p.Note = p.noteM.Render(lang)
		c.Ports[i] = p
	}
	c.Containers = make([]ContainerInfo, len(r.Containers))
	for i, ct := range r.Containers {
		ct.Versions = localizeVersions(ct.Versions, lang)
		c.Containers[i] = ct
	}
	return &c
}

func localizeVersions(in []VersionInfo, lang string) []VersionInfo {
	out := make([]VersionInfo, len(in))
	for i, v := range in {
		v.Note = v.noteM.Render(lang)
		out[i] = v
	}
	return out
}
