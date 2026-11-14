package main

import (
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
}

type PortInfo struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
	Exposed bool   `json:"exposed"`
	Note    string `json:"note,omitempty"`
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
	Started    time.Time     `json:"started"`
	DurationMs int64         `json:"duration_ms"`
	Score      int           `json:"score"`
	Counts     map[string]int `json:"counts"`
	Findings   []Finding     `json:"findings"`
	Ports      []PortInfo    `json:"ports"`
	Services   []ServiceInfo `json:"services"`
	Certs      []CertInfo    `json:"certs"`
	Versions   []VersionInfo `json:"versions"`
	Projects   []ProjectInfo `json:"projects"`
	Attackers  []Attacker    `json:"attackers"`
}

type Collector struct {
	mu  sync.Mutex
	R   Report
	cfg Config
	sam *Sampler
}

func (c *Collector) add(cat, sev, title, detail, fix string) {
	c.mu.Lock()
	c.R.Findings = append(c.R.Findings, Finding{cat, sev, title, detail, fix})
	c.mu.Unlock()
}

type Scanner struct {
	mu      sync.RWMutex
	last    *Report
	running bool
	cfg     *ConfigStore
	sam     *Sampler
	audits  sync.Map // caché de auditorías por proyecto
}

func (s *Scanner) Last() (*Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.last, s.running
}

// Start lanza un escaneo asíncrono; devuelve false si ya hay uno en curso.
func (s *Scanner) Start() bool {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return false
	}
	s.running = true
	s.mu.Unlock()
	go func() {
		r := s.RunSync()
		s.mu.Lock()
		s.last, s.running = r, false
		s.mu.Unlock()
	}()
	return true
}

var sevRank = map[string]int{"crit": 0, "warn": 1, "info": 2, "ok": 3}

func (s *Scanner) RunSync() *Report {
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

	r := &c.R
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		return a.Category < b.Category
	})
	r.Counts = map[string]int{}
	score := 100
	for _, f := range r.Findings {
		r.Counts[f.Severity]++
		switch f.Severity {
		case "crit":
			score -= 12
		case "warn":
			score -= 4
		}
	}
	if score < 0 {
		score = 0
	}
	r.Score = score
	sort.Slice(r.Ports, func(i, j int) bool { return r.Ports[i].Port < r.Ports[j].Port })
	sort.Slice(r.Certs, func(i, j int) bool { return r.Certs[i].DaysLeft < r.Certs[j].DaysLeft })
	r.DurationMs = time.Since(r.Started).Milliseconds()
	return r
}
