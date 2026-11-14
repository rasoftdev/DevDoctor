package scanner

import (
	"sort"
	"time"

	"devdoctor/internal/intel"
)

// IntelResult es el resultado de la última consulta a las fuentes públicas de seguridad.
// Se guarda aparte del informe del servidor: no entra en los hallazgos ni en la puntuación.
type IntelResult struct {
	Findings []Finding
	Info     IntelInfo
}

// IntelOut es lo que ve el dashboard.
type IntelOut struct {
	Enabled   bool           `json:"enabled"`
	Running   bool           `json:"running"`
	CheckedAt *time.Time     `json:"checked_at,omitempty"`
	Sources   []intel.Status `json:"sources"`
	Counts    map[string]int `json:"counts"`
	Findings  []Finding      `json:"findings"`
}

func (s *Scanner) intelInterval() time.Duration {
	if h := s.cfg.Get().IntelIntervalHours; h > 0 {
		return time.Duration(h) * time.Hour
	}
	return 24 * time.Hour
}

// IntelView devuelve las alertas de las fuentes de seguridad en el idioma pedido.
func (s *Scanner) IntelView(lang string) IntelOut {
	cfg := s.cfg.Get()
	s.mu.RLock()
	last, running := s.intelLast, s.intelRunning
	s.mu.RUnlock()
	out := IntelOut{Enabled: !cfg.IntelDisabled, Running: running, Sources: []intel.Status{}, Counts: map[string]int{}, Findings: []Finding{}}
	if last == nil {
		return out
	}
	t := last.Info.CheckedAt
	out.CheckedAt = &t
	out.Sources = last.Info.Sources
	for _, f := range last.Findings {
		f.Title, f.Detail, f.Fix = f.t.Render(lang), f.d.Render(lang), f.f.Render(lang)
		out.Findings = append(out.Findings, f)
		out.Counts[f.Severity]++
	}
	return out
}

// StartIntel lanza la consulta a las fuentes de seguridad en segundo plano, sin tocar el escaneo general.
// Devuelve false si ya hay una en curso o todavía no hay un informe del servidor del que partir.
func (s *Scanner) StartIntel() bool {
	s.mu.Lock()
	if s.intelRunning || s.last == nil || s.cfg.Get().IntelDisabled {
		s.mu.Unlock()
		return false
	}
	s.intelRunning = true
	base := s.last
	s.mu.Unlock()
	go func() {
		defer func() {
			if recover() != nil {
				s.mu.Lock()
				s.intelRunning = false
				s.mu.Unlock()
			}
		}()
		res := s.RunIntel(base)
		s.mu.Lock()
		s.intelLast, s.intelRunning = res, false
		last := s.last
		s.mu.Unlock()
		if last != nil {
			s.notifyDone(last)
		}
	}()
	return true
}

// maybeAutoIntel hace la consulta diaria automática (se comprueba tras cada escaneo general).
func (s *Scanner) maybeAutoIntel() {
	if s.cfg.Get().IntelDisabled {
		return
	}
	s.mu.RLock()
	last, running := s.intelLast, s.intelRunning
	s.mu.RUnlock()
	if running {
		return
	}
	if last == nil || time.Since(last.Info.CheckedAt) > s.intelInterval() {
		s.StartIntel()
	}
}

// RunIntel cruza el software y los proyectos del último informe con las fuentes públicas de seguridad.
func (s *Scanner) RunIntel(base *Report) *IntelResult {
	c := &Collector{cfg: s.cfg.Get(), sam: s.sam}
	c.R.Versions = append([]VersionInfo(nil), base.Versions...)
	for _, p := range base.Projects { // copia profunda: las comprobaciones de dependencias anotan los mapas
		q := p
		if p.Vulns != nil {
			q.Vulns = map[string]int{}
			for k, v := range p.Vulns {
				q.Vulns[k] = v
			}
		}
		c.R.Projects = append(c.R.Projects, q)
	}
	info := runIntel(c, s)
	fs := c.R.Findings
	sort.SliceStable(fs, func(i, j int) bool { return sevRank[fs[i].Severity] < sevRank[fs[j].Severity] })
	return &IntelResult{Findings: fs, Info: info}
}

// notifyDone avisa al notificador con el informe del servidor y las alertas de seguridad juntos
// (el dashboard las muestra por separado, pero los avisos a Telegram/Slack cubren ambas).
func (s *Scanner) notifyDone(base *Report) {
	if s.OnDone == nil || base == nil {
		return
	}
	cp := *base
	cp.Findings = append([]Finding(nil), base.Findings...)
	s.mu.RLock()
	last := s.intelLast
	s.mu.RUnlock()
	if last != nil {
		cp.Findings = append(cp.Findings, last.Findings...)
		info := last.Info
		cp.Intel = &info
	}
	cp.Counts = map[string]int{}
	for _, f := range cp.Findings {
		cp.Counts[f.Severity]++
	}
	go func() {
		defer func() { recover() }()
		s.OnDone(&cp)
	}()
}
