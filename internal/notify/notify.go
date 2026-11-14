// Package notify envía avisos a Telegram y Slack cuando un escaneo detecta problemas nuevos.
package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"devdoctor/internal/config"
	"devdoctor/internal/scanner"
)

// Result es el resultado de enviar a un canal.
type Result struct {
	Channel string `json:"channel"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

var httpc = &http.Client{Timeout: 15 * time.Second}

func telegramAPI() string {
	if v := os.Getenv("DEVDOCTOR_TELEGRAM_API"); v != "" { // sólo para pruebas
		return strings.TrimRight(v, "/")
	}
	return "https://api.telegram.org"
}

// scrub quita secretos de los mensajes de error (la URL de Telegram contiene el token).
func scrub(err error, secrets ...string) string {
	s := err.Error()
	for _, x := range secrets {
		if x != "" {
			s = strings.ReplaceAll(s, x, "***")
		}
	}
	return s
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func sendTelegram(n config.NotifyConfig, html string) error {
	if len(html) > 3900 {
		html = html[:3900] + "…"
	}
	body, _ := json.Marshal(map[string]any{"chat_id": n.TelegramChatID, "text": html, "parse_mode": "HTML", "disable_web_page_preview": true})
	resp, err := httpc.Post(telegramAPI()+"/bot"+n.TelegramToken+"/sendMessage", "application/json", bytes.NewReader(body))
	if err != nil {
		return errors.New(scrub(err, n.TelegramToken))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	json.Unmarshal(b, &r)
	if resp.StatusCode != 200 || !r.OK {
		if r.Description == "" {
			r.Description = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return errors.New(r.Description)
	}
	return nil
}

func sendSlack(n config.NotifyConfig, text string) error {
	if len(text) > 3500 {
		text = text[:3500] + "…"
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	resp, err := httpc.Post(n.SlackWebhook, "application/json", bytes.NewReader(body))
	if err != nil {
		return errors.New(scrub(err, n.SlackWebhook))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// doc es un mensaje independiente del canal; se pinta con el formato de cada uno.
type doc struct {
	Title string
	Lines []string
}

func (d doc) telegram() string {
	var b strings.Builder
	b.WriteString("<b>" + esc(d.Title) + "</b>")
	for _, l := range d.Lines {
		b.WriteString("\n" + esc(l))
	}
	return b.String()
}

func (d doc) slack() string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	var b strings.Builder
	b.WriteString("*" + r.Replace(d.Title) + "*")
	for _, l := range d.Lines {
		b.WriteString("\n" + r.Replace(l))
	}
	return b.String()
}

func send(n config.NotifyConfig, d doc) []Result {
	var out []Result
	if n.TelegramEnabled() {
		r := Result{Channel: "telegram", OK: true}
		if err := sendTelegram(n, d.telegram()); err != nil {
			r.OK, r.Error = false, err.Error()
		}
		out = append(out, r)
	}
	if n.SlackEnabled() {
		r := Result{Channel: "slack", OK: true}
		if err := sendSlack(n, d.slack()); err != nil {
			r.OK, r.Error = false, err.Error()
		}
		out = append(out, r)
	}
	return out
}

// ---------------------------------------------------------------- textos

var txt = map[string]map[string]string{
	"en": {
		"new":      "DevDoctor on %s: %d new issue(s)",
		"resolved": "Resolved:",
		"more":     "+%d more in the dashboard",
		"dash":     "Dashboard: %s",
		"intro":    "DevDoctor notifications are now active for %s. Current status: %d critical, %d warnings.",
		"top":      "Most important right now:",
		"test":     "Test message from DevDoctor on %s. If you can read this, notifications work.",
		"crit":     "[CRITICAL]",
		"warn":     "[WARNING]",
		"info":     "[INFO]",
		"fix":      "Fix:",
		"details":  "Details:",
	},
	"es": {
		"new":      "DevDoctor en %s: %d problema(s) nuevo(s)",
		"resolved": "Resueltos:",
		"more":     "+%d más en el dashboard",
		"dash":     "Dashboard: %s",
		"intro":    "Las notificaciones de DevDoctor están activas para %s. Estado actual: %d críticos, %d avisos.",
		"top":      "Lo más importante ahora:",
		"test":     "Mensaje de prueba de DevDoctor en %s. Si lo lees, las notificaciones funcionan.",
		"crit":     "[CRÍTICO]",
		"warn":     "[AVISO]",
		"info":     "[INFO]",
		"fix":      "Solución:",
		"details":  "Detalles:",
	},
}

func tr(lang, k string) string {
	if m, ok := txt[lang]; ok {
		return m[k]
	}
	return txt["en"][k]
}

func langOf(n config.NotifyConfig) string {
	if n.Lang == "es" {
		return "es"
	}
	return "en"
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "server"
	}
	return h
}

// Test envía un mensaje de prueba a los canales configurados.
func Test(n config.NotifyConfig) []Result {
	return send(n, doc{Title: "DevDoctor", Lines: []string{fmt.Sprintf(tr(langOf(n), "test"), hostname())}})
}

// ---------------------------------------------------------------- gestor de avisos

type entry struct {
	Sev   string    `json:"sev"`
	Title string    `json:"title"`
	First time.Time `json:"first"`
	Miss  int       `json:"miss"`
	Cat   string    `json:"cat"`
}

type state struct {
	Init  bool              `json:"init"`
	Items map[string]*entry `json:"items"`
}

type Manager struct {
	cs *config.Store
	mu sync.Mutex
}

func NewManager(cs *config.Store) *Manager { return &Manager{cs: cs} }

var numUnit = regexp.MustCompile(`\d+(?:\.\d+)?\s*(days|ms|%)`)

// fingerprint identifica un problema ignorando valores que cambian solos (días restantes, % de disco, ms).
func fingerprint(f scanner.Finding) string {
	return f.Category + "|" + f.Severity + "|" + numUnit.ReplaceAllString(f.Title, "#$1")
}

func (m *Manager) statePath() string {
	return filepath.Join(filepath.Dir(m.cs.Path()), "notified.json")
}

func (m *Manager) load() state {
	st := state{Items: map[string]*entry{}}
	if b, err := os.ReadFile(m.statePath()); err == nil {
		json.Unmarshal(b, &st)
		if st.Items == nil {
			st.Items = map[string]*entry{}
		}
	}
	return st
}

func (m *Manager) save(st state) {
	if b, err := json.Marshal(st); err == nil {
		os.WriteFile(m.statePath(), b, 0o600)
	}
}

// Handle se llama al terminar cada escaneo: avisa de los problemas nuevos (y, si se pide, de los resueltos).
func (m *Manager) Handle(rep *scanner.Report) {
	if rep == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.cs.Get()
	n := cfg.Notify
	if !n.Enabled() {
		return
	}
	lang := langOf(n)
	loc := rep.Localize(lang)
	maxRank := 0 // sólo críticos
	if n.MinSeverity == "warn" {
		maxRank = 1
	}
	rank := map[string]int{"crit": 0, "warn": 1}

	type item struct {
		key string
		f   scanner.Finding // localizado
	}
	cur := map[string]item{}
	var order []item
	for i, f := range rep.Findings {
		r, ok := rank[f.Severity]
		if !ok || r > maxRank {
			continue
		}
		k := fingerprint(f)
		if _, dup := cur[k]; dup {
			continue
		}
		it := item{k, loc.Findings[i]}
		cur[k] = it
		order = append(order, it)
	}
	sort.SliceStable(order, func(i, j int) bool { return rank[order[i].f.Severity] < rank[order[j].f.Severity] })

	dash := fmt.Sprintf("https://%s:%d", cfg.Host, cfg.Port)
	host := hostname()
	st := m.load()
	now := time.Now()

	line := func(f scanner.Finding) []string {
		l := []string{tr(lang, f.Severity) + " " + f.Title}
		if f.Fix != "" {
			l = append(l, "   "+tr(lang, "fix")+" "+f.Fix)
		}
		if f.Link != "" {
			l = append(l, "   "+f.Link)
		}
		return l
	}

	// primer escaneo con las notificaciones activas: resumen, sin inundar con todo lo existente
	if !st.Init {
		var lines []string
		shown := 0
		for _, it := range order {
			if shown == 0 {
				lines = append(lines, tr(lang, "top"))
			}
			if shown >= 5 {
				break
			}
			lines = append(lines, line(it.f)...)
			shown++
		}
		lines = append(lines, fmt.Sprintf(tr(lang, "dash"), dash))
		res := send(n, doc{Title: "DevDoctor", Lines: append([]string{fmt.Sprintf(tr(lang, "intro"), host, rep.Counts["crit"], rep.Counts["warn"])}, lines...)})
		if allOK(res) {
			for _, it := range order {
				st.Items[it.key] = &entry{Sev: it.f.Severity, Title: it.f.Title, First: now, Cat: it.f.Category}
			}
			st.Init = true
			m.save(st)
		} else {
			logFail(res)
		}
		return
	}

	// novedades y recuperaciones
	var news []item
	for _, it := range order {
		if e, ok := st.Items[it.key]; ok {
			e.Miss, e.Title = 0, it.f.Title
		} else {
			news = append(news, it)
		}
	}
	intelDown := false
	if rep.Intel != nil {
		for _, s := range rep.Intel.Sources {
			if !s.OK {
				intelDown = true
			}
		}
	}
	var resolved []string
	for k, e := range st.Items {
		if _, still := cur[k]; still {
			continue
		}
		if e.Cat == "Advisories" && intelDown { // sin datos de las fuentes no se puede decir que se resolvió
			continue
		}
		e.Miss++
		if e.Miss >= 2 { // ausente en dos escaneos seguidos
			resolved = append(resolved, e.Title)
			delete(st.Items, k)
		}
	}
	if !n.Recovery {
		resolved = nil
	}
	if len(news) == 0 && len(resolved) == 0 {
		m.save(st)
		return
	}

	var lines []string
	const max = 8
	for i, it := range news {
		if i >= max {
			lines = append(lines, fmt.Sprintf(tr(lang, "more"), len(news)-max))
			break
		}
		lines = append(lines, line(it.f)...)
	}
	if len(resolved) > 0 {
		lines = append(lines, tr(lang, "resolved"))
		for i, r := range resolved {
			if i >= 5 {
				break
			}
			lines = append(lines, " - "+r)
		}
	}
	lines = append(lines, fmt.Sprintf(tr(lang, "dash"), dash))
	title := fmt.Sprintf(tr(lang, "new"), host, len(news))
	res := send(n, doc{Title: title, Lines: lines})
	if allOK(res) {
		for _, it := range news {
			st.Items[it.key] = &entry{Sev: it.f.Severity, Title: it.f.Title, First: now, Cat: it.f.Category}
		}
		m.save(st)
	} else {
		logFail(res) // no se marcan como avisados: se reintenta en el siguiente escaneo
	}
}

func allOK(rs []Result) bool {
	for _, r := range rs {
		if r.OK {
			return true // basta con que llegue a un canal
		}
	}
	return false
}

func logFail(rs []Result) {
	for _, r := range rs {
		if !r.OK {
			log.Printf("notification failed (%s): %s", r.Channel, r.Error)
		}
	}
}
