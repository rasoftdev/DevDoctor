package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"devdoctor/internal/config"
	"devdoctor/internal/notify"
	"devdoctor/internal/scanner"
	"devdoctor/internal/sysinfo"
	"devdoctor/internal/version"
	"devdoctor/internal/web"
)

const cookieName = "__Host-dd_session" // el prefijo __Host- obliga Secure, Path=/ y sin Domain

type Server struct {
	cs   *config.Store
	auth *Auth
	sam  *sysinfo.Sampler
	scan *scanner.Scanner
	csp  string
}

// scriptHash calcula el hash CSP del único <script> en línea del dashboard,
// para no necesitar 'unsafe-inline' en script-src.
func scriptHash(page []byte) string {
	start := bytes.Index(page, []byte("<script>"))
	end := bytes.LastIndex(page, []byte("</script>"))
	if start < 0 || end < start {
		return ""
	}
	body := page[start+len("<script>") : end]
	body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n")) // el parser HTML normaliza CRLF
	sum := sha256.Sum256(body)
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(web.Index)
	})
	for _, name := range []string{"logo.png", "favicon.png", "favicon-32.png", "apple-touch-icon.png"} {
		mux.HandleFunc("GET /"+name, assetHandler(name))
	}
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("POST /api/setup", s.setup)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /api/metrics", s.guard(s.metrics))
	mux.HandleFunc("GET /api/report", s.guard(s.report))
	mux.HandleFunc("POST /api/scan", s.guard(s.startScan))
	mux.HandleFunc("POST /api/account", s.guard(s.account))
	mux.HandleFunc("GET /api/settings", s.guard(s.getSettings))
	mux.HandleFunc("POST /api/settings", s.guard(s.setSettings))
	mux.HandleFunc("POST /api/notify/test", s.guard(s.testNotify))
	return s.secure(mux)
}

// originOK rejects requests that do not come from the page itself (extra CSRF defence on top of SameSite).
// assetHandler sirve un archivo embebido (logo/iconos) con caché pública.
func assetHandler(name string) http.HandlerFunc {
	data, _ := web.Assets.ReadFile(name)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(data)
	}
}

func originOK(r *http.Request) bool {
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}

func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Content-Security-Policy", s.csp)
		if r.Method == http.MethodPost {
			// Los POST deben ser JSON y del mismo origen (impide formularios cross-site).
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
				return
			}
			if !originOK(r) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sessionOK(r *http.Request) bool {
	ck, err := r.Cookie(cookieName)
	return err == nil && s.auth.Valid(ck.Value, r.UserAgent())
}

func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sessionOK(r) {
			writeJSON(w, 401, map[string]string{"error": "not authenticated"})
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// clientIP devuelve la IP real del cliente. Sólo se confía en X-Forwarded-For cuando la
// conexión viene de un proxy local (127.0.0.1/::1), usando el último valor (el que añadió el proxy).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if cand := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); cand != nil {
				return cand.String()
			}
		}
	}
	return host
}

func setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionAbsolute.Seconds())})
}

func tooMany(w http.ResponseWriter) {
	writeJSON(w, 429, map[string]string{"error": "too many attempts; wait 15 minutes"})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return false
	}
	return true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.auth.Locked(ip) {
		tooMany(w)
		return
	}
	var in struct{ Username, Password string }
	if !decode(w, r, &in) {
		return
	}
	cfg := s.cs.Get()
	ok := false
	if len(in.Username) <= 128 && len(in.Password) <= 256 {
		var err error
		ok, err = s.auth.WithHash(func() bool { return cfg.CheckLogin(in.Username, in.Password) })
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "server busy, try again"})
			return
		}
	}
	if !ok {
		s.auth.Fail(ip)
		log.Printf("failed login from %s", ip)
		time.Sleep(s.auth.Delay())
		writeJSON(w, 401, map[string]string{"error": "incorrect username or password"})
		return
	}
	s.auth.Reset(ip)
	setSession(w, s.auth.NewSession(r.UserAgent()))
	writeJSON(w, 200, map[string]string{"user": cfg.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(cookieName); err == nil {
		s.auth.Drop(ck.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	if !s.sessionOK(r) {
		writeJSON(w, 401, map[string]string{"error": "not authenticated"})
		return
	}
	cfg := s.cs.Get()
	writeJSON(w, 200, map[string]any{"user": cfg.Username, "version": version.Version})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, s.sam.Get()) }

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	lang := "en"
	if r.URL.Query().Get("lang") == "es" {
		lang = "es"
	}
	rep, running := s.scan.Last()
	if rep != nil {
		rep = rep.Localize(lang)
	}
	writeJSON(w, 200, map[string]any{"running": running, "report": rep})
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]bool{"started": s.scan.Start()})
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.auth.Locked(ip) {
		tooMany(w)
		return
	}
	var in struct {
		Current  string `json:"current"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	cfg := s.cs.Get()
	ok := false
	if len(in.Current) <= 256 {
		var err error
		ok, err = s.auth.WithHash(func() bool { return cfg.CheckLogin(cfg.Username, in.Current) })
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "server busy, try again"})
			return
		}
	}
	if !ok { // un robo de sesión no debe permitir adivinar la contraseña actual sin límite
		s.auth.Fail(ip)
		log.Printf("failed login from %s (account change)", ip)
		time.Sleep(s.auth.Delay())
		writeJSON(w, 403, map[string]string{"error": "current password is incorrect"})
		return
	}
	s.auth.Reset(ip)
	var perr error
	err := s.cs.Update(func(c *config.Config) {
		next := *c
		if in.Username != "" {
			if len(in.Username) < 3 || len(in.Username) > 64 {
				perr = errors.New("username must be 3 to 64 characters")
				return
			}
			next.Username = in.Username
		}
		if in.Password != "" {
			if perr = next.SetPassword(in.Password); perr != nil {
				return
			}
		}
		*c = next
	})
	if perr != nil {
		writeJSON(w, 400, map[string]string{"error": perr.Error()})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("credentials updated from %s", ip)
	s.auth.DropAll() // cierra todas las sesiones; hay que volver a entrar
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// status indica al frontend si hay que mostrar el asistente de primer acceso.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	cfg := s.cs.Get()
	writeJSON(w, 200, map[string]bool{"setup": !cfg.Configured()})
}

// setup crea la cuenta inicial desde la web. Exige el código de un solo uso mostrado en la
// terminal durante la instalación, para que nadie más pueda reclamar la cuenta.
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.auth.Locked(ip) {
		tooMany(w)
		return
	}
	var in struct{ Token, Username, Password string }
	if !decode(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	var perr error
	var denied bool
	err := s.cs.Update(func(c *config.Config) {
		if c.Configured() || c.SetupToken == "" || subtle.ConstantTimeCompare([]byte(in.Token), []byte(c.SetupToken)) != 1 {
			denied = true
			return
		}
		if len(in.Username) < 3 || len(in.Username) > 64 {
			perr = errors.New("username must be 3 to 64 characters")
			return
		}
		next := *c
		next.Username = in.Username
		if perr = next.SetPassword(in.Password); perr != nil {
			return
		}
		next.SetupToken = ""
		*c = next
	})
	switch {
	case denied:
		s.auth.Fail(ip)
		log.Printf("rejected initial setup attempt from %s", ip)
		time.Sleep(s.auth.Delay())
		writeJSON(w, 403, map[string]string{"error": "wrong setup code or the account already exists"})
		return
	case perr != nil:
		writeJSON(w, 400, map[string]string{"error": perr.Error()})
		return
	case err != nil:
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.auth.Reset(ip)
	log.Printf("initial account created: %s", in.Username)
	setSession(w, s.auth.NewSession(r.UserAgent()))
	writeJSON(w, 200, map[string]string{"user": in.Username})
}

func Serve(cs *config.Store, dir string) error {
	cfg := cs.Get()
	cert, err := config.EnsureCert(dir, cfg.Host)
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	sam := &sysinfo.Sampler{}
	sam.Start()
	sc := scanner.New(cs, sam)
	sc.OnDone = notify.NewManager(cs).Handle
	sc.Start()
	go func() {
		for {
			time.Sleep(time.Duration(cs.Get().ScanIntervalMin) * time.Minute)
			sc.Start()
		}
	}()
	csp := "default-src 'none'; script-src " + scriptHash(web.Index) +
		"; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
	srv := &Server{cs: cs, auth: NewAuth(), sam: sam, scan: sc, csp: csp}
	hs := &http.Server{
		Addr:    net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port)),
		Handler: srv.routes(),
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	if !cfg.Configured() {
		log.Printf("PENDING: open https://%s:%d and create your account with the setup code (run: devdoctor setup-code)", cfg.Host, cfg.Port)
	}
	log.Printf("DevDoctor %s listening on https://%s:%d", version.Version, cfg.Host, cfg.Port)
	return hs.ListenAndServeTLS("", "")
}

// notifyView es lo que ve el dashboard: nunca se devuelven los secretos, sólo si están guardados.
type notifyView struct {
	TelegramChatID   string `json:"telegram_chat_id"`
	TelegramTokenSet bool   `json:"telegram_token_set"`
	SlackWebhookSet  bool   `json:"slack_webhook_set"`
	MinSeverity      string `json:"min_severity"`
	Lang             string `json:"lang"`
	Recovery         bool   `json:"recovery"`
}

// notifyIn es lo que envía el dashboard. Un secreto vacío significa "conservar el guardado".
type notifyIn struct {
	TelegramToken  string `json:"telegram_token"`
	TelegramClear  bool   `json:"telegram_clear"`
	TelegramChatID string `json:"telegram_chat_id"`
	SlackWebhook   string `json:"slack_webhook"`
	SlackClear     bool   `json:"slack_clear"`
	MinSeverity    string `json:"min_severity"`
	Lang           string `json:"lang"`
	Recovery       bool   `json:"recovery"`
}

func mergeNotify(old config.NotifyConfig, in *notifyIn) (config.NotifyConfig, error) {
	n := old
	if in == nil {
		return n, nil
	}
	if in.TelegramClear {
		n.TelegramToken, n.TelegramChatID = "", ""
	}
	if t := strings.TrimSpace(in.TelegramToken); t != "" {
		n.TelegramToken = t
	}
	if !in.TelegramClear {
		n.TelegramChatID = strings.TrimSpace(in.TelegramChatID)
	}
	if in.SlackClear {
		n.SlackWebhook = ""
	}
	if w := strings.TrimSpace(in.SlackWebhook); w != "" {
		n.SlackWebhook = w
	}
	n.MinSeverity, n.Lang, n.Recovery = in.MinSeverity, in.Lang, in.Recovery
	if n.MinSeverity == "" {
		n.MinSeverity = "crit"
	}
	return n, n.Validate()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// getSettings devuelve las carpetas, URLs, notificaciones y consultas online configuradas.
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.cs.Get()
	n := cfg.Notify
	sev := n.MinSeverity
	if sev == "" {
		sev = "crit"
	}
	writeJSON(w, 200, map[string]any{
		"scan_roots":    nonNil(cfg.ScanRoots),
		"urls":          nonNil(cfg.URLs),
		"intel_enabled": !cfg.IntelDisabled,
		"notify": notifyView{TelegramChatID: n.TelegramChatID, TelegramTokenSet: n.TelegramToken != "", SlackWebhookSet: n.SlackWebhook != "",
			MinSeverity: sev, Lang: n.Lang, Recovery: n.Recovery},
	})
}

// setSettings guarda la configuración y lanza un escaneo inmediato.
func (s *Server) setSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ScanRoots    []string  `json:"scan_roots"`
		URLs         []string  `json:"urls"`
		IntelEnabled *bool     `json:"intel_enabled"`
		Notify       *notifyIn `json:"notify"`
	}
	if !decode(w, r, &in) {
		return
	}
	roots, err := config.NormalizeRoots(in.ScanRoots)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	urls, err := config.NormalizeURLs(in.URLs)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	cur := s.cs.Get()
	notif, err := mergeNotify(cur.Notify, in.Notify)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := s.cs.Update(func(c *config.Config) {
		c.ScanRoots, c.URLs, c.Notify = roots, urls, notif
		if in.IntelEnabled != nil {
			c.IntelDisabled = !*in.IntelEnabled
		}
	}); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("settings updated from %s (%d folders, %d URLs, notifications: %v)", clientIP(r), len(roots), len(urls), notif.Enabled())
	s.scan.Start()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// testNotify envía un mensaje de prueba con los valores del formulario (sin guardarlos).
func (s *Server) testNotify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Notify *notifyIn `json:"notify"`
	}
	if !decode(w, r, &in) {
		return
	}
	n, err := mergeNotify(s.cs.Get().Notify, in.Notify)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if !n.Enabled() {
		writeJSON(w, 400, map[string]string{"error": "no notification channel is configured"})
		return
	}
	writeJSON(w, 200, map[string]any{"results": notify.Test(n)})
}
