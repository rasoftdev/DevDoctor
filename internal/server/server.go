package server

import (
	"crypto/tls"
	"devdoctor/internal/config"
	"devdoctor/internal/scanner"
	"devdoctor/internal/sysinfo"
	"devdoctor/internal/version"
	"devdoctor/internal/web"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

type Server struct {
	cs   *config.Store
	auth *Auth
	sam  *sysinfo.Sampler
	scan *scanner.Scanner
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(web.Index)
	})
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /api/metrics", s.guard(s.metrics))
	mux.HandleFunc("GET /api/report", s.guard(s.report))
	mux.HandleFunc("POST /api/scan", s.guard(s.startScan))
	mux.HandleFunc("POST /api/account", s.guard(s.account))
	return secure(mux)
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		// Los POST deben ser JSON (impide formularios cross-site simples).
		if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "content-type inválido", http.StatusUnsupportedMediaType)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("dd_session")
		if err != nil || !s.auth.Valid(ck.Value) {
			writeJSON(w, 401, map[string]string{"error": "no autenticado"})
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

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.auth.Locked(ip) {
		writeJSON(w, 429, map[string]string{"error": "demasiados intentos; espera 15 minutos"})
		return
	}
	var in struct{ Username, Password string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]string{"error": "solicitud inválida"})
		return
	}
	cfg := s.cs.Get()
	if !cfg.CheckLogin(in.Username, in.Password) {
		s.auth.Fail(ip)
		log.Printf("login fallido desde %s", ip)
		time.Sleep(500 * time.Millisecond)
		writeJSON(w, 401, map[string]string{"error": "usuario o contraseña incorrectos"})
		return
	}
	s.auth.Reset(ip)
	http.SetCookie(w, &http.Cookie{Name: "dd_session", Value: s.auth.NewSession(), Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	writeJSON(w, 200, map[string]string{"user": cfg.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie("dd_session"); err == nil {
		s.auth.Drop(ck.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "dd_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie("dd_session")
	if err != nil || !s.auth.Valid(ck.Value) {
		writeJSON(w, 401, map[string]string{"error": "no autenticado"})
		return
	}
	cfg := s.cs.Get()
	writeJSON(w, 200, map[string]any{"user": cfg.Username, "version": version.Version})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, s.sam.Get()) }

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	rep, running := s.scan.Last()
	writeJSON(w, 200, map[string]any{"running": running, "report": rep})
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]bool{"started": s.scan.Start()})
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current  string `json:"current"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in) != nil {
		writeJSON(w, 400, map[string]string{"error": "solicitud inválida"})
		return
	}
	cfg := s.cs.Get()
	if !cfg.CheckLogin(cfg.Username, in.Current) {
		time.Sleep(500 * time.Millisecond)
		writeJSON(w, 403, map[string]string{"error": "la contraseña actual no es correcta"})
		return
	}
	var perr error
	err := s.cs.Update(func(c *config.Config) {
		if in.Username != "" {
			c.Username = in.Username
		}
		if in.Password != "" {
			perr = c.SetPassword(in.Password)
		}
	})
	if perr != nil {
		writeJSON(w, 400, map[string]string{"error": perr.Error()})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.auth.DropAll() // cierra todas las sesiones; hay que volver a entrar
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func Serve(cs *config.Store, dir string) error {
	cfg := cs.Get()
	cert, err := config.EnsureCert(dir, cfg.Host)
	if err != nil {
		return fmt.Errorf("certificado TLS: %w", err)
	}
	sam := &sysinfo.Sampler{}
	sam.Start()
	sc := scanner.New(cs, sam)
	sc.Start()
	go func() {
		for {
			time.Sleep(time.Duration(cs.Get().ScanIntervalMin) * time.Minute)
			sc.Start()
		}
	}()
	srv := &Server{cs: cs, auth: NewAuth(), sam: sam, scan: sc}
	hs := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.Port),
		Handler:           srv.routes(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("DevDoctor %s escuchando en https://%s:%d", version.Version, cfg.Host, cfg.Port)
	return hs.ListenAndServeTLS("", "")
}
