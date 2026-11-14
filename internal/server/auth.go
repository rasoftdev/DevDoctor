package server

import (
	"errors"
	"sync"
	"time"

	"devdoctor/internal/config"
)

const (
	sessionAbsolute = 12 * time.Hour   // vida máxima de una sesión
	sessionIdle     = 30 * time.Minute // cierre por inactividad
	maxSessions     = 20
	maxTrackedIPs   = 5000
	lockAfter       = 5
	lockFor         = 15 * time.Minute
	failWindow      = 15 * time.Minute
)

type failRec struct {
	n     int
	until time.Time
	first time.Time
}

type session struct {
	created, last time.Time
	ua            string
}

type Auth struct {
	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string]*failRec
	global   []time.Time   // fallos recientes de cualquier origen (ataques distribuidos)
	hashSem  chan struct{} // limita cuántos PBKDF2 corren a la vez (anti-agotamiento de CPU)
}

func NewAuth() *Auth {
	return &Auth{sessions: map[string]*session{}, fails: map[string]*failRec{}, hashSem: make(chan struct{}, 2)}
}

var errBusy = errors.New("servidor ocupado")

// WithHash ejecuta fn (una verificación de contraseña costosa) con concurrencia limitada.
func (a *Auth) WithHash(fn func() bool) (bool, error) {
	select {
	case a.hashSem <- struct{}{}:
		defer func() { <-a.hashSem }()
		return fn(), nil
	case <-time.After(5 * time.Second):
		return false, errBusy
	}
}

func (a *Auth) Locked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[ip]
	return f != nil && time.Now().Before(f.until)
}

func (a *Auth) Fail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	f := a.fails[ip]
	if f == nil || now.Sub(f.first) > failWindow {
		f = &failRec{first: now}
		a.fails[ip] = f
	}
	f.n++
	if f.n >= lockAfter {
		f.until = now.Add(lockFor)
	}
	a.global = append(a.global, now)
	// poda: ventana global y tabla de IPs acotada
	cut := 0
	for cut < len(a.global) && now.Sub(a.global[cut]) > 10*time.Minute {
		cut++
	}
	a.global = a.global[cut:]
	if len(a.fails) > maxTrackedIPs {
		for k, v := range a.fails {
			if now.After(v.until) && now.Sub(v.first) > failWindow {
				delete(a.fails, k)
			}
		}
	}
}

// Delay frena a todos los intentos cuando hay muchos fallos recientes (ataque distribuido),
// sin bloquear al usuario legítimo.
func (a *Auth) Delay() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := time.Duration(len(a.global)) * 100 * time.Millisecond
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return 400*time.Millisecond + d
}

func (a *Auth) Reset(ip string) { a.mu.Lock(); delete(a.fails, ip); a.mu.Unlock() }

func (a *Auth) NewSession(ua string) string {
	t := config.RandomToken()
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, s := range a.sessions {
		if now.Sub(s.created) > sessionAbsolute || now.Sub(s.last) > sessionIdle {
			delete(a.sessions, k)
		}
	}
	for len(a.sessions) >= maxSessions { // expulsa la más antigua
		var oldK string
		var oldT time.Time
		for k, s := range a.sessions {
			if oldK == "" || s.created.Before(oldT) {
				oldK, oldT = k, s.created
			}
		}
		delete(a.sessions, oldK)
	}
	a.sessions[t] = &session{created: now, last: now, ua: ua}
	return t
}

// Valid comprueba la sesión y renueva su temporizador de inactividad.
func (a *Auth) Valid(t, ua string) bool {
	if t == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[t]
	now := time.Now()
	if !ok || now.Sub(s.created) > sessionAbsolute || now.Sub(s.last) > sessionIdle || s.ua != ua {
		delete(a.sessions, t)
		return false
	}
	s.last = now
	return true
}

func (a *Auth) Drop(t string) { a.mu.Lock(); delete(a.sessions, t); a.mu.Unlock() }
func (a *Auth) DropAll()      { a.mu.Lock(); a.sessions = map[string]*session{}; a.mu.Unlock() }
