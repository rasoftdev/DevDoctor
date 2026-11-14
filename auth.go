package main

import (
	"sync"
	"time"
)

type failRec struct {
	n     int
	until time.Time
	first time.Time
}

type Auth struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	fails    map[string]*failRec
}

const sessionTTL = 12 * time.Hour

func NewAuth() *Auth {
	return &Auth{sessions: map[string]time.Time{}, fails: map[string]*failRec{}}
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
	f := a.fails[ip]
	if f == nil || time.Since(f.first) > 15*time.Minute {
		f = &failRec{first: time.Now()}
		a.fails[ip] = f
	}
	f.n++
	if f.n >= 5 {
		f.until = time.Now().Add(15 * time.Minute)
	}
}

func (a *Auth) Reset(ip string) { a.mu.Lock(); delete(a.fails, ip); a.mu.Unlock() }

func (a *Auth) NewSession() string {
	t := randomToken()
	a.mu.Lock()
	a.sessions[t] = time.Now().Add(sessionTTL)
	for k, exp := range a.sessions { // limpieza oportunista
		if time.Now().After(exp) {
			delete(a.sessions, k)
		}
	}
	a.mu.Unlock()
	return t
}

func (a *Auth) Valid(t string) bool {
	if t == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[t]
	if !ok || time.Now().After(exp) {
		delete(a.sessions, t)
		return false
	}
	return true
}

func (a *Auth) Drop(t string) { a.mu.Lock(); delete(a.sessions, t); a.mu.Unlock() }
func (a *Auth) DropAll()      { a.mu.Lock(); a.sessions = map[string]time.Time{}; a.mu.Unlock() }
