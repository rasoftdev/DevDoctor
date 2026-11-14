package config

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const pbkdf2Iter = 600000

type Config struct {
	Port               int          `json:"port"`
	Host               string       `json:"host"`
	Listen             string       `json:"listen,omitempty"` // interfaz de escucha; vacío = todas, "127.0.0.1" = solo local (con proxy)
	Username           string       `json:"username"`
	SetupToken         string       `json:"setup_token,omitempty"` // código de un solo uso para crear la cuenta en la web
	PassSalt           string       `json:"pass_salt"`
	PassHash           string       `json:"pass_hash"`
	Iter               int          `json:"iter"`
	ScanRoots          []string     `json:"scan_roots"`
	IntelDisabled      bool         `json:"intel_disabled,omitempty"`       // true = no consultar fuentes públicas de seguridad
	IntelIntervalHours int          `json:"intel_interval_hours,omitempty"` // cada cuántas horas se consultan las fuentes de seguridad (por defecto 24)
	Notify             NotifyConfig `json:"notify"`
	NVDAPIKey          string       `json:"nvd_api_key,omitempty"` // opcional: sube el límite de peticiones a NVD
	ScanIntervalMin    int          `json:"scan_interval_min"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

func DefaultPath() string {
	if p := os.Getenv("DEVDOCTOR_CONFIG"); p != "" {
		return p
	}
	if runtime.GOOS == "linux" {
		return "/etc/devdoctor/config.json"
	}
	return "devdoctor.json"
}

func Load(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path}
	if err := json.Unmarshal(b, &s.cfg); err != nil {
		return nil, err
	}
	if s.cfg.ScanIntervalMin <= 0 {
		s.cfg.ScanIntervalMin = 15
	}
	return s, nil
}

func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *Store) Update(fn func(c *Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.cfg)
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s.cfg, "", "  ")
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (c *Config) SetPassword(pw string) error {
	if err := ValidatePassword(c.Username, pw); err != nil {
		return err
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	h, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return err
	}
	c.Iter = pbkdf2Iter
	c.PassSalt = base64.StdEncoding.EncodeToString(salt)
	c.PassHash = base64.StdEncoding.EncodeToString(h)
	return nil
}

func (c *Config) CheckLogin(user, pw string) bool {
	salt, _ := base64.StdEncoding.DecodeString(c.PassSalt)
	want, _ := base64.StdEncoding.DecodeString(c.PassHash)
	iter := c.Iter
	if iter == 0 {
		iter = pbkdf2Iter
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, 32)
	if err != nil || len(want) == 0 {
		return false
	}
	okPass := subtle.ConstantTimeCompare(got, want) == 1
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(c.Username)) == 1
	return okPass && okUser
}

func RandomPassword(n int) string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	for i := range out {
		v, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		out[i] = alphabet[v.Int64()]
	}
	return string(out)
}

func RandomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// New crea un Store en memoria asociado a una ruta (no escribe hasta Update).
func New(path string, cfg Config) *Store { return &Store{path: path, cfg: cfg} }

// Path devuelve la ruta del archivo de configuración.
func (s *Store) Path() string { return s.path }

// Configured indica si ya existe una cuenta de acceso.
func (c *Config) Configured() bool { return c.PassHash != "" && c.Username != "" }

// Refresh recarga la configuración desde disco (p. ej. tras editarla con el CLI) sin reiniciar el servicio.
func (s *Store) Refresh() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var c Config
	if json.Unmarshal(b, &c) != nil {
		return
	}
	if c.ScanIntervalMin <= 0 {
		c.ScanIntervalMin = 15
	}
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
}
