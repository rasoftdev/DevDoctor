// Package intel consulta fuentes públicas de seguridad (php.net, nodejs.org, endoflife.date, CISA KEV,
// OSV.dev, NVD, Ubuntu Security y GitHub Advisories) con caché en disco. Sólo envía nombres y versiones
// de software, nunca datos del servidor (IPs, usuarios, rutas).
package intel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Status describe el resultado de consultar una fuente (se muestra en el dashboard).
type Status struct {
	Name   string    `json:"name"`
	OK     bool      `json:"ok"`
	Cached bool      `json:"cached"`
	Error  string    `json:"error,omitempty"`
	At     time.Time `json:"at"`
}

type Client struct {
	dir    string
	ua     string
	nvdKey string
	http   *http.Client

	mu     sync.Mutex
	status map[string]*Status

	nvdMu   sync.Mutex
	nvdLast time.Time
}

// New crea un cliente. dir es la carpeta de caché ("" = sin caché en disco).
func New(dir, ua, nvdKey string) *Client {
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			dir = ""
		}
	}
	return &Client{dir: dir, ua: ua, nvdKey: nvdKey, http: &http.Client{Timeout: 40 * time.Second}, status: map[string]*Status{}}
}

// Statuses devuelve el estado de las fuentes consultadas, ordenado por nombre.
func (c *Client) Statuses() []Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Status, 0, len(c.status))
	for _, s := range c.status {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (c *Client) mark(name string, err error, cached bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.status[name]
	if s == nil {
		s = &Status{Name: name, OK: true}
		c.status[name] = s
	}
	s.At = time.Now()
	if err != nil {
		if cached { // datos viejos de la caché: sigue siendo útil
			s.Cached, s.Error = true, err.Error()
			return
		}
		s.OK, s.Error = false, err.Error()
		return
	}
	s.Cached = s.Cached || cached
}

func cacheFile(dir, url string, body []byte) string {
	h := sha256.Sum256(append([]byte(url+"|"), body...))
	return filepath.Join(dir, hex.EncodeToString(h[:8])+".json")
}

// fetch hace GET (o POST JSON si body != nil) con caché de ttl; si falla usa la caché aunque esté vencida.
func (c *Client) fetch(source, url string, ttl time.Duration, body []byte, out any) error {
	var path string
	if c.dir != "" {
		path = cacheFile(c.dir, url, body)
		if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < ttl {
			if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, out) == nil {
				c.mark(source, nil, true)
				return nil
			}
		}
	}
	b, err := c.request(url, body)
	if err == nil {
		if err = json.Unmarshal(b, out); err == nil {
			if path != "" {
				os.WriteFile(path, b, 0o600)
			}
			c.mark(source, nil, false)
			return nil
		}
	}
	if path != "" { // fuente caída: usar caché vieja si existe
		if sb, e := os.ReadFile(path); e == nil && json.Unmarshal(sb, out) == nil {
			c.mark(source, err, true)
			return nil
		}
	}
	c.mark(source, err, false)
	return err
}

func (c *Client) request(url string, body []byte) ([]byte, error) {
	method := "GET"
	var rd io.Reader
	if body != nil {
		method, rd = "POST", bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.nvdKey != "" && strings.Contains(url, "services.nvd.nist.gov") {
		req.Header.Set("apiKey", c.nvdKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 40<<20))
}

// ---------------------------------------------------------------- versiones

var numRe = regexp.MustCompile(`\d+`)

// CompareVersions compara dos versiones tipo "8.3.14" / "v22.1.0" (sólo la parte numérica).
func CompareVersions(a, b string) int {
	pa, pb := numRe.FindAllString(a, 3), numRe.FindAllString(b, 3)
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ---------------------------------------------------------------- php.net

type Release struct {
	Version  string
	Date     string
	Security bool
}

// PHPReleases devuelve las últimas versiones de una rama (p. ej. "8.3") con su marca de seguridad.
func (c *Client) PHPReleases(branch string) ([]Release, error) {
	var raw map[string]struct {
		Tags []string `json:"tags"`
		Date string   `json:"date"`
	}
	if err := c.fetch("php.net", "https://www.php.net/releases/index.php?json&version="+branch+"&max=40", 6*time.Hour, nil, &raw); err != nil {
		return nil, err
	}
	var out []Release
	for v, r := range raw {
		sec := false
		for _, t := range r.Tags {
			if t == "security" {
				sec = true
			}
		}
		out = append(out, Release{v, r.Date, sec})
	}
	sort.Slice(out, func(i, j int) bool { return CompareVersions(out[i].Version, out[j].Version) > 0 })
	return out, nil
}

// ---------------------------------------------------------------- nodejs.org

func (c *Client) NodeReleases() ([]Release, error) {
	var raw []struct {
		Version  string `json:"version"`
		Date     string `json:"date"`
		Security bool   `json:"security"`
	}
	if err := c.fetch("nodejs.org", "https://nodejs.org/dist/index.json", 6*time.Hour, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]Release, 0, len(raw))
	for _, r := range raw {
		out = append(out, Release{r.Version, r.Date, r.Security})
	}
	return out, nil
}

// ---------------------------------------------------------------- endoflife.date

type EOLCycle struct {
	Cycle    string
	EOL      string // fecha ISO; vacío si no hay fecha (soportado) o "true" si ya terminó sin fecha
	Latest   string
	Extended string // fin del soporte extendido (ESM), si aplica
}

func rawDate(r json.RawMessage) string {
	var s string
	if json.Unmarshal(r, &s) == nil {
		return s
	}
	var b bool
	if json.Unmarshal(r, &b) == nil && b {
		return "true"
	}
	return ""
}

func (c *Client) EOL(product string) ([]EOLCycle, error) {
	var raw []struct {
		Cycle    json.RawMessage `json:"cycle"`
		EOL      json.RawMessage `json:"eol"`
		Latest   string          `json:"latest"`
		Extended json.RawMessage `json:"extendedSupport"`
	}
	if err := c.fetch("endoflife.date", "https://endoflife.date/api/"+product+".json", 24*time.Hour, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]EOLCycle, 0, len(raw))
	for _, r := range raw {
		cy := strings.Trim(string(r.Cycle), `"`)
		out = append(out, EOLCycle{cy, rawDate(r.EOL), r.Latest, rawDate(r.Extended)})
	}
	return out, nil
}

// ---------------------------------------------------------------- CISA KEV

type KEV struct {
	CVE, Vendor, Product, Name, Added, Description, Ransomware string
}

func (c *Client) KEV() ([]KEV, error) {
	var raw struct {
		Vulnerabilities []struct {
			CVE         string `json:"cveID"`
			Vendor      string `json:"vendorProject"`
			Product     string `json:"product"`
			Name        string `json:"vulnerabilityName"`
			Added       string `json:"dateAdded"`
			Description string `json:"shortDescription"`
			Ransomware  string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := c.fetch("CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 6*time.Hour, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]KEV, 0, len(raw.Vulnerabilities))
	for _, v := range raw.Vulnerabilities {
		out = append(out, KEV{v.CVE, v.Vendor, v.Product, v.Name, v.Added, v.Description, v.Ransomware})
	}
	return out, nil
}

// ---------------------------------------------------------------- OSV.dev

type OSVQuery struct{ Ecosystem, Name, Version string }

// OSVBatch consulta vulnerabilidades de paquetes (Packagist, npm...) y devuelve los IDs por consulta.
func (c *Client) OSVBatch(qs []OSVQuery) ([][]string, error) {
	res := make([][]string, len(qs))
	for start := 0; start < len(qs); start += 500 {
		end := start + 500
		if end > len(qs) {
			end = len(qs)
		}
		type pk struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}
		type q struct {
			Package pk     `json:"package"`
			Version string `json:"version"`
		}
		var body struct {
			Queries []q `json:"queries"`
		}
		for _, x := range qs[start:end] {
			body.Queries = append(body.Queries, q{pk{x.Name, x.Ecosystem}, x.Version})
		}
		b, _ := json.Marshal(body)
		var out struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := c.fetch("OSV.dev", "https://api.osv.dev/v1/querybatch", 12*time.Hour, b, &out); err != nil {
			return nil, err
		}
		for i, r := range out.Results {
			if start+i < len(res) {
				for _, v := range r.Vulns {
					res[start+i] = append(res[start+i], v.ID)
				}
			}
		}
	}
	return res, nil
}

type OSVDetail struct {
	ID, Summary, Severity string
}

func (c *Client) OSVVuln(id string) (OSVDetail, error) {
	var raw struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Database struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if err := c.fetch("OSV.dev", "https://api.osv.dev/v1/vulns/"+id, 7*24*time.Hour, nil, &raw); err != nil {
		return OSVDetail{ID: id}, err
	}
	return OSVDetail{raw.ID, raw.Summary, strings.ToUpper(raw.Database.Severity)}, nil
}

// ---------------------------------------------------------------- NVD

type NVDCVE struct {
	ID, Severity, Published, Description string
	Score                                float64
}

type NVDResult struct {
	Total int
	CVEs  []NVDCVE
}

func (c *Client) nvdWait() {
	gap := 6500 * time.Millisecond // sin clave: 5 peticiones / 30 s
	if c.nvdKey != "" {
		gap = 700 * time.Millisecond
	}
	c.nvdMu.Lock()
	defer c.nvdMu.Unlock()
	if d := time.Until(c.nvdLast.Add(gap)); d > 0 {
		time.Sleep(d)
	}
	c.nvdLast = time.Now()
}

type nvdRaw struct {
	Total int `json:"totalResults"`
	Vulns []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics map[string][]struct {
				Data struct {
					Score    float64 `json:"baseScore"`
					Severity string  `json:"baseSeverity"`
				} `json:"cvssData"`
				Severity string `json:"baseSeverity"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (r nvdRaw) convert() NVDResult {
	var out []NVDCVE
	for _, v := range r.Vulns {
		cv := NVDCVE{ID: v.CVE.ID, Published: v.CVE.Published}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				cv.Description = d.Value
				break
			}
		}
		for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if ms := v.CVE.Metrics[key]; len(ms) > 0 {
				cv.Score, cv.Severity = ms[0].Data.Score, strings.ToUpper(ms[0].Data.Severity)
				if cv.Severity == "" {
					cv.Severity = strings.ToUpper(ms[0].Severity)
				}
				break
			}
		}
		out = append(out, cv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Published > out[j].Published })
	return NVDResult{Total: r.Total, CVEs: out}
}

func isRateLimit(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "HTTP 403") || strings.Contains(s, "HTTP 429") || strings.Contains(s, "HTTP 503")
}

// NVD devuelve las CVE que NVD asocia a un CPE concreto (producto + versión exacta).
func (c *Client) NVD(cpe string) (NVDResult, error) {
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=500&cpeName=" + cpe
	var raw nvdRaw
	// con caché fresca no hace falta respetar el ritmo de NVD
	if c.dir != "" {
		if fi, err := os.Stat(cacheFile(c.dir, url, nil)); err == nil && time.Since(fi.ModTime()) < 24*time.Hour {
			if err := c.fetch("NVD", url, 24*time.Hour, nil, &raw); err == nil {
				return raw.convert(), nil
			}
		}
	}
	c.nvdWait()
	err := c.fetch("NVD", url, 24*time.Hour, nil, &raw)
	if isRateLimit(err) {
		time.Sleep(10 * time.Second) // NVD limita el ritmo: un único reintento
		c.nvdWait()
		err = c.fetch("NVD", url, 24*time.Hour, nil, &raw)
	}
	if err != nil {
		return NVDResult{}, err
	}
	return raw.convert(), nil
}
