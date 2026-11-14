package intel

import (
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------- Ubuntu Security

type UbuntuCVE struct {
	ID, Priority, Status, Description string
	CVSS                              float64
}

// UbuntuUnpatched devuelve las CVE que Ubuntu aún no ha corregido ("needed"/"pending") para un paquete
// fuente en una versión de Ubuntu (codename, p. ej. "noble"). Tiene en cuenta los backports de Ubuntu.
func (c *Client) UbuntuUnpatched(pkg, codename string) ([]UbuntuCVE, int, error) {
	q := url.Values{}
	q.Set("package", pkg)
	q.Set("version", codename)
	q.Add("status", "needed")
	q.Add("status", "pending")
	q.Set("limit", "20") // máximo que admite la API
	var raw struct {
		Total int `json:"total_results"`
		CVEs  []struct {
			ID          string  `json:"id"`
			Priority    string  `json:"priority"`
			Description string  `json:"description"`
			CVSS3       float64 `json:"cvss3"`
			Packages    []struct {
				Name     string `json:"name"`
				Statuses []struct {
					Release string `json:"release_codename"`
					Status  string `json:"status"`
				} `json:"statuses"`
			} `json:"packages"`
		} `json:"cves"`
	}
	if err := c.fetch("Ubuntu Security", "https://ubuntu.com/security/cves.json?"+q.Encode(), 12*time.Hour, nil, &raw); err != nil {
		return nil, 0, err
	}
	var out []UbuntuCVE
	for _, cv := range raw.CVEs {
		for _, p := range cv.Packages {
			if p.Name != pkg { // la API busca por coincidencia parcial: sólo el paquete exacto
				continue
			}
			for _, st := range p.Statuses {
				if st.Release == codename && (st.Status == "needed" || st.Status == "pending") {
					out = append(out, UbuntuCVE{cv.ID, cv.Priority, st.Status, cv.Description, cv.CVSS3})
				}
			}
		}
	}
	total := raw.Total
	if total < len(out) {
		total = len(out)
	}
	return out, total, nil
}

// ---------------------------------------------------------------- GitHub Security Advisories (php-src)

type GHSA struct {
	ID, CVE, Summary, Severity, URL, Published string
	Ranges                                     []GHSARange
}

type GHSARange struct{ Range, Patched string }

// PHPAdvisories devuelve los avisos de seguridad publicados por el proyecto PHP en GitHub.
func (c *Client) PHPAdvisories() ([]GHSA, error) {
	var raw []struct {
		ID        string `json:"ghsa_id"`
		CVE       string `json:"cve_id"`
		Summary   string `json:"summary"`
		Severity  string `json:"severity"`
		URL       string `json:"html_url"`
		Published string `json:"published_at"`
		Vulns     []struct {
			Range   string `json:"vulnerable_version_range"`
			Patched string `json:"patched_versions"`
		} `json:"vulnerabilities"`
	}
	if err := c.fetch("GitHub Advisories", "https://api.github.com/repos/php/php-src/security-advisories?per_page=30", 6*time.Hour, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]GHSA, 0, len(raw))
	for _, r := range raw {
		g := GHSA{ID: r.ID, CVE: r.CVE, Summary: r.Summary, Severity: strings.ToLower(r.Severity), URL: r.URL, Published: r.Published}
		for _, v := range r.Vulns {
			g.Ranges = append(g.Ranges, GHSARange{v.Range, v.Patched})
		}
		out = append(out, g)
	}
	return out, nil
}
