package scanner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"devdoctor/internal/version"
)

// URLCheck es el resultado de vigilar un sitio web configurado por el usuario.
type URLCheck struct {
	URL       string   `json:"url"`
	Final     string   `json:"final,omitempty"`
	Status    int      `json:"status"`
	LatencyMs int64    `json:"latency_ms"`
	HasTLS    bool     `json:"has_tls"`
	DaysLeft  int      `json:"days_left"`
	TLS       string   `json:"tls,omitempty"`
	Missing   []string `json:"missing,omitempty"`
	Error     string   `json:"error,omitempty"`
}

var verRe = regexp.MustCompile(`\d+\.\d+`)

// safeDialer impide que el monitor se use contra direcciones de metadatos de nube (169.254.0.0/16).
func safeDialer() *net.Dialer {
	return &net.Dialer{Timeout: 8 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		if ip := net.ParseIP(host); ip != nil && (ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return errors.New("address not allowed")
		}
		return nil
	}}
}

func checkURLs(c *Collector) {
	urls := c.cfg.URLs
	if len(urls) == 0 {
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem; recover() }()
			r := checkOneURL(c, u)
			c.mu.Lock()
			c.R.URLs = append(c.R.URLs, r)
			c.mu.Unlock()
		}(u)
	}
	wg.Wait()
	// orden estable según la configuración
	pos := map[string]int{}
	for i, u := range urls {
		pos[u] = i
	}
	c.mu.Lock()
	for i := 1; i < len(c.R.URLs); i++ {
		for j := i; j > 0 && pos[c.R.URLs[j].URL] < pos[c.R.URLs[j-1].URL]; j-- {
			c.R.URLs[j], c.R.URLs[j-1] = c.R.URLs[j-1], c.R.URLs[j]
		}
	}
	c.mu.Unlock()
}

func newClient(insecure bool) *http.Client {
	return &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			DialContext:       safeDialer().DialContext,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func checkOneURL(c *Collector, raw string) URLCheck {
	r := URLCheck{URL: raw}
	u, _ := url.Parse(raw)
	host := raw
	if u != nil {
		host = u.Host
	}
	req, _ := http.NewRequest("GET", raw, nil)
	req.Header.Set("User-Agent", "DevDoctor/"+version.Version+" (site monitor)")

	start := time.Now()
	certErr := ""
	resp, err := newClient(false).Do(req)
	if err != nil && strings.Contains(err.Error(), "x509:") {
		certErr = err.Error()
		resp, err = newClient(true).Do(req) // seguir para recoger el resto de datos
	}
	r.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		r.Error = shortErr(err)
		c.add("Websites", "crit", M("URL %s is unreachable", host), r.Error,
			"Check that the site/service is running and the URL is correct (curl -I <url>) and that the firewall allows it.")
		return r
	}
	defer resp.Body.Close()
	io.CopyN(io.Discard, resp.Body, 32<<10)

	r.Status = resp.StatusCode
	r.Final = resp.Request.URL.String()
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		r.HasTLS = true
		r.DaysLeft = int(time.Until(resp.TLS.PeerCertificates[0].NotAfter).Hours() / 24)
		r.TLS = tlsName(resp.TLS.Version)
	}

	switch {
	case r.Status >= 500:
		c.add("Websites", "crit", M("URL %s returned HTTP %d", host, r.Status), "", "Check the application and web server logs (journalctl -u <service> / error.log).")
	case r.Status >= 400:
		c.add("Websites", "warn", M("URL %s returned HTTP %d", host, r.Status), "", "Check the URL and the access rules of the site.")
	}
	if r.LatencyMs > 3000 {
		c.add("Websites", "warn", M("URL %s is slow (%d ms)", host, r.LatencyMs), "", "Check server load, database queries and caching.")
	}
	if certErr != "" {
		c.add("Websites", "crit", M("The certificate of %s is not valid", host), shortErr(errors.New(certErr)),
			"Renew or fix the certificate (certbot renew) and make sure the full chain is served.")
	} else if r.HasTLS {
		switch {
		case r.DaysLeft < 0:
			c.add("Websites", "crit", M("The certificate of %s has EXPIRED", host), "", "certbot renew --force-renewal  ·  then reload the web server.")
		case r.DaysLeft <= 14:
			c.add("Websites", "crit", M("The certificate of %s expires in %d days", host, r.DaysLeft), "", "certbot renew  ·  check the timer: systemctl status certbot.timer")
		case r.DaysLeft <= 30:
			c.add("Websites", "warn", M("The certificate of %s expires in %d days", host, r.DaysLeft), "", "Make sure automatic renewal works: certbot renew --dry-run")
		}
	}
	if u != nil && u.Scheme == "http" && resp.Request.URL.Scheme == "http" {
		c.add("Websites", "warn", M("%s is served over HTTP without redirecting to HTTPS", host), "", "Redirect all HTTP traffic to HTTPS with a 301 and enable HSTS.")
	}

	if resp.Request.URL.Scheme == "https" {
		h := resp.Header
		var miss []string
		if h.Get("Strict-Transport-Security") == "" {
			miss = append(miss, "Strict-Transport-Security")
		}
		if h.Get("X-Content-Type-Options") == "" {
			miss = append(miss, "X-Content-Type-Options")
		}
		if h.Get("Content-Security-Policy") == "" {
			miss = append(miss, "Content-Security-Policy")
		}
		if h.Get("X-Frame-Options") == "" && !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors") {
			miss = append(miss, "X-Frame-Options")
		}
		if h.Get("Referrer-Policy") == "" {
			miss = append(miss, "Referrer-Policy")
		}
		r.Missing = miss
		if len(miss) > 0 {
			sev := "info"
			if h.Get("Strict-Transport-Security") == "" {
				sev = "warn"
			}
			c.add("Websites", sev, M("%s is missing security headers: %s", host, strings.Join(miss, ", ")), "",
				"Add them in your web server or application configuration (check the result at securityheaders.com).")
		}
	}
	var leaks []string
	if s := resp.Header.Get("Server"); verRe.MatchString(s) {
		leaks = append(leaks, "Server: "+s)
	}
	if x := resp.Header.Get("X-Powered-By"); x != "" {
		leaks = append(leaks, "X-Powered-By: "+x)
	}
	if len(leaks) > 0 {
		c.add("Websites", "info", M("%s reveals software versions in its headers", host), strings.Join(leaks, "\n"),
			"Hide them: nginx server_tokens off;  Apache ServerTokens Prod;  PHP expose_php = Off")
	}
	return r
}

func tlsName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 140 {
		s = s[i+2:]
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
