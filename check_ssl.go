package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var sslDirectiveRe = regexp.MustCompile(`(?m)^\s*(?:ssl_certificate|SSLCertificateFile)\s+"?([^;"\s]+)"?`)

func checkSSL(c *Collector) {
	paths := map[string]bool{}
	if m, _ := filepath.Glob("/etc/letsencrypt/live/*/cert.pem"); m != nil {
		for _, p := range m {
			paths[p] = true
		}
	}
	for _, root := range []string{"/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/caddy"} {
		filepath.WalkDir(root, func(p string, de os.DirEntry, err error) error {
			if err != nil || de.IsDir() {
				return nil
			}
			if fi, e := de.Info(); e != nil || fi.Size() > 1<<20 {
				return nil
			}
			for _, m := range sslDirectiveRe.FindAllStringSubmatch(readFile(p), -1) {
				paths[m[1]] = true
			}
			return nil
		})
	}
	seen := map[string]bool{}
	for p := range paths {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			c.add("SSL", "crit", "Certificado referenciado pero no encontrado: "+p, "La configuración del servidor web apunta a un archivo inexistente.", "Revisa la ruta o renueva el certificado (certbot renew).")
			continue
		}
		if seen[real] {
			continue
		}
		seen[real] = true
		ci, ok := parseCert(p, real)
		if !ok {
			continue
		}
		c.mu.Lock()
		c.R.Certs = append(c.R.Certs, ci)
		c.mu.Unlock()
		name := ci.Subject
		if len(ci.DNS) > 0 {
			name = strings.Join(ci.DNS, ", ")
		}
		switch {
		case ci.DaysLeft < 0:
			c.add("SSL", "crit", fmt.Sprintf("Certificado EXPIRADO hace %d días: %s", -ci.DaysLeft, name), ci.Path, "certbot renew --force-renewal  ·  y recarga el servidor web.")
		case ci.DaysLeft <= 14:
			c.add("SSL", "crit", fmt.Sprintf("Certificado expira en %d días: %s", ci.DaysLeft, name), ci.Path, "certbot renew  ·  revisa el timer: systemctl status certbot.timer")
		case ci.DaysLeft <= 30:
			c.add("SSL", "warn", fmt.Sprintf("Certificado expira en %d días: %s", ci.DaysLeft, name), ci.Path, "Verifica que la renovación automática funcione: certbot renew --dry-run")
		}
		if ci.SelfSigned && !strings.Contains(ci.Path, "ssl-cert-snakeoil") {
			c.add("SSL", "info", "Certificado autofirmado en uso: "+name, ci.Path, "Usa Let's Encrypt para sitios públicos.")
		}
	}

	// Sondeo local de HTTPS: ¿acepta protocolos obsoletos?
	c.mu.Lock()
	has443, has80 := false, false
	for _, p := range c.R.Ports {
		if p.Port == 443 && p.Proto == "tcp" {
			has443 = true
		}
		if p.Port == 80 && p.Proto == "tcp" {
			has80 = true
		}
	}
	c.mu.Unlock()
	if !has443 {
		// los puertos pueden no estar listos aún (check paralelo): sondeo directo
		if cn, err := net.DialTimeout("tcp", "127.0.0.1:443", 800*time.Millisecond); err == nil {
			cn.Close()
			has443 = true
		}
	}
	if has443 {
		old := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
		if cn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", "127.0.0.1:443", old); err == nil {
			cn.Close()
			c.add("SSL", "warn", "El servidor HTTPS acepta TLS 1.0/1.1 (obsoletos)", "", "Configura ssl_protocols TLSv1.2 TLSv1.3; (nginx) o SSLProtocol -all +TLSv1.2 +TLSv1.3 (Apache).")
		}
	} else if has80 {
		if cn, err := net.DialTimeout("tcp", "127.0.0.1:443", 800*time.Millisecond); err != nil {
			c.add("SSL", "warn", "Hay un sitio en el puerto 80 pero nada escucha en el 443 (sin HTTPS)", "", "Emite un certificado con certbot --nginx / --apache y redirige HTTP→HTTPS.")
		} else {
			cn.Close()
		}
	}
}

func parseCert(shown, real string) (CertInfo, bool) {
	b, err := os.ReadFile(real)
	if err != nil {
		return CertInfo{}, false
	}
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return CertInfo{}, false
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return CertInfo{}, false
		}
		return CertInfo{
			Path: shown, Subject: cert.Subject.CommonName, DNS: cert.DNSNames,
			Issuer: cert.Issuer.CommonName, NotAfter: cert.NotAfter,
			DaysLeft:   int(time.Until(cert.NotAfter).Hours() / 24),
			SelfSigned: cert.Subject.String() == cert.Issuer.String(),
		}, true
	}
}
