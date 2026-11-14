package scanner

import (
	"devdoctor/internal/sh"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type riskyPort struct {
	name string
	sev  string
}

var riskyPorts = map[int]riskyPort{
	21: {"FTP (sin cifrar)", "warn"}, 23: {"Telnet", "crit"}, 1433: {"SQL Server", "crit"},
	3306: {"MySQL/MariaDB", "crit"}, 3389: {"RDP", "warn"}, 5432: {"PostgreSQL", "crit"},
	5900: {"VNC", "warn"}, 5984: {"CouchDB", "crit"}, 6379: {"Redis", "crit"},
	9200: {"Elasticsearch", "crit"}, 11211: {"Memcached", "crit"}, 27017: {"MongoDB", "crit"},
	2375: {"Docker API sin TLS", "crit"},
}

var procRe = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)

func checkPortsServices(c *Collector) {
	ports := scanPorts(c)
	checkServices(c, ports)
}

func scanPorts(c *Collector) []PortInfo {
	out, err := sh.Run(10*time.Second, "ss", "-H", "-tulnp")
	if err != nil && out == "" {
		c.add("Puertos", "info", "No se pudo ejecutar 'ss'", "Instala iproute2 para analizar puertos.", "")
		return nil
	}
	merged := map[string]*PortInfo{}
	var order []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		addr := strings.Split(local[:i], "%")[0]
		port, _ := strconv.Atoi(local[i+1:])
		exposed := addr == "0.0.0.0" || addr == "*" || addr == "[::]" || addr == "::"
		p := PortInfo{Proto: f[0], Addr: addr, Port: port, Exposed: exposed}
		if m := procRe.FindStringSubmatch(l); m != nil {
			p.Process, p.PID = m[1], atoi(m[2])
		}
		key := p.Proto + strconv.Itoa(port)
		if ex, ok := merged[key]; ok {
			ex.Exposed = ex.Exposed || exposed
			if ex.Process == "" {
				ex.Process, ex.PID = p.Process, p.PID
			}
			continue
		}
		merged[key] = &p
		order = append(order, key)
	}
	var res []PortInfo
	for _, k := range order {
		p := merged[k]
		if r, ok := riskyPorts[p.Port]; ok && p.Exposed && p.Proto == "tcp" {
			p.Note = r.name + " expuesto a toda la red"
			who := p.Process
			if who == "" {
				who = "proceso desconocido"
			}
			c.add("Puertos", r.sev, fmt.Sprintf("Puerto %d (%s) abierto a todas las interfaces", p.Port, r.name),
				"Escucha en "+p.Addr+" — "+who,
				fmt.Sprintf("Haz que escuche solo en 127.0.0.1 (bind-address) o bloquéalo con el firewall: ufw deny %d", p.Port))
		}
		res = append(res, *p)
	}
	c.mu.Lock()
	c.R.Ports = res
	c.mu.Unlock()
	return res
}

var svcCandidates = regexp.MustCompile(`^(nginx|apache2|httpd|mysql|mysqld|mariadb|postgresql|redis-server|redis|docker|ssh|sshd|fail2ban|cron|crond|supervisor|supervisord|memcached|mongod|elasticsearch|rabbitmq-server|php[0-9.]*-fpm|ufw|firewalld|chrony|chronyd|systemd-timesyncd|caddy|traefik|haproxy|varnish|cloudflared|certbot\.timer)\.(service|timer)$`)

func checkServices(c *Collector, ports []PortInfo) {
	if !sh.Have("systemctl") {
		c.add("Servicios", "info", "systemd no disponible", "No se pueden revisar servicios con systemctl.", "")
		return
	}
	out, _ := sh.Run(10*time.Second, "systemctl", "list-unit-files", "--no-legend", "--no-pager", "--type=service,timer")
	known := map[string]bool{}
	var svcs []ServiceInfo
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !svcCandidates.MatchString(f[0]) {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSuffix(f[0], ".service"), ".timer")
		if f[0] == "certbot.timer" {
			name = "certbot.timer"
		}
		if known[name] {
			continue
		}
		known[name] = true
		act, _ := sh.Run(5*time.Second, "systemctl", "is-active", f[0])
		svcs = append(svcs, ServiceInfo{Name: name, Active: strings.TrimSpace(act), Enabled: f[1]})
	}

	holder := map[int]string{}
	for _, p := range ports {
		if p.Proto == "tcp" {
			holder[p.Port] = p.Process
		}
	}
	for _, s := range svcs {
		if s.Active == "active" || s.Active == "activating" {
			continue
		}
		if s.Enabled != "enabled" && s.Active != "failed" {
			continue
		}
		detail := ""
		if jl, _ := sh.Run(6*time.Second, "journalctl", "-u", s.Name, "-n", "6", "--no-pager", "-o", "cat"); jl != "" {
			detail = sh.Trunc(jl, 500)
		}
		// Conflicto de puertos típico entre servidores web.
		if s.Name == "nginx" || s.Name == "apache2" || s.Name == "httpd" {
			own := map[string]bool{s.Name: true}
			if s.Name != "nginx" {
				own["apache2"], own["httpd"] = true, true
			}
			for _, port := range []int{80, 443} {
				if h := holder[port]; h != "" && !own[h] {
					detail = fmt.Sprintf("CONFLICTO: el puerto %d está ocupado por «%s». ", port, h) + detail
					break
				}
			}
		}
		c.add("Servicios", "crit", fmt.Sprintf("Servicio %s caído (%s) pero habilitado", s.Name, s.Active), detail,
			fmt.Sprintf("systemctl status %s  ·  journalctl -u %s -n 50  ·  systemctl restart %s", s.Name, s.Name, s.Name))
	}

	// Otros servicios fallidos del sistema.
	if fl, _ := sh.Run(8*time.Second, "systemctl", "--failed", "--no-legend", "--no-pager", "--plain"); fl != "" {
		for _, l := range strings.Split(fl, "\n") {
			f := strings.Fields(l)
			if len(f) == 0 || !strings.Contains(f[0], ".") {
				continue
			}
			n := strings.TrimSuffix(f[0], ".service")
			if known[n] {
				continue
			}
			c.add("Servicios", "warn", "Unidad systemd fallida: "+f[0], "", "systemctl status "+f[0]+" ; systemctl reset-failed "+f[0])
		}
	}
	c.mu.Lock()
	c.R.Services = svcs
	c.mu.Unlock()
}
