package scanner

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"devdoctor/internal/sh"
)

type riskyPort struct {
	name string
	sev  string
}

var riskyPorts = map[int]riskyPort{
	21: {"FTP (unencrypted)", "warn"}, 23: {"Telnet", "crit"}, 1433: {"SQL Server", "crit"},
	3306: {"MySQL/MariaDB", "crit"}, 3389: {"RDP", "warn"}, 5432: {"PostgreSQL", "crit"},
	5900: {"VNC", "warn"}, 5984: {"CouchDB", "crit"}, 6379: {"Redis", "crit"},
	9200: {"Elasticsearch", "crit"}, 11211: {"Memcached", "crit"}, 27017: {"MongoDB", "crit"},
	2375: {"Docker API without TLS", "crit"},
}

var procRe = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)

func checkPortsServices(c *Collector) {
	ports := scanPorts(c)
	checkServices(c, ports)
}

func scanPorts(c *Collector) []PortInfo {
	out, err := sh.Run(10*time.Second, "ss", "-H", "-tulnp")
	if err != nil && out == "" {
		c.add("Ports", "info", "Could not run 'ss'", "Install iproute2 to analyze ports.", "")
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
			p.noteM = M("%s exposed to the whole network", r.name)
			p.Note = p.noteM.Render("en")
			who := Msg{Tpl: p.Process}
			if p.Process == "" {
				who = M("unknown process")
			}
			c.add("Ports", r.sev, M("Port %d (%s) open on all interfaces", p.Port, r.name),
				M("Listening on %s — %s", p.Addr, who),
				M("Make it listen only on 127.0.0.1 (bind-address) or block it with the firewall: ufw deny %d", p.Port))
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
		c.add("Services", "info", "systemd not available", "Services cannot be checked without systemctl.", "")
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
		logs := ""
		if jl, _ := sh.Run(6*time.Second, "journalctl", "-u", s.Name, "-n", "6", "--no-pager", "-o", "cat"); jl != "" {
			logs = sh.Trunc(jl, 500)
		}
		var detail any = logs
		// Typical port conflict between web servers.
		if s.Name == "nginx" || s.Name == "apache2" || s.Name == "httpd" {
			own := map[string]bool{s.Name: true}
			if s.Name != "nginx" {
				own["apache2"], own["httpd"] = true, true
			}
			for _, port := range []int{80, 443} {
				if h := holder[port]; h != "" && !own[h] {
					detail = M("CONFLICT: port %d is held by \"%s\". %s", port, h, logs)
					break
				}
			}
		}
		c.add("Services", "crit", M("Service %s is down (%s) but enabled", s.Name, s.Active), detail,
			M("systemctl status %[1]s  ·  journalctl -u %[1]s -n 50  ·  systemctl restart %[1]s", s.Name))
	}

	// Other failed systemd units.
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
			c.add("Services", "warn", M("Failed systemd unit: %s", f[0]), "", M("systemctl status %[1]s ; systemctl reset-failed %[1]s", f[0]))
		}
	}
	c.mu.Lock()
	c.R.Services = svcs
	c.mu.Unlock()
}
