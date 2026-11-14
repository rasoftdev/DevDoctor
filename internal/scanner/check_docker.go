package scanner

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"devdoctor/internal/sh"
)

type ContainerInfo struct {
	Name     string         `json:"name"`
	Image    string         `json:"image"`
	State    string         `json:"state"`
	Restarts int            `json:"restarts"`
	User     string         `json:"user"`
	Ports    []string       `json:"ports,omitempty"`
	CPU      string         `json:"cpu,omitempty"`
	Mem      string         `json:"mem,omitempty"`
	Versions []VersionInfo  `json:"versions,omitempty"`
	AgeDays  int            `json:"age_days"`
	Vulns    map[string]int `json:"vulns,omitempty"`
}

type dockerInspect struct {
	ID    string `json:"Id"`
	Name  string
	Image string
	State struct {
		Status     string
		Running    bool
		Restarting bool
		OOMKilled  bool
		ExitCode   int
	}
	RestartCount int
	Config       struct {
		Image string
		User  string
		Env   []string
	}
	HostConfig struct {
		Privileged   bool
		NetworkMode  string
		Binds        []string
		PortBindings map[string][]struct{ HostIp, HostPort string }
	}
	Mounts []struct{ Source string }
}

var (
	rePHP   = regexp.MustCompile(`PHP (\d+\.\d+\.\d+)`)
	reNode  = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)
	reNginx = regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`)
)

func checkDocker(c *Collector, s *Scanner) {
	if !sh.Have("docker") {
		return
	}
	if out, err := sh.Run(10*time.Second, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		c.add("Docker", "info", "Docker está instalado pero no responde", sh.Trunc(out, 300),
			"systemctl status docker  ·  ¿tiene DevDoctor acceso a /var/run/docker.sock?")
		return
	}
	ids, _ := sh.Run(10*time.Second, "docker", "ps", "-aq")
	idList := strings.Fields(ids)
	if len(idList) == 0 {
		return
	}
	if len(idList) > 60 {
		idList = idList[:60]
	}
	raw, err := sh.RunStdout(20*time.Second, "", "docker", append([]string{"inspect"}, idList...)...)
	var cts []dockerInspect
	if err != nil || json.Unmarshal([]byte(raw), &cts) != nil {
		return
	}

	// Antigüedad de imágenes (una sola llamada).
	imgAge := map[string]int{}
	imgSet := map[string]bool{}
	for _, ct := range cts {
		imgSet[ct.Image] = true
	}
	var imgIDs []string
	for id := range imgSet {
		imgIDs = append(imgIDs, id)
	}
	if o, e := sh.RunStdout(15*time.Second, "", "docker", append([]string{"image", "inspect"}, imgIDs...)...); e == nil {
		var imgs []struct{ Id, Created string }
		if json.Unmarshal([]byte(o), &imgs) == nil {
			for _, im := range imgs {
				if t, e := time.Parse(time.RFC3339Nano, im.Created); e == nil {
					imgAge[im.Id] = int(time.Since(t).Hours() / 24)
				}
			}
		}
	}

	// CPU/RAM por contenedor.
	stats := map[string][2]string{}
	if o, _ := sh.RunStdout(20*time.Second, "", "docker", "stats", "--no-stream", "--format", "{{json .}}"); o != "" {
		for _, l := range strings.Split(o, "\n") {
			var st struct{ Name, CPUPerc, MemUsage, MemPerc string }
			if json.Unmarshal([]byte(l), &st) == nil && st.Name != "" {
				stats[st.Name] = [2]string{st.CPUPerc, st.MemUsage + " (" + st.MemPerc + ")"}
			}
		}
	}

	infos := make([]ContainerInfo, len(cts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	var rootOnes, latestOnes []string

	for i, ct := range cts {
		name := strings.TrimPrefix(ct.Name, "/")
		user := ct.Config.User
		if user == "" || user == "0" || user == "root" {
			user = "root"
			if ct.State.Running {
				rootOnes = append(rootOnes, name)
			}
		}
		info := ContainerInfo{Name: name, Image: ct.Config.Image, State: ct.State.Status, Restarts: ct.RestartCount,
			User: user, AgeDays: imgAge[ct.Image]}
		if st, ok := stats[name]; ok {
			info.CPU, info.Mem = st[0], st[1]
		}
		for p, binds := range ct.HostConfig.PortBindings {
			for _, b := range binds {
				pub := b.HostIp == "" || b.HostIp == "0.0.0.0" || b.HostIp == "::"
				info.Ports = append(info.Ports, fmt.Sprintf("%s→%s", b.HostPort, p))
				cont := strings.Split(p, "/")[0]
				if r, ok := riskyPorts[atoi(cont)]; ok && pub && r.sev == "crit" {
					c.add("Docker", "crit", fmt.Sprintf("Contenedor «%s» publica %s (puerto %s) a toda la red", name, r.name, b.HostPort), "",
						fmt.Sprintf("Publica solo en loopback: -p 127.0.0.1:%s:%s", b.HostPort, cont))
				}
			}
		}
		sort.Strings(info.Ports)

		tag := ct.Config.Image
		if !strings.Contains(strings.TrimPrefix(tag, "sha256:"), ":") || strings.HasSuffix(tag, ":latest") {
			latestOnes = append(latestOnes, name+" ("+tag+")")
		}

		// hallazgos de configuración / estado
		if ct.HostConfig.Privileged {
			c.add("Docker", "crit", fmt.Sprintf("Contenedor «%s» corre en modo --privileged", name),
				"Tiene acceso casi total al anfitrión: un fallo dentro del contenedor compromete el servidor.", "Quita privileged y concede solo las capabilities necesarias (--cap-add).")
		}
		socks := append([]string{}, ct.HostConfig.Binds...)
		for _, m := range ct.Mounts {
			socks = append(socks, m.Source)
		}
		for _, b := range socks {
			if strings.Contains(b, "/var/run/docker.sock") || strings.Contains(b, "/run/docker.sock") {
				c.add("Docker", "crit", fmt.Sprintf("Contenedor «%s» monta docker.sock", name),
					"Equivale a dar root del anfitrión a todo lo que corra dentro.", "Evita montarlo o usa un proxy de socket de solo lectura (docker-socket-proxy).")
				break
			}
		}
		switch {
		case ct.State.Restarting:
			logs, _ := sh.Run(8*time.Second, "docker", "logs", "--tail", "6", name)
			c.add("Docker", "crit", fmt.Sprintf("Contenedor «%s» en bucle de reinicios (%d reinicios)", name, ct.RestartCount), sh.Trunc(logs, 500), "docker logs "+name)
		case ct.State.OOMKilled:
			c.add("Docker", "crit", fmt.Sprintf("Contenedor «%s» fue matado por falta de memoria (OOM)", name), "", "Aumenta --memory o reduce el consumo de la app.")
		case !ct.State.Running && ct.State.ExitCode != 0:
			logs, _ := sh.Run(8*time.Second, "docker", "logs", "--tail", "6", name)
			c.add("Docker", "warn", fmt.Sprintf("Contenedor «%s» terminó con error (código %d)", name, ct.State.ExitCode), sh.Trunc(logs, 500), "docker logs "+name)
		case ct.RestartCount > 5:
			c.add("Docker", "warn", fmt.Sprintf("Contenedor «%s» se ha reiniciado %d veces", name, ct.RestartCount), "", "docker logs "+name)
		}
		switch {
		case info.AgeDays > 540:
			c.add("Docker", "warn", fmt.Sprintf("La imagen de «%s» tiene %d días sin reconstruirse", name, info.AgeDays), ct.Config.Image, "Reconstruye/actualiza la imagen base para recibir parches de seguridad.")
		case info.AgeDays > 240:
			c.add("Docker", "info", fmt.Sprintf("La imagen de «%s» tiene %d días", name, info.AgeDays), ct.Config.Image, "docker pull / reconstruir.")
		}

		infos[i] = info

		// versiones internas (contenedores en ejecución)
		if ct.State.Running {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, ct dockerInspect, name string) {
				defer wg.Done()
				defer func() { <-sem; recover() }()
				vs := containerVersions(ct)
				for _, v := range vs {
					if v.Status == "crit" || v.Status == "warn" {
						c.add("Docker", v.Status, fmt.Sprintf("«%s»: %s %s — %s", name, v.Name, v.Version, v.Note), "Imagen: "+ct.Config.Image,
							"Actualiza la imagen a una versión con soporte (cambia el tag en tu Dockerfile/compose y reconstruye).")
					}
				}
				mu.Lock()
				infos[i].Versions = vs
				mu.Unlock()
			}(i, ct, name)
		}
	}
	wg.Wait()

	if len(latestOnes) > 0 {
		c.add("Docker", "warn", fmt.Sprintf("%d contenedores usan etiqueta «latest» o sin versión fija", len(latestOnes)), strings.Join(latestOnes, "\n"),
			"Fija versiones concretas (p. ej. php:8.3-fpm) para despliegues reproducibles.")
	}
	if len(rootOnes) > 0 {
		c.add("Docker", "info", fmt.Sprintf("%d contenedores corren como root", len(rootOnes)), strings.Join(rootOnes, ", "), "Usa USER no privilegiado en el Dockerfile o --user.")
	}

	scanImagesTrivy(c, s, cts, infos)

	c.mu.Lock()
	c.R.Containers = infos
	c.mu.Unlock()
}

func containerVersions(ct dockerInspect) []VersionInfo {
	env := map[string]string{}
	for _, e := range ct.Config.Env {
		if i := strings.Index(e, "="); i > 0 {
			env[e[:i]] = e[i+1:]
		}
	}
	var out []VersionInfo
	add := func(name, v string) {
		st, note := "ok", ""
		switch name {
		case "PHP":
			st, note = phpStatus(v)
		case "Node.js":
			st, note = nodeStatus(v)
		}
		out = append(out, VersionInfo{name, v, st, note})
	}
	have := map[string]bool{}
	if v := env["PHP_VERSION"]; v != "" {
		add("PHP", v)
		have["PHP"] = true
	}
	if v := env["NODE_VERSION"]; v != "" {
		add("Node.js", v)
		have["Node.js"] = true
	}
	if v := env["PYTHON_VERSION"]; v != "" {
		add("Python", v)
	}
	if v := env["GOLANG_VERSION"]; v != "" {
		add("Go", strings.TrimPrefix(v, "go"))
	}
	if v := env["NGINX_VERSION"]; v != "" {
		add("Nginx", v)
		have["Nginx"] = true
	}
	// Complemento con docker exec para lo que no venga en el entorno (si hay shell).
	if !have["PHP"] || !have["Node.js"] || !have["Nginx"] {
		res, err := sh.Run(8*time.Second, "docker", "exec", ct.ID, "sh", "-c",
			"php -v 2>/dev/null | head -1; node -v 2>/dev/null; nginx -v 2>&1 | head -1")
		if err == nil {
			if m := rePHP.FindStringSubmatch(res); m != nil && !have["PHP"] {
				add("PHP", m[1])
			}
			if m := reNginx.FindStringSubmatch(res); m != nil && !have["Nginx"] {
				add("Nginx", m[1])
			}
			for _, l := range strings.Split(res, "\n") {
				if m := reNode.FindStringSubmatch(strings.TrimSpace(l)); m != nil && strings.HasPrefix(strings.TrimSpace(l), "v") && !have["Node.js"] {
					add("Node.js", m[1])
				}
			}
		}
	}
	return out
}

// scanImagesTrivy usa trivy (si existe) para contar CVEs HIGH/CRITICAL por imagen.
func scanImagesTrivy(c *Collector, s *Scanner, cts []dockerInspect, infos []ContainerInfo) {
	if !sh.Have("trivy") {
		c.add("Docker", "info", "Para detectar CVEs dentro de las imágenes instala trivy",
			"DevDoctor lo usará automáticamente cuando esté disponible.", "apt install trivy  (o https://trivy.dev)")
		return
	}
	done := map[string]map[string]int{}
	scanned := 0
	for i, ct := range cts {
		if !ct.State.Running {
			continue
		}
		counts, ok := done[ct.Image]
		if !ok {
			if scanned >= 6 {
				continue
			}
			scanned++
			key := "trivy|" + ct.Image
			if v, hit := s.audits.Load(key); hit {
				counts, _ = v.(map[string]int)
			} else {
				out, _ := sh.RunStdout(150*time.Second, "", "trivy", "image", "--quiet", "--format", "json",
					"--severity", "HIGH,CRITICAL", "--scanners", "vuln", ct.Config.Image)
				var rep struct {
					Results []struct {
						Vulnerabilities []struct{ Severity string }
					}
				}
				if json.Unmarshal([]byte(out), &rep) == nil {
					counts = map[string]int{}
					for _, r := range rep.Results {
						for _, v := range r.Vulnerabilities {
							counts[strings.ToLower(v.Severity)]++
						}
					}
				}
				s.audits.Store(key, counts)
			}
			done[ct.Image] = counts
		}
		if counts == nil {
			continue
		}
		infos[i].Vulns = counts
		if counts["critical"] > 0 {
			c.add("Docker", "crit", fmt.Sprintf("Imagen %s: %d CVEs críticos y %d altos", ct.Config.Image, counts["critical"], counts["high"]),
				"Contenedor: "+infos[i].Name, "Actualiza la imagen base: docker pull + reconstruir. Detalle: trivy image "+ct.Config.Image)
		} else if counts["high"] > 0 {
			c.add("Docker", "warn", fmt.Sprintf("Imagen %s: %d CVEs altos", ct.Config.Image, counts["high"]), "Contenedor: "+infos[i].Name, "trivy image "+ct.Config.Image)
		}
	}
}
