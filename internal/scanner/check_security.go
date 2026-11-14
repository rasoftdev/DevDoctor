package scanner

import (
	"devdoctor/internal/sh"
	"devdoctor/internal/sysinfo"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

func checkSecurity(c *Collector) {
	// --- SSH ---
	sshCfg := map[string]string{}
	if out, err := sh.Run(8*time.Second, "sshd", "-T"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if f := strings.SplitN(strings.TrimSpace(l), " ", 2); len(f) == 2 {
				sshCfg[strings.ToLower(f[0])] = strings.ToLower(f[1])
			}
		}
	} else {
		for _, l := range strings.Split(sh.ReadFile("/etc/ssh/sshd_config"), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if f := strings.Fields(l); len(f) >= 2 {
				if _, ok := sshCfg[strings.ToLower(f[0])]; !ok {
					sshCfg[strings.ToLower(f[0])] = strings.ToLower(f[1])
				}
			}
		}
	}
	if len(sshCfg) > 0 {
		if sshCfg["permitrootlogin"] == "yes" {
			c.add("Seguridad", "crit", "SSH permite login directo como root con contraseña", "", "PermitRootLogin prohibit-password  (en /etc/ssh/sshd_config) y systemctl reload ssh")
		}
		if sshCfg["permitemptypasswords"] == "yes" {
			c.add("Seguridad", "crit", "SSH permite contraseñas vacías", "", "PermitEmptyPasswords no")
		}
		if sshCfg["passwordauthentication"] == "yes" {
			c.add("Seguridad", "warn", "SSH acepta autenticación por contraseña", "Expuesto a fuerza bruta.", "Usa claves SSH y PasswordAuthentication no (tras verificar que puedes entrar con tu clave).")
		}
	}

	// --- Firewall ---
	fw := false
	if sh.Have("ufw") {
		if out, _ := sh.Run(5*time.Second, "ufw", "status"); strings.Contains(out, "Status: active") {
			fw = true
		}
	}
	if !fw && sh.Have("firewall-cmd") {
		if out, _ := sh.Run(5*time.Second, "firewall-cmd", "--state"); strings.Contains(out, "running") {
			fw = true
		}
	}
	if !fw && sh.Have("nft") {
		if out, _ := sh.Run(5*time.Second, "nft", "list", "ruleset"); strings.Count(out, "\n") > 12 {
			fw = true
		}
	}
	if !fw && sh.Have("iptables") {
		if out, _ := sh.Run(5*time.Second, "iptables", "-S"); strings.Contains(out, "-P INPUT DROP") || strings.Count(out, "\n") > 6 {
			fw = true
		}
	}
	if !fw {
		c.add("Seguridad", "warn", "No se detecta un firewall activo", "Todos los puertos en escucha son alcanzables desde la red.", "ufw default deny incoming && ufw allow 22 && ufw allow 80,443/tcp && ufw enable")
	}

	// --- fail2ban ---
	if out, _ := sh.Run(4*time.Second, "systemctl", "is-active", "fail2ban"); strings.TrimSpace(out) != "active" {
		c.add("Seguridad", "info", "fail2ban no está activo", "Bloquea IPs con intentos repetidos de login.", "apt install fail2ban && systemctl enable --now fail2ban")
	}

	// --- Actualizaciones pendientes ---
	if sh.Have("apt-get") {
		out, _ := sh.Run(40*time.Second, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")
		total, sec := 0, 0
		var secPk []string
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "Inst ") {
				total++
				if strings.Contains(l, "-security") || strings.Contains(l, "Security") {
					sec++
					if len(secPk) < 8 {
						secPk = append(secPk, strings.Fields(l)[1])
					}
				}
			}
		}
		switch {
		case sec > 0:
			c.add("Seguridad", "crit", fmt.Sprintf("%d actualizaciones de SEGURIDAD pendientes (%d en total)", sec, total), strings.Join(secPk, ", "), "apt update && apt upgrade")
		case total > 0:
			c.add("Seguridad", "info", fmt.Sprintf("%d paquetes con actualización disponible", total), "", "apt update && apt upgrade")
		}
		if fi, err := os.Stat("/var/lib/apt/periodic/update-success-stamp"); err == nil && time.Since(fi.ModTime()) > 10*24*time.Hour {
			c.add("Seguridad", "info", "La lista de paquetes apt no se actualiza hace más de 10 días", "Los datos de vulnerabilidades pendientes pueden estar desactualizados.", "apt update")
		}
	} else if sh.Have("dnf") {
		out, err := sh.Run(60*time.Second, "dnf", "-q", "check-update", "--security")
		if err != nil && strings.TrimSpace(out) != "" {
			n := 0
			for _, l := range strings.Split(out, "\n") {
				if f := strings.Fields(l); len(f) == 3 {
					n++
				}
			}
			if n > 0 {
				c.add("Seguridad", "crit", fmt.Sprintf("%d actualizaciones de seguridad pendientes", n), "", "dnf upgrade --security")
			}
		}
	}
	if sh.Exists("/var/run/reboot-required") {
		pk := strings.TrimSpace(sh.ReadFile("/var/run/reboot-required.pkgs"))
		c.add("Seguridad", "warn", "El servidor necesita reiniciarse (actualización de kernel/librerías)", pk, "Programa un reinicio: reboot")
	}

	// --- Cuentas ---
	for _, l := range strings.Split(sh.ReadFile("/etc/passwd"), "\n") {
		f := strings.Split(l, ":")
		if len(f) > 3 && f[2] == "0" && f[0] != "root" {
			c.add("Seguridad", "crit", "Usuario «"+f[0]+"» con UID 0 (equivale a root)", "", "Revisa /etc/passwd; elimina o corrige la cuenta.")
		}
	}
	for _, l := range strings.Split(sh.ReadFile("/etc/shadow"), "\n") {
		f := strings.Split(l, ":")
		if len(f) > 1 && f[0] != "" && f[1] == "" {
			c.add("Seguridad", "crit", "Cuenta «"+f[0]+"» sin contraseña", "", "passwd -l "+f[0])
		}
	}

	// --- Hora ---
	if sh.Have("timedatectl") {
		if out, _ := sh.Run(4*time.Second, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); strings.TrimSpace(out) == "no" {
			c.add("Seguridad", "info", "Reloj no sincronizado por NTP", "Puede romper certificados, tokens y logs.", "timedatectl set-ntp true")
		}
	}

	// --- Intentos de intrusión SSH (24 h) ---
	sshAttackers(c)
}

var failRe = regexp.MustCompile(`(?:Failed password|Invalid user|authentication failure).*?(?:from|rhost=)\s*([0-9a-fA-F:.]{3,45})`)

func sshAttackers(c *Collector) {
	out, err := sh.Run(15*time.Second, "journalctl", "_COMM=sshd", "--since", "24 hours ago", "--no-pager", "-o", "cat")
	if err != nil || strings.TrimSpace(out) == "" {
		out = tailFile("/var/log/auth.log", 2<<20)
		if out == "" {
			out = tailFile("/var/log/secure", 2<<20)
		}
	}
	counts := map[string]int{}
	total := 0
	for _, l := range strings.Split(out, "\n") {
		if m := failRe.FindStringSubmatch(l); m != nil {
			counts[m[1]]++
			total++
		}
	}
	if total == 0 {
		return
	}
	var at []Attacker
	for ip, n := range counts {
		at = append(at, Attacker{ip, n})
	}
	sort.Slice(at, func(i, j int) bool { return at[i].Count > at[j].Count })
	if len(at) > 8 {
		at = at[:8]
	}
	c.mu.Lock()
	c.R.Attackers = at
	c.mu.Unlock()
	if total >= 200 {
		c.add("Seguridad", "warn", fmt.Sprintf("%d intentos fallidos de login SSH recientes desde %d IPs", total, len(counts)), "Ataque de fuerza bruta en curso o histórico reciente.", "Instala fail2ban, usa claves SSH o cambia el puerto/restringe por firewall.")
	} else if total >= 30 {
		c.add("Seguridad", "info", fmt.Sprintf("%d intentos fallidos de login SSH recientes", total), "", "Considera fail2ban.")
	}
}

func tailFile(p string, max int64) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > max {
		f.Seek(fi.Size()-max, 0)
	}
	b := make([]byte, max)
	n, _ := f.Read(b)
	return string(b[:n])
}

// ---------------- Recursos ----------------

func checkResources(c *Collector) {
	// espera breve a que el sampler tenga datos de disco
	var sn sysinfo.Snapshot
	for i := 0; i < 5; i++ {
		sn = c.sam.Get()
		if len(sn.Disks) > 0 || i == 4 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, d := range sn.Disks {
		switch {
		case d.Pct >= 95:
			c.add("Recursos", "crit", fmt.Sprintf("Disco %s al %.0f%%", d.Mount, d.Pct), d.FS, "du -xh "+d.Mount+" --max-depth=2 | sort -h | tail -20  ·  journalctl --vacuum-size=200M  ·  apt clean")
		case d.Pct >= 85:
			c.add("Recursos", "warn", fmt.Sprintf("Disco %s al %.0f%%", d.Mount, d.Pct), d.FS, "du -xh "+d.Mount+" --max-depth=2 | sort -h | tail -20")
		}
		if d.InodePct >= 90 {
			c.add("Recursos", "crit", fmt.Sprintf("Inodos agotándose en %s (%.0f%%)", d.Mount, d.InodePct), "Habrá errores «No space left» aunque haya espacio libre.", "Busca directorios con millones de archivos pequeños (sesiones, caché, mail).")
		}
	}
	if sn.MemTotal > 0 {
		if p := float64(sn.MemUsed) / float64(sn.MemTotal) * 100; p >= 92 {
			c.add("Recursos", "crit", fmt.Sprintf("Memoria RAM al %.0f%%", p), "", "Revisa los procesos con ps aux --sort=-%mem | head ; considera más RAM o ajustar workers de PHP-FPM/Node.")
		} else if p >= 85 {
			c.add("Recursos", "warn", fmt.Sprintf("Memoria RAM al %.0f%%", p), "", "ps aux --sort=-%mem | head")
		}
	}
	if sn.SwapTotal == 0 && sn.MemTotal > 0 && sn.MemTotal < 4<<30 {
		c.add("Recursos", "info", "Sin swap en un servidor con poca RAM", "Un pico de memoria puede disparar el OOM killer.", "fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile")
	} else if sn.SwapTotal > 0 && float64(sn.SwapUsed)/float64(sn.SwapTotal) > 0.5 {
		c.add("Recursos", "warn", fmt.Sprintf("Swap en uso al %.0f%%", float64(sn.SwapUsed)/float64(sn.SwapTotal)*100), "El sistema está presionado por memoria.", "")
	}
	if sn.Cores > 0 && sn.Load[1] > float64(sn.Cores)*1.5 {
		c.add("Recursos", "warn", fmt.Sprintf("Carga alta: load15 %.2f con %d núcleos", sn.Load[2], sn.Cores), "", "top / htop para identificar el proceso.")
	}
	if sn.Zombies > 5 {
		c.add("Recursos", "info", fmt.Sprintf("%d procesos zombie", sn.Zombies), "", "Reinicia el proceso padre que no recoge a sus hijos.")
	}
	if out, _ := sh.Run(10*time.Second, "journalctl", "-k", "--since", "7 days ago", "--no-pager", "-o", "cat"); out != "" {
		if n := strings.Count(out, "Out of memory: Killed process"); n > 0 {
			c.add("Recursos", "crit", fmt.Sprintf("El OOM killer mató procesos %d veces esta semana", n), "El kernel se quedó sin memoria.", "Añade RAM/swap y limita workers (php-fpm pm.max_children, Node --max-old-space-size).")
		}
	}
}
