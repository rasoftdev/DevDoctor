package scanner

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"devdoctor/internal/sh"
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
			c.add("Security", "crit", "SSH allows direct root login with a password", "",
				"PermitRootLogin prohibit-password  (in /etc/ssh/sshd_config) and systemctl reload ssh")
		}
		if sshCfg["permitemptypasswords"] == "yes" {
			c.add("Security", "crit", "SSH allows empty passwords", "", "PermitEmptyPasswords no")
		}
		if sshCfg["passwordauthentication"] == "yes" {
			c.add("Security", "warn", "SSH accepts password authentication", "Exposed to brute force.",
				"Use SSH keys and PasswordAuthentication no (after verifying you can log in with your key).")
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
		c.add("Security", "warn", "No active firewall detected", "Every listening port is reachable from the network.",
			"ufw default deny incoming && ufw allow 22 && ufw allow 80,443/tcp && ufw enable")
	}

	// --- fail2ban ---
	if out, _ := sh.Run(4*time.Second, "systemctl", "is-active", "fail2ban"); strings.TrimSpace(out) != "active" {
		c.add("Security", "info", "fail2ban is not active", "It blocks IPs with repeated failed logins.",
			"apt install fail2ban && systemctl enable --now fail2ban")
	}

	// --- Pending updates ---
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
			c.add("Security", "crit", M("%d pending SECURITY updates (%d in total)", sec, total), strings.Join(secPk, ", "), "apt update && apt upgrade")
		case total > 0:
			c.add("Security", "info", M("%d packages have updates available", total), "", "apt update && apt upgrade")
		}
		if fi, err := os.Stat("/var/lib/apt/periodic/update-success-stamp"); err == nil && time.Since(fi.ModTime()) > 10*24*time.Hour {
			c.add("Security", "info", "The apt package list has not been refreshed for over 10 days",
				"Pending-vulnerability data may be out of date.", "apt update")
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
				c.add("Security", "crit", M("%d pending security updates", n), "", "dnf upgrade --security")
			}
		}
	}
	if sh.Exists("/var/run/reboot-required") {
		pk := strings.TrimSpace(sh.ReadFile("/var/run/reboot-required.pkgs"))
		c.add("Security", "warn", "The server needs a reboot (kernel/library update)", pk, "Schedule a reboot: reboot")
	}

	// --- Accounts ---
	for _, l := range strings.Split(sh.ReadFile("/etc/passwd"), "\n") {
		f := strings.Split(l, ":")
		if len(f) > 3 && f[2] == "0" && f[0] != "root" {
			c.add("Security", "crit", M("User \"%s\" has UID 0 (equivalent to root)", f[0]), "", "Review /etc/passwd; remove or fix the account.")
		}
	}
	for _, l := range strings.Split(sh.ReadFile("/etc/shadow"), "\n") {
		f := strings.Split(l, ":")
		if len(f) > 1 && f[0] != "" && f[1] == "" {
			c.add("Security", "crit", M("Account \"%s\" has no password", f[0]), "", "passwd -l "+f[0])
		}
	}

	// --- Clock ---
	if sh.Have("timedatectl") {
		if out, _ := sh.Run(4*time.Second, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); strings.TrimSpace(out) == "no" {
			c.add("Security", "info", "Clock is not synchronized via NTP", "It can break certificates, tokens and logs.", "timedatectl set-ntp true")
		}
	}

	// --- SSH intrusion attempts (24 h) ---
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
		c.add("Security", "warn", M("%d recent failed SSH logins from %d IPs", total, len(counts)),
			"A brute-force attack is ongoing or happened recently.", "Install fail2ban, use SSH keys, or restrict the port/IPs with the firewall.")
	} else if total >= 30 {
		c.add("Security", "info", M("%d recent failed SSH logins", total), "", "Consider fail2ban.")
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

// ---------------- Resources ----------------

func checkResources(c *Collector) {
	// brief wait for the sampler to have disk data
	var sn = c.sam.Get()
	for i := 0; i < 5 && len(sn.Disks) == 0; i++ {
		time.Sleep(500 * time.Millisecond)
		sn = c.sam.Get()
	}
	for _, d := range sn.Disks {
		switch {
		case d.Pct >= 95:
			c.add("Resources", "crit", M("Disk %s at %.0f%%", d.Mount, d.Pct), d.FS,
				"du -xh "+d.Mount+" --max-depth=2 | sort -h | tail -20  ·  journalctl --vacuum-size=200M  ·  apt clean")
		case d.Pct >= 85:
			c.add("Resources", "warn", M("Disk %s at %.0f%%", d.Mount, d.Pct), d.FS, "du -xh "+d.Mount+" --max-depth=2 | sort -h | tail -20")
		}
		if d.InodePct >= 90 {
			c.add("Resources", "crit", M("Inodes running out on %s (%.0f%%)", d.Mount, d.InodePct),
				"You will get \"No space left\" errors even with free space.", "Look for directories with millions of small files (sessions, cache, mail).")
		}
	}
	if sn.MemTotal > 0 {
		if p := float64(sn.MemUsed) / float64(sn.MemTotal) * 100; p >= 92 {
			c.add("Resources", "crit", M("RAM at %.0f%%", p), "",
				"ps aux --sort=-%mem | head ; consider more RAM or tune PHP-FPM/Node workers.")
		} else if p >= 85 {
			c.add("Resources", "warn", M("RAM at %.0f%%", p), "", "ps aux --sort=-%mem | head")
		}
	}
	if sn.SwapTotal == 0 && sn.MemTotal > 0 && sn.MemTotal < 4<<30 {
		c.add("Resources", "info", "No swap on a low-RAM server", "A memory spike can trigger the OOM killer.",
			"fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile")
	} else if sn.SwapTotal > 0 && float64(sn.SwapUsed)/float64(sn.SwapTotal) > 0.5 {
		c.add("Resources", "warn", M("Swap usage at %.0f%%", float64(sn.SwapUsed)/float64(sn.SwapTotal)*100), "The system is under memory pressure.", "")
	}
	if sn.Cores > 0 && sn.Load[1] > float64(sn.Cores)*1.5 {
		c.add("Resources", "warn", M("High load: load15 %.2f on %d cores", sn.Load[2], sn.Cores), "", "top / htop to find the culprit process.")
	}
	if sn.Zombies > 5 {
		c.add("Resources", "info", M("%d zombie processes", sn.Zombies), "", "Restart the parent process that is not reaping its children.")
	}
	if out, _ := sh.Run(10*time.Second, "journalctl", "-k", "--since", "7 days ago", "--no-pager", "-o", "cat"); out != "" {
		if n := strings.Count(out, "Out of memory: Killed process"); n > 0 {
			c.add("Resources", "crit", M("The OOM killer terminated processes %d times this week", n), "The kernel ran out of memory.",
				"Add RAM/swap and limit workers (php-fpm pm.max_children, Node --max-old-space-size).")
		}
	}
}

var _ = fmt.Sprintf
