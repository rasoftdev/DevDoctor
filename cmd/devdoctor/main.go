package main

import (
	"bufio"
	"crypto/rand"
	"devdoctor/internal/config"
	"devdoctor/internal/notify"
	"devdoctor/internal/scanner"
	"devdoctor/internal/server"
	"devdoctor/internal/sysinfo"
	"devdoctor/internal/version"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func main() {
	os.Setenv("PATH", os.Getenv("PATH")+":/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin")
	os.Setenv("COMPOSER_ALLOW_SUPERUSER", "1")
	os.Setenv("LC_ALL", "C")

	cmd, args := "run", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run", "serve":
		cmdRun(args)
	case "init":
		cmdInit(args)
	case "passwd":
		cmdPasswd(args)
	case "url":
		cmdURL(args)
	case "setup-code":
		cmdSetupCode(args)
	case "scan":
		cmdScan(args)
	case "paths":
		cmdPaths(args)
	case "notify":
		cmdNotify(args)
	case "update":
		cmdUpdate(args)
	case "uninstall":
		cmdUninstall(args)
	case "version", "-v", "--version":
		fmt.Println("devdoctor", version.Version)
	default:
		fmt.Println(`DevDoctor ` + version.Version + `

Usage: devdoctor <command> [options]

  init        Create the configuration, TLS certificate and (optionally) the account
              (--port, --host, --listen, --user, --password)
  run         Start the web dashboard (what the systemd service runs)
  url         Print the access URL
  setup-code  Print the one-time code used to create the account in the web UI
  passwd      Reset the username/password from the terminal (forgot it or locked out; --user, --password)
  scan        Run a diagnosis in the terminal (--json for JSON output)
  notify      Send a test notification to the configured Telegram/Slack channels (notify test)
  paths       List/add/remove extra folders where projects are searched (paths add /srv/apps)
  update      Update to the latest version (--check to only look, --ref, --force)
  uninstall   Remove DevDoctor from this server (--yes, --keep-config)
  version     Print the version`)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", config.DefaultPath(), "path to the configuration file")
}

func portFree(p int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	path := configFlag(fs)
	port := fs.Int("port", 0, "port (default: a random free port between 61000 and 64999)")
	host := fs.String("host", "", "public IP or domain shown in the URL (auto-detected if omitted)")
	user := fs.String("user", "admin", "username (only with --password; otherwise it is created in the web UI)")
	pass := fs.String("password", "", "password (optional; if omitted, you create it in the web UI on first access)")
	listen := fs.String("listen", "", "listen interface (empty = all; 127.0.0.1 if you will use Nginx/Apache as a proxy)")
	force := fs.Bool("force", false, "overwrite existing configuration")
	fs.Parse(args)

	if _, err := os.Stat(*path); err == nil && !*force {
		fmt.Println("Configuration already exists at", *path, "(use --force to recreate it).")
		cmdURL([]string{"--config", *path})
		return
	}
	p := *port
	if p == 0 {
		if p = pickPort(); p == 0 {
			fail(fmt.Errorf("could not find a free port; pick one with --port"))
		}
	} else if !portFree(p) {
		fail(fmt.Errorf("port %d is already in use; choose another with --port", p))
	}
	h := *host
	if h == "" {
		h = sysinfo.PrimaryIP()
	}
	// Sin --password: el usuario y la contraseña se definen en la web (primer acceso),
	// protegido por un código de un solo uso que se muestra aquí.
	cfg := config.Config{Port: p, Host: h, Listen: *listen, ScanIntervalMin: 15}
	if *pass != "" {
		cfg.Username = *user
		if err := cfg.SetPassword(*pass); err != nil {
			fail(err)
		}
	} else {
		cfg.SetupToken = config.RandomPassword(12)
	}
	cs := config.New(*path, cfg)
	if err := cs.Update(func(*config.Config) {}); err != nil {
		fail(err)
	}
	if _, err := config.EnsureCert(filepath.Dir(*path), h); err != nil {
		fail(err)
	}
	fmt.Printf("\n  DevDoctor listo\n  ───────────────\n  URL:        https://%s:%d\n", h, p)
	if cfg.SetupToken != "" {
		fmt.Printf("  Code:       %s\n\n  Open the URL, enter the code and create your username and password in the web UI.\n  (Lost the code? sudo devdoctor setup-code)\n", cfg.SetupToken)
	} else {
		fmt.Printf("  Usuario:    %s\n", *user)
	}
	fmt.Println("\n  El navegador avisará de certificado autofirmado: es normal, acepta la excepción.")
}

// cmdPasswd resets the dashboard credentials from the terminal (forgotten password, locked out...).
func cmdPasswd(args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	path := configFlag(fs)
	user := fs.String("user", "", "username (keeps the current one if omitted)")
	pass := fs.String("password", "", "new password (a random one is generated if omitted)")
	noRestart := fs.Bool("no-restart", false, "do not restart the service afterwards")
	fs.Parse(args)
	cs, err := config.Load(*path)
	if err != nil {
		if os.IsPermission(err) {
			fail(errors.New("permission denied reading " + *path + ": run with sudo"))
		}
		fail(err)
	}
	generated := false
	if *pass == "" {
		*pass, generated = config.RandomPassword(16), true
	}
	var perr error
	var finalUser string
	err = cs.Update(func(c *config.Config) {
		next := *c
		if *user != "" {
			next.Username = strings.TrimSpace(*user)
		}
		if next.Username == "" {
			next.Username = "admin" // account was never created in the web UI
		}
		if perr = next.SetPassword(*pass); perr != nil {
			return
		}
		next.SetupToken = "" // the account now exists: the one-time setup code is no longer needed
		*c = next
		finalUser = next.Username
	})
	if perr != nil {
		fail(perr)
	}
	if err != nil {
		fail(err)
	}
	fmt.Println("Credentials updated.")
	fmt.Println("  Username:", finalUser)
	if generated {
		fmt.Println("  Password:", *pass)
		fmt.Println("  (You can change it later in the dashboard: Account)")
	}

	// A restart closes every active session and clears the in-memory login lockouts.
	restarted := false
	if !*noRestart && os.Geteuid() == 0 {
		if out, _ := exec.Command("systemctl", "is-active", "devdoctor").Output(); strings.TrimSpace(string(out)) == "active" {
			restarted = exec.Command("systemctl", "restart", "devdoctor").Run() == nil
		}
	}
	if restarted {
		fmt.Println("The service was restarted: sessions were closed and login lockouts were cleared.")
	} else {
		fmt.Println("Restart the service to close sessions and clear login lockouts: sudo systemctl restart devdoctor")
	}
}

func cmdURL(args []string) {
	fs := flag.NewFlagSet("url", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	cs, err := config.Load(*path)
	if err != nil {
		fail(err)
	}
	c := cs.Get()
	fmt.Printf("https://%s:%d\n", c.Host, c.Port)
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	cs, err := config.Load(*path)
	if err != nil {
		fail(fmt.Errorf("could not read %s (%v). Run first: devdoctor init", *path, err))
	}
	fail(server.Serve(cs, filepath.Dir(*path)))
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	path := configFlag(fs)
	asJSON := fs.Bool("json", false, "JSON output")
	fs.Parse(args)
	cs, err := config.Load(*path)
	if err != nil {
		cs = config.New(*path, config.Config{ScanIntervalMin: 15})
	}
	sam := &sysinfo.Sampler{}
	sam.Start()
	r := scanner.New(cs, sam).RunSync()
	if *asJSON {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return
	}
	icons := map[string]string{"crit": "✖ CRITICAL", "warn": "▲ WARNING ", "info": "● INFO    ", "ok": "✔ OK      "}
	fmt.Printf("Health score: %d/100  (%d critical, %d warnings)  — %dms\n\n", r.Score, r.Counts["crit"], r.Counts["warn"], r.DurationMs)
	for _, f := range r.Findings {
		fmt.Printf("%s [%s] %s\n", icons[f.Severity], f.Category, f.Title)
		if f.Detail != "" {
			fmt.Println("           " + strings.ReplaceAll(f.Detail, "\n", "\n           "))
		}
		if f.Fix != "" {
			fmt.Println("           → " + f.Fix)
		}
	}
}

func cmdSetupCode(args []string) {
	fs := flag.NewFlagSet("setup-code", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	cs, err := config.Load(*path)
	if err != nil {
		fail(err)
	}
	c := cs.Get()
	if c.Configured() || c.SetupToken == "" {
		fmt.Println("The account is already set up. To reset it use: devdoctor passwd")
		return
	}
	fmt.Printf("URL:    https://%s:%d\nCódigo: %s\n", c.Host, c.Port, c.SetupToken)
}

// pickPort picks an unusual high port: random in 61000-64999, above the Linux ephemeral
// range (32768-60999, used for outgoing connections), and verified to be free.
func pickPort() int {
	lo, hi := 61000, 64999
	if f := strings.Fields(sysReadFile("/proc/sys/net/ipv4/ip_local_port_range")); len(f) == 2 {
		if top, err := strconv.Atoi(f[1]); err == nil && top >= lo && top < hi-1000 {
			lo = top + 1 // the system widened the ephemeral range: start above it
		}
	}
	for i := 0; i < 200; i++ {
		p := lo + int(binary.BigEndian.Uint16(randBytes(2)))%(hi-lo+1)
		if portFree(p) {
			return p
		}
	}
	return 0
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func sysReadFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

const repoRaw = "https://raw.githubusercontent.com/rasoftdev/DevDoctor"

func needRoot() {
	if os.Geteuid() != 0 {
		fail(errors.New("this command must be run as root (use sudo)"))
	}
}

// remoteVersion reads the published version number from the repository (a public file; nothing is sent).
func remoteVersion(ref string) (string, error) {
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Get(repoRaw + "/" + ref + "/internal/version/version.go")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	m := regexp.MustCompile(`Version\s*=\s*"([^"]+)"`).FindStringSubmatch(string(b))
	if m == nil {
		return "", errors.New("version not found")
	}
	return m[1], nil
}

func cmdUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	ref := fs.String("ref", "main", "branch or tag to install")
	check := fs.Bool("check", false, "only check whether a newer version exists")
	force := fs.Bool("force", false, "reinstall even if the version number is the same")
	fs.Parse(args)

	latest, err := remoteVersion(*ref)
	if err != nil {
		fail(fmt.Errorf("could not check the latest version: %w", err))
	}
	fmt.Printf("Installed: %s\nLatest:    %s (%s)\n", version.Version, latest, *ref)
	same := latest == version.Version
	if same && !*force {
		fmt.Println("DevDoctor is up to date. (Use --force to reinstall anyway.)")
		return
	}
	if *check {
		fmt.Println("An update is available. Run: sudo devdoctor update")
		return
	}
	needRoot()
	fmt.Println("Updating (your account, port and configuration are kept)...")
	cmd := exec.Command("bash", "-c", "curl -fsSL "+repoRaw+"/"+*ref+"/get.sh | bash")
	cmd.Env = append(os.Environ(), "DEVDOCTOR_REF="+*ref)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fail(fmt.Errorf("update failed: %w", err))
	}
}

func cmdUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	path := configFlag(fs)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	keep := fs.Bool("keep-config", false, "keep the configuration directory (account, port, certificate)")
	fs.Parse(args)
	needRoot()

	if !*yes {
		fmt.Print("This will remove DevDoctor from this server. Continue? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Println("Cancelled.")
			return
		}
	}
	step := func(msg string, err error) {
		if err != nil && !os.IsNotExist(err) {
			fmt.Printf("  [WARN] %s: %v\n", msg, err)
			return
		}
		fmt.Printf("  [OK]   %s\n", msg)
	}
	exec.Command("systemctl", "disable", "--now", "devdoctor").Run()
	step("service stopped and disabled", nil)
	step("removed /etc/systemd/system/devdoctor.service", os.Remove("/etc/systemd/system/devdoctor.service"))
	exec.Command("systemctl", "daemon-reload").Run()
	if _, err := os.Stat("/etc/fail2ban/filter.d/devdoctor.conf"); err == nil {
		os.Remove("/etc/fail2ban/filter.d/devdoctor.conf")
		os.Remove("/etc/fail2ban/jail.d/devdoctor.local")
		exec.Command("systemctl", "reload", "fail2ban").Run()
		step("removed the fail2ban jail", nil)
	}
	if *keep {
		fmt.Printf("  [OK]   configuration kept in %s\n", filepath.Dir(*path))
	} else if dir := filepath.Dir(*path); filepath.Base(dir) == "devdoctor" {
		step("removed "+dir, os.RemoveAll(dir))
	}
	if exe, err := os.Executable(); err == nil {
		step("removed "+exe, os.Remove(exe))
	}
	fmt.Println("DevDoctor has been uninstalled.")
}

// cmdPaths manages the extra folders where DevDoctor looks for projects (scan_roots in the config).
func cmdPaths(args []string) {
	fs := flag.NewFlagSet("paths", flag.ExitOnError)
	path := configFlag(fs)
	// allow: devdoctor paths add /srv/apps --config x   (subcommand first)
	sub, rest := "list", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, rest = args[0], args[1:]
	}
	fs.Parse(rest)
	cs, err := config.Load(*path)
	if err != nil {
		if os.IsPermission(err) {
			fail(errors.New("permission denied reading " + *path + ": run with sudo"))
		}
		fail(err)
	}
	switch sub {
	case "list":
		c := cs.Get()
		fmt.Println("Always searched: /var/www, /srv, /home, /opt, the Nginx/Apache document roots and the folders mounted by running Docker containers.")
		if len(c.ScanRoots) == 0 {
			fmt.Println("Extra folders: (none)  ->  add one with: sudo devdoctor paths add /path/to/projects")
			return
		}
		fmt.Println("Extra folders:")
		for _, p := range c.ScanRoots {
			fmt.Println("  ", p)
		}
	case "add", "remove", "rm":
		if fs.NArg() == 0 {
			fail(errors.New("usage: devdoctor paths " + sub + " /absolute/path"))
		}
		p := filepath.Clean(fs.Arg(0))
		if !filepath.IsAbs(p) {
			fail(errors.New("the path must be absolute: " + p))
		}
		if sub == "add" {
			if st, err := os.Stat(p); err != nil || !st.IsDir() {
				fail(errors.New("not a directory: " + p))
			}
		}
		err = cs.Update(func(c *config.Config) {
			var out []string
			for _, x := range c.ScanRoots {
				if x != p {
					out = append(out, x)
				}
			}
			if sub == "add" {
				out = append(out, p)
			}
			c.ScanRoots = out
		})
		if err != nil {
			fail(err)
		}
		if sub == "add" {
			fmt.Println("Added:", p, "(applies on the next scan; use \"Scan now\" in the dashboard)")
		} else {
			fmt.Println("Removed:", p)
		}
	default:
		fail(errors.New("unknown subcommand " + sub + " (use list, add or remove)"))
	}
}

// cmdNotify sends a test message to the notification channels configured in the dashboard.
func cmdNotify(args []string) {
	fs := flag.NewFlagSet("notify", flag.ExitOnError)
	path := configFlag(fs)
	sub, rest := "test", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, rest = args[0], args[1:]
	}
	fs.Parse(rest)
	if sub != "test" {
		fail(errors.New("unknown subcommand " + sub + " (use: devdoctor notify test)"))
	}
	cs, err := config.Load(*path)
	if err != nil {
		if os.IsPermission(err) {
			fail(errors.New("permission denied reading " + *path + ": run with sudo"))
		}
		fail(err)
	}
	n := cs.Get().Notify
	if !n.Enabled() {
		fail(errors.New("no notification channel is configured: add Telegram or Slack in the dashboard (Settings)"))
	}
	bad := false
	for _, r := range notify.Test(n) {
		if r.OK {
			fmt.Printf("  [OK]    %s: message sent\n", r.Channel)
		} else {
			bad = true
			fmt.Printf("  [ERROR] %s: %s\n", r.Channel, r.Error)
		}
	}
	if bad {
		os.Exit(1)
	}
}
