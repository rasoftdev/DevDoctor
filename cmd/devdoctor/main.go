package main

import (
	"devdoctor/internal/config"
	"devdoctor/internal/scanner"
	"devdoctor/internal/server"
	"devdoctor/internal/sysinfo"
	"devdoctor/internal/version"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	case "scan":
		cmdScan(args)
	case "version", "-v", "--version":
		fmt.Println("devdoctor", version.Version)
	default:
		fmt.Println(`DevDoctor ` + version.Version + `

Uso: devdoctor <comando> [opciones]

  init     Crea la configuración, el certificado TLS y el usuario (--port, --host, --user, --password)
  run      Inicia el dashboard web (lo que ejecuta el servicio systemd)
  url      Muestra la URL de acceso
  passwd   Cambia usuario/contraseña desde la terminal (--user, --password)
  scan     Ejecuta un diagnóstico en la terminal (--json para salida JSON)
  version  Muestra la versión`)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", config.DefaultPath(), "ruta del archivo de configuración")
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
	port := fs.Int("port", 0, "puerto (por defecto 9443, o el siguiente libre)")
	host := fs.String("host", "", "IP o dominio público para la URL (auto-detecta si se omite)")
	user := fs.String("user", "admin", "usuario del dashboard")
	pass := fs.String("password", "", "contraseña (se genera una aleatoria si se omite)")
	force := fs.Bool("force", false, "sobrescribir configuración existente")
	fs.Parse(args)

	if _, err := os.Stat(*path); err == nil && !*force {
		fmt.Println("Ya existe configuración en", *path, "(usa --force para recrearla).")
		cmdURL([]string{"--config", *path})
		return
	}
	p := *port
	if p == 0 {
		p = 9443
		for i := 0; i < 100 && !portFree(p); i++ {
			p++
		}
		if !portFree(p) {
			fail(fmt.Errorf("no encontré un puerto libre cerca de 9443"))
		}
	} else if !portFree(p) {
		fail(fmt.Errorf("el puerto %d ya está ocupado; elige otro con --port", p))
	}
	h := *host
	if h == "" {
		h = sysinfo.PrimaryIP()
	}
	generated := false
	if *pass == "" {
		*pass, generated = config.RandomPassword(16), true
	}
	cfg := config.Config{Port: p, Host: h, Username: *user, ScanIntervalMin: 15}
	if err := cfg.SetPassword(*pass); err != nil {
		fail(err)
	}
	cs := config.New(*path, cfg)
	if err := cs.Update(func(*config.Config) {}); err != nil {
		fail(err)
	}
	if _, err := config.EnsureCert(filepath.Dir(*path), h); err != nil {
		fail(err)
	}
	fmt.Printf("\n  DevDoctor listo\n  ───────────────\n  URL:        https://%s:%d\n  Usuario:    %s\n", h, p, *user)
	if generated {
		fmt.Printf("  Contraseña: %s   (cámbiala en el dashboard → Cuenta)\n", *pass)
	}
	fmt.Println("\n  El navegador avisará de certificado autofirmado: es normal, acepta la excepción.")
}

func cmdPasswd(args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	path := configFlag(fs)
	user := fs.String("user", "", "nuevo usuario (opcional)")
	pass := fs.String("password", "", "nueva contraseña (aleatoria si se omite)")
	fs.Parse(args)
	cs, err := config.Load(*path)
	if err != nil {
		fail(err)
	}
	generated := false
	if *pass == "" {
		*pass, generated = config.RandomPassword(16), true
	}
	var perr error
	err = cs.Update(func(c *config.Config) {
		if *user != "" {
			c.Username = *user
		}
		perr = c.SetPassword(*pass)
	})
	if perr != nil {
		fail(perr)
	}
	if err != nil {
		fail(err)
	}
	fmt.Println("Credenciales actualizadas. Reinicia el servicio para cerrar sesiones activas: systemctl restart devdoctor")
	if generated {
		fmt.Println("Nueva contraseña:", *pass)
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
		fail(fmt.Errorf("no se pudo leer %s (%v). Ejecuta primero: devdoctor init", *path, err))
	}
	fail(server.Serve(cs, filepath.Dir(*path)))
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	path := configFlag(fs)
	asJSON := fs.Bool("json", false, "salida JSON")
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
	icons := map[string]string{"crit": "✖ CRÍTICO", "warn": "▲ AVISO  ", "info": "● INFO   ", "ok": "✔ OK     "}
	fmt.Printf("Puntuación de salud: %d/100  (%d críticos, %d avisos)  — %dms\n\n", r.Score, r.Counts["crit"], r.Counts["warn"], r.DurationMs)
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
