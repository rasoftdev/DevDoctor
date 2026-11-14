# DevDoctor

Agente + dashboard web para servidores Linux. Un único binario (Go, sin dependencias) que:

- sirve un dashboard en `https://IP:PUERTO` con login (usuario/contraseña configurables),
- muestra CPU, RAM, swap, red, discos, procesos y carga **en vivo**,
- diagnostica versiones PHP/Node (EOL), puertos y conflictos, permisos, servicios caídos,
  contenedores Docker (versiones internas, imágenes, configuración peligrosa, CVEs con trivy),
  SSL/certificados, dependencias (Composer/npm: requisitos, extensiones, `audit`) y seguridad
  (SSH, firewall, parches pendientes, intentos de intrusión).

DevDoctor **sólo lee** el sistema; nunca modifica nada fuera de `/etc/devdoctor`.

## Instalar en el servidor

```bash
# En tu máquina de desarrollo (Windows/Linux/Mac con Go):
bash scripts/build.sh            # genera dist/
scp -r dist user@servidor:~/devdoctor

# En el servidor:
cd ~/devdoctor && sudo ./install.sh            # puerto libre desde 9443, contraseña aleatoria
sudo ./install.sh --port 8443 --user admin --password 'MiClaveLarga123'
```

El instalador imprime la URL (`https://IP:PUERTO`). El certificado es autofirmado: acepta la
excepción del navegador, o pon DevDoctor detrás de tu Nginx con un certificado real.
Si usas firewall: `ufw allow PUERTO/tcp`. En nubes con IP pública NAT, usa `--host IP_PUBLICA`.

## Comandos

| Comando | Qué hace |
|---|---|
| `devdoctor init` | Crea config, certificado TLS y usuario |
| `devdoctor run` | Inicia el dashboard (lo usa systemd) |
| `devdoctor url` | Muestra la URL |
| `devdoctor passwd` | Cambia usuario/contraseña desde terminal |
| `devdoctor scan [--json]` | Diagnóstico en terminal, sin servidor |

## Estructura

```
cmd/devdoctor/        CLI (init, run, url, passwd, scan)
internal/config/      configuración, hash PBKDF2, certificado TLS autofirmado
internal/sh/          helpers para ejecutar comandos con timeout
internal/sysinfo/     métricas en vivo (/proc, df, ps) e historial
internal/scanner/     motor de diagnóstico: check_versions, check_ports, check_ssl,
                      check_perms, check_projects, check_docker, check_security, semver
internal/server/      HTTPS, API JSON, sesiones, rate-limit de login
internal/web/         dashboard (HTML/CSS/JS embebido en el binario)
internal/version/     versión
deploy/               install.sh y unidad systemd
scripts/              build.sh (cross-compile linux amd64/arm64)
```

## Seguridad

PBKDF2-SHA256 (600k iteraciones), cookie `HttpOnly; Secure; SameSite=Strict`, bloqueo de IP tras
5 fallos, cabeceras CSP/HSTS, POST sólo `application/json`, servicio systemd endurecido.
