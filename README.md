# DevDoctor

**Diagnóstico y dashboard web para servidores Linux, en un único binario.**

DevDoctor se instala en tu servidor, inspecciona el entorno y publica un dashboard protegido con
usuario y contraseña en `https://IP:PUERTO`. Detecta problemas de versiones PHP/Node, puertos
ocupados, permisos, servicios caídos, SSL, dependencias, contenedores Docker y vulnerabilidades,
y muestra los recursos del servidor en vivo.

> DevDoctor **solo lee** el sistema. No instala, borra ni modifica nada fuera de `/etc/devdoctor`.
> Cada hallazgo incluye el comando sugerido para corregirlo, pero eres tú quien lo ejecuta.

---

## Contenido

- [Características](#características)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Primer acceso](#primer-acceso)
- [Comandos](#comandos)
- [Configuración](#configuración)
- [Qué revisa DevDoctor](#qué-revisa-devdoctor)
- [Puntuación de salud](#puntuación-de-salud)
- [Seguridad de la propia app](#seguridad-de-la-propia-app)
- [Poner DevDoctor detrás de Nginx](#poner-devdoctor-detrás-de-nginx)
- [API](#api)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Desarrollo y compilación](#desarrollo-y-compilación)
- [Actualizar y desinstalar](#actualizar-y-desinstalar)
- [Solución de problemas](#solución-de-problemas)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Autor y contacto](#autor-y-contacto)

---

## Características

- **Un solo binario** escrito en Go, sin dependencias en el servidor (ni PHP, ni Node, ni Python).
  El dashboard va embebido; funciona sin internet y sin CDNs.
- **URL automática** con la IP del servidor y un puerto libre (desde el 9443), servida por HTTPS
  con un certificado autofirmado que se genera solo.
- **Login configurable:** usuario y contraseña definidos al instalar y editables desde el dashboard
  (botón **Cuenta**) o con `devdoctor passwd`.
- **Recursos en vivo** (refresco cada 2 s): CPU, RAM, swap, red, carga, discos e inodos, procesos
  con más consumo, uptime e IPs.
- **Diagnóstico completo** programado cada 15 minutos o bajo demanda, con puntuación de salud de 0 a 100.
- **Docker:** versiones dentro de los contenedores, estado, configuración peligrosa y CVEs de imágenes.
- **Modo terminal:** `devdoctor scan` produce el mismo diagnóstico sin levantar el servidor.
- **Servicio systemd endurecido** que se reinicia solo si falla.

## Requisitos

| | |
|---|---|
| Sistema | Linux con systemd (Debian/Ubuntu, RHEL/Alma/Rocky, etc.) |
| Arquitectura | `amd64` o `arm64` |
| Permisos | `root` para instalar y para leer `/etc/shadow`, `journalctl`, etc. |
| Herramientas del sistema | `ss` (iproute2), `df`, `ps`. El resto es opcional |
| Opcionales | `composer`, `npm` (auditorías de dependencias), `docker`, `trivy` (CVEs en imágenes), `ufw`/`firewalld` |

Para **compilar** necesitas Go 1.24 o superior (no es necesario en el servidor).

## Instalación

### 1. Compilar

En tu máquina de desarrollo (Windows, macOS o Linux con Go instalado):

```bash
bash scripts/build.sh
```

Genera en `dist/`: `devdoctor-linux-amd64`, `devdoctor-linux-arm64`, `install.sh` y `devdoctor.service`.

### 2. Copiar al servidor

```bash
scp -r dist usuario@IP_DEL_SERVIDOR:~/devdoctor
```

### 3. Instalar

```bash
ssh usuario@IP_DEL_SERVIDOR
cd ~/devdoctor
sudo ./install.sh
```

Opciones del instalador (se pasan a `devdoctor init`):

```bash
sudo ./install.sh --port 8443 --host 203.0.113.10 --user admin --password 'UnaClaveLarga123'
```

| Opción | Descripción | Por defecto |
|---|---|---|
| `--port` | Puerto del dashboard | 9443, o el siguiente libre |
| `--host` | IP o dominio que aparecerá en la URL | IP de salida del servidor |
| `--user` | Usuario del dashboard | `admin` |
| `--password` | Contraseña (mínimo 10 caracteres) | aleatoria de 16 caracteres, se muestra una vez |

Al terminar verás algo así:

```
  DevDoctor listo
  ───────────────
  URL:        https://192.168.0.182:9443
  Usuario:    admin
  Contraseña: 7KmQp4xWbN2cRvTz   (cámbiala en el dashboard → Cuenta)
```

> **Firewall:** si usas `ufw`, abre el puerto: `sudo ufw allow 9443/tcp`.
> **Servidores en la nube con IP pública por NAT:** usa `--host IP_PUBLICA`, porque el servidor solo
> conoce su IP privada. DevDoctor no consulta servicios externos para averiguarla.

## Primer acceso

1. Abre la URL en tu navegador.
2. El navegador avisará de un **certificado no confiable**: es normal, es autofirmado. Acepta la
   excepción (o usa [Nginx con un certificado real](#poner-devdoctor-detrás-de-nginx)).
3. Inicia sesión y, si la contraseña fue generada, cámbiala en **Cuenta**.
4. El primer diagnóstico tarda entre 5 y 30 segundos según cuántos proyectos y contenedores tengas.

## Comandos

```
devdoctor init     Crea configuración, certificado TLS y usuario
devdoctor run      Inicia el dashboard (lo que ejecuta systemd)
devdoctor url      Muestra la URL de acceso
devdoctor passwd   Cambia usuario/contraseña desde la terminal
devdoctor scan     Ejecuta un diagnóstico en la terminal (--json para salida JSON)
devdoctor version  Muestra la versión
```

Todos aceptan `--config RUTA` (por defecto `/etc/devdoctor/config.json`, o la variable de entorno
`DEVDOCTOR_CONFIG`).

Ejemplos útiles:

```bash
devdoctor url                                  # ¿cuál era la URL?
sudo devdoctor passwd --password 'NuevaClave123456'
sudo devdoctor scan                            # diagnóstico rápido por SSH
sudo devdoctor scan --json | jq '.findings[] | select(.severity=="crit")'
sudo systemctl status devdoctor
sudo journalctl -u devdoctor -f                # logs en vivo
```

## Configuración

Archivo: `/etc/devdoctor/config.json` (permisos `0600`, solo root).

```json
{
  "port": 9443,
  "host": "192.168.0.182",
  "username": "admin",
  "pass_salt": "…",
  "pass_hash": "…",
  "iter": 600000,
  "scan_roots": ["/var/www", "/srv"],
  "scan_interval_min": 15
}
```

| Campo | Descripción |
|---|---|
| `port` / `host` | Puerto de escucha y host que se muestra en la URL |
| `username`, `pass_*` | Credenciales (la contraseña nunca se guarda en claro) |
| `scan_roots` | Directorios **adicionales** donde buscar proyectos. Siempre se revisan `/var/www`, `/srv`, `/home` y `/opt` |
| `scan_interval_min` | Minutos entre diagnósticos automáticos (15 por defecto) |

Tras editar a mano: `sudo systemctl restart devdoctor`.

Otros archivos en `/etc/devdoctor/`: `tls.crt` y `tls.key` (certificado autofirmado, válido 825 días
y renovado automáticamente al reiniciar cuando le quedan menos de 30).

## Qué revisa DevDoctor

### Recursos (en vivo)
CPU, memoria, swap, red (↓/↑), carga 1/5/15, discos con uso de inodos, procesos más pesados, procesos
zombie y uptime.

### Versiones
PHP (incluidas versiones múltiples como `php8.1` y `php8.3`), Node.js, npm, Composer, Python, Nginx,
Apache, MySQL/MariaDB, PostgreSQL, Redis, Docker, Git y OpenSSL. PHP y Node se comparan con sus
fechas de fin de soporte: **crítico** si ya no tienen soporte, **aviso** si faltan menos de 180 días
o si Node es una versión impar (no LTS).

### Puertos
Lista todos los puertos TCP/UDP en escucha con su proceso. Marca como **crítico** que estén abiertos
a toda la red: MySQL/MariaDB, PostgreSQL, Redis, MongoDB, Memcached, Elasticsearch, CouchDB, SQL Server,
Telnet y la API de Docker sin TLS; y como **aviso** FTP, RDP y VNC.

### Servicios
Servicios habilitados que no están activos (nginx, apache, php-fpm, mysql, postgresql, redis, docker,
ssh, fail2ban, cron, supervisor, etc.) con las últimas líneas de su log. Detecta **conflictos de
puerto**, por ejemplo nginx caído porque Apache ocupa el 80. También lista cualquier otra unidad
systemd fallida.

### SSL
Certificados de Let's Encrypt y los referenciados en Nginx/Apache/Caddy: expirados, por expirar
(≤ 14 días crítico, ≤ 30 días aviso), autofirmados y rutas que ya no existen. Además prueba si el HTTPS
local acepta TLS 1.0/1.1 y avisa si hay sitio en el puerto 80 sin HTTPS.

### Permisos
`/etc/shadow`, `/etc/passwd`, `sudoers`, claves SSH privadas, sticky bit de `/tmp`; y dentro de las
raíces web: archivos de código con permisos 777/666, directorios escribibles por todos, `.env` y
`wp-config.php` legibles por cualquiera, respaldos `.sql`/`.zip` expuestos, repositorios `.git` y
`storage/` o `bootstrap/cache` de Laravel sin permiso de escritura para el usuario web.

### Proyectos y dependencias
Detecta proyectos (`composer.json`, `package.json`, `wp-config.php`) y reconoce Laravel, WordPress,
Symfony, Next.js y Nuxt. Para cada uno:

- compara `require.php` / `engines.node` con lo instalado (soporta `^`, `~`, `>=`, `||`, comodines),
- detecta **extensiones PHP faltantes** (`ext-*`),
- avisa de `vendor/` o `node_modules/` sin instalar, lockfiles ausentes o desactualizados y JSON inválido,
- ejecuta `composer audit` y `npm audit` y cuenta vulnerabilidades conocidas (cacheado 1 hora).

### Docker
Con `docker` instalado revisa cada contenedor:

- **Versiones internas** (PHP, Node, Python, Go, Nginx) vía variables de entorno o `docker exec`,
- estado: bucles de reinicio, muertes por memoria (OOM), salidas con error, con logs recientes,
- CPU y RAM por contenedor,
- configuración peligrosa: `--privileged`, montaje de `docker.sock`, bases de datos publicadas a toda
  la red, ejecución como root, etiquetas `latest`,
- antigüedad de la imagen,
- **CVEs altos y críticos** si `trivy` está instalado (hasta 6 imágenes por diagnóstico).

### Seguridad del servidor
SSH (`PermitRootLogin`, contraseñas vacías o por contraseña), firewall activo, fail2ban, actualizaciones
de **seguridad pendientes** (apt y dnf), reinicio requerido, usuarios con UID 0 extra, cuentas sin
contraseña, sincronización NTP, OOM kills de la última semana y **IPs con intentos fallidos de SSH**
en las últimas 24 horas.

## Puntuación de salud

Empieza en 100. Cada hallazgo **crítico** resta 12 puntos y cada **aviso** 4, con un máximo de 35 puntos
de descuento por categoría para que un solo área (por ejemplo, muchas dependencias vulnerables) no
hunda la nota por completo. Los hallazgos informativos no restan.

| Puntuación | Color |
|---|---|
| 80–100 | Verde |
| 55–79 | Ámbar |
| 0–54 | Rojo |

## Seguridad de la propia app

- Contraseña con **PBKDF2-SHA256** (600 000 iteraciones y sal aleatoria); nunca en texto plano.
- **Bloqueo por IP** durante 15 minutos tras 5 intentos de login fallidos, más un retardo en cada fallo.
- Sesión en cookie `HttpOnly; Secure; SameSite=Strict`, válida 12 horas; cambiar la contraseña cierra
  todas las sesiones.
- Cabeceras `Content-Security-Policy`, `HSTS`, `X-Frame-Options: DENY`, `nosniff` y `no-store`.
- Las peticiones POST solo se aceptan como `application/json` (frena formularios cross-site).
- TLS 1.2 como mínimo.
- Servicio systemd con `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`,
  `PrivateTmp` y escritura permitida solo en `/etc/devdoctor`.
- No hace llamadas a servicios externos por su cuenta (solo `composer audit` / `npm audit`, que
  consultan sus propios registros, y `trivy` si lo instalas).

**Recomendaciones:** no expongas el puerto a todo internet si no hace falta (restríngelo por firewall a
tu IP o usa una VPN), usa una contraseña larga y, para uso público, ponlo detrás de Nginx con un
certificado válido.

## Poner DevDoctor detrás de Nginx

Para tener un dominio y un certificado reconocido (p. ej. `doctor.midominio.com`):

```nginx
server {
    listen 443 ssl;
    server_name doctor.midominio.com;

    ssl_certificate     /etc/letsencrypt/live/doctor.midominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/doctor.midominio.com/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:9443;
        proxy_ssl_verify off;            # certificado interno autofirmado
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

Con el proxy, cierra el acceso directo al puerto 9443 en el firewall. Ten en cuenta que el bloqueo por
IP de DevDoctor verá la IP del proxy (`127.0.0.1`) y no la del visitante, por lo que los intentos fallidos
se contarán en conjunto; limita también los intentos en Nginx con `limit_req`.

## API

Todas las rutas devuelven JSON. Excepto `/` y `/api/login`, requieren la cookie de sesión.

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/` | Dashboard |
| `POST` | `/api/login` | `{"username","password"}` → crea la sesión |
| `POST` | `/api/logout` | Cierra la sesión |
| `GET` | `/api/me` | Usuario y versión |
| `GET` | `/api/metrics` | Recursos en vivo e historial (90 muestras) |
| `GET` | `/api/report` | Último diagnóstico y si hay uno en curso |
| `POST` | `/api/scan` | Lanza un diagnóstico ahora |
| `POST` | `/api/account` | `{"current","username","password"}` cambia las credenciales |

Las peticiones POST deben llevar `Content-Type: application/json`.

## Estructura del proyecto

```
DevDoctor/
├── cmd/devdoctor/          CLI: init, run, url, passwd, scan, version
├── internal/
│   ├── config/             configuración, hash de contraseña, certificado TLS autofirmado
│   ├── sh/                 ejecución de comandos externos con timeout
│   ├── sysinfo/            métricas en vivo (/proc, df, ps) e historial
│   ├── scanner/            motor de diagnóstico
│   │   ├── scanner.go        tipos, ejecución en paralelo y puntuación
│   │   ├── check_versions.go versiones y fin de soporte
│   │   ├── check_ports.go    puertos y servicios
│   │   ├── check_ssl.go      certificados y TLS
│   │   ├── check_perms.go    permisos
│   │   ├── check_projects.go proyectos, composer y npm
│   │   ├── check_docker.go   contenedores
│   │   ├── check_security.go seguridad y recursos
│   │   └── semver.go         evaluador de constraints (^, ~, >=, ||)
│   ├── server/             HTTPS, API JSON, sesiones, límite de intentos
│   ├── web/                dashboard (HTML/CSS/JS en un solo archivo, embebido)
│   └── version/            versión
├── deploy/                 install.sh y devdoctor.service
├── scripts/build.sh        compilación cruzada linux/amd64 y linux/arm64
├── go.mod
└── README.md
```

## Desarrollo y compilación

```bash
go vet ./...
go build ./cmd/devdoctor                 # binario para tu sistema (el diagnóstico real requiere Linux)
bash scripts/build.sh                    # binarios estáticos para Linux en dist/
```

Para probarlo sin tocar el sistema, usa otra ruta de configuración:

```bash
./devdoctor init --config ./dev/config.json --port 9555 --password 'ClaveDePrueba123'
./devdoctor run  --config ./dev/config.json
```

Para añadir un chequeo nuevo: crea `internal/scanner/check_<tema>.go` con una función
`checkTema(c *Collector)`, registra la llamada en la lista de `RunSync` (`scanner.go`) y usa
`c.add(categoría, severidad, título, detalle, solución)` para emitir hallazgos.

## Actualizar y desinstalar

**Actualizar:** compila, copia `dist/` al servidor y ejecuta de nuevo `sudo ./install.sh`. Conserva la
configuración, la contraseña y el certificado existentes.

**Desinstalar:**

```bash
sudo systemctl disable --now devdoctor
sudo rm /etc/systemd/system/devdoctor.service /usr/local/bin/devdoctor
sudo rm -rf /etc/devdoctor
sudo systemctl daemon-reload
```

## Solución de problemas

| Síntoma | Qué hacer |
|---|---|
| No abre la URL | `sudo systemctl status devdoctor`; revisa que el puerto esté abierto en el firewall (`ufw allow PUERTO/tcp`) y en el panel de tu proveedor cloud |
| La URL muestra una IP privada | Reinstala con `--host IP_PUBLICA` o edita `host` en `config.json` y reinicia |
| `El puerto N ya está ocupado` | Elige otro con `--port` |
| Olvidé la contraseña | `sudo devdoctor passwd` genera una nueva |
| «Demasiados intentos» | Espera 15 minutos o reinicia el servicio (`systemctl restart devdoctor`) |
| Proyectos como «no auditado» | El servidor no tiene salida a internet o falta `composer`/`npm` |
| No aparece la pestaña Docker con datos | `docker` no está instalado o el servicio no tiene acceso a `/var/run/docker.sock` |
| Faltan datos de SSH/seguridad | Ejecuta el servicio como root (es lo que hace la unidad por defecto) |
| Logs del servicio | `sudo journalctl -u devdoctor -n 50` |

## Limitaciones conocidas

- Solo Linux con systemd; en otros sistemas el binario compila pero no hay datos que analizar.
- Los escaneos de vulnerabilidades dependen de herramientas externas (`composer audit`, `npm audit`,
  `trivy`) y de que haya conexión a internet.
- El sondeo de dependencias se limita a 40 proyectos y 4 niveles de profundidad.
- La detección de versiones dentro de contenedores sin shell ni variables de entorno de versión
  (p. ej. imágenes `distroless`) no es posible.
- Es un diagnóstico de buenas prácticas, **no sustituye** una auditoría de seguridad profesional.

## Autor y contacto

Creado por **Ricardo Alvarez**.

- Correo: [dev@ricardoalvarez.co](mailto:dev@ricardoalvarez.co)
- Sitio web: [me.ricardoalvarez.co](https://me.ricardoalvarez.co)

¿Encontraste un fallo o quieres proponer un chequeo nuevo? Escribe al correo de contacto.

## Licencia

Pendiente de definir por el autor. Hasta entonces, todos los derechos reservados.
