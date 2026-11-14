<p align="center">
  <img src="assets/logo.png" alt="DevDoctor" width="300">
</p>

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
- [Poner DevDoctor detrás de Nginx o Apache](#poner-devdoctor-detrás-de-nginx-o-apache)
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
- **URL automática** con la IP del servidor y un puerto alto y poco habitual (aleatorio entre 61000 y 64999, fuera del rango que usa Linux para conexiones salientes y comprobado como libre), servida por HTTPS
  con un certificado autofirmado que se genera solo.
- **Login configurable:** usuario y contraseña definidos al instalar y editables desde el dashboard
  (botón **Cuenta**) o con `devdoctor passwd`.
- **Recursos en vivo** (refresco cada 2 s): CPU con desglose (usuario, sistema, espera de E/S, steal), RAM
  (caché y disponible) y swap, red (bytes, paquetes y errores), **E/S de disco** (MB/s e IOPS), carga,
  **conexiones TCP**, procesos e hilos, **descriptores de archivo**, temperatura (si el hardware la
  expone), **presión del sistema (PSI)**, discos con inodos, procesos con más consumo, uptime e IPs.
- **Diagnóstico completo** programado cada 15 minutos o bajo demanda, con puntuación de salud de 0 a 100. Al pulsar **Escanear ahora**
  el dashboard muestra una capa desenfocada con el logo y el tiempo transcurrido hasta que termina
  (los escaneos automáticos no interrumpen la pantalla).
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

### Opción A — Un solo comando (descarga, instala y limpia)

El repositorio incluye `get.sh`: clona el repo en una carpeta temporal, compila (descarga un Go temporal si
el servidor no lo tiene), instala el servicio y **borra todo lo temporal** al terminar.

```bash
curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash

# con opciones (puerto, host…):
curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash -s -- --port 8443 --host 203.0.113.10

# actualizar: volver a ejecutar el mismo comando (conserva cuenta y configuración)
# desinstalar:
curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash -s -- uninstall
```

Requiere `git` y `curl` en el servidor. Como con cualquier `curl | bash`, revisa el script antes si no
confías en el origen: <https://github.com/rasoftdev/DevDoctor/blob/main/get.sh>.

### Opción B — Compilar y copiar a mano

#### 1. Compilar

En tu máquina de desarrollo (Windows, macOS o Linux con Go instalado):

```bash
bash scripts/build.sh
```

Genera en `dist/`: `devdoctor-linux-amd64`, `devdoctor-linux-arm64`, `install.sh` y `devdoctor.service`.

#### 2. Copiar al servidor

```bash
scp -r dist usuario@IP_DEL_SERVIDOR:~/devdoctor
```

#### 3. Instalar

```bash
ssh usuario@IP_DEL_SERVIDOR
cd ~/devdoctor
sudo ./install.sh
```

Opciones del instalador (se pasan a `devdoctor init`):

```bash
sudo ./install.sh --port 8443 --host 203.0.113.10
# Solo para instalaciones desatendidas (scripts): credenciales por línea de comandos
sudo ./install.sh --user admin --password 'UnaClaveLarga123!'
```

| Opción | Descripción | Por defecto |
|---|---|---|
| `--port` | Puerto del dashboard | aleatorio libre entre 61000 y 64999 |
| `--host` | IP o dominio que aparecerá en la URL | IP de salida del servidor |
| `--listen` | Interfaz de escucha; usa `127.0.0.1` si lo pondrás detrás de Nginx/Apache | todas |
| `--password` | Opcional. Si la omites (recomendado), **creas usuario y contraseña en la web** en el primer acceso | — |
| `--user` | Usuario, solo junto con `--password` | `admin` |

Al terminar verás algo así:

```
  DevDoctor listo
  ───────────────
  URL:        https://192.168.0.182:62817
  Código:     wGNTZm9jnuMZ

  Abre la URL, introduce el código y crea tu usuario y contraseña en la web.
```

> **Firewall:** si usas `ufw`, abre el puerto: `sudo ufw allow 62817/tcp`.
> **Servidores en la nube con IP pública por NAT:** usa `--host IP_PUBLICA`, porque el servidor solo
> conoce su IP privada. DevDoctor no consulta servicios externos para averiguarla.

## Primer acceso

1. Abre la URL en tu navegador.
2. El navegador avisará de un **certificado no confiable**: es normal, es autofirmado. Acepta la
   excepción (o usa [Nginx o Apache con un certificado real](#poner-devdoctor-detrás-de-nginx-o-apache)).
3. Verás el asistente **Configuración inicial**: introduce el **código** que mostró el instalador, elige tu **usuario** y tu **contraseña**. Entrarás directamente al dashboard. Más adelante puedes cambiarlos en **Cuenta**. (¿Perdiste el código? `sudo devdoctor setup-code`.)
4. El primer diagnóstico tarda entre 5 y 30 segundos según cuántos proyectos y contenedores tengas.

## Comandos

```
devdoctor init     Crea configuración, certificado TLS y usuario
devdoctor run      Inicia el dashboard (lo que ejecuta systemd)
devdoctor url      Muestra la URL de acceso
devdoctor setup-code  Muestra el código para crear la cuenta en la web
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
  "port": 62817,
  "host": "192.168.0.182",
  "listen": "",
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
| `listen` | Interfaz de escucha. Vacío = todas; `127.0.0.1` = solo local (para usar con Nginx/Apache) |
| `username`, `pass_*` | Credenciales (la contraseña nunca se guarda en claro) |
| `scan_roots` | Directorios **adicionales** donde buscar proyectos. Siempre se revisan `/var/www`, `/srv`, `/home` y `/opt` |
| `scan_interval_min` | Minutos entre diagnósticos automáticos (15 por defecto) |

Tras editar a mano: `sudo systemctl restart devdoctor`.

Otros archivos en `/etc/devdoctor/`: `tls.crt` y `tls.key` (certificado autofirmado, válido 825 días
y renovado automáticamente al reiniciar cuando le quedan menos de 30).

## Qué revisa DevDoctor

### Recursos (en vivo)
CPU (total y desglose usuario/sistema/iowait/steal), memoria (usada, caché, disponible), swap, red
(↓/↑, paquetes/s y errores), E/S de disco (lectura, escritura e IOPS), carga 1/5/15 y por núcleo,
conexiones TCP (establecidas, time-wait, en escucha), procesos e hilos, descriptores de archivo,
temperatura, presión del kernel (PSI de CPU, memoria y E/S), discos con uso de inodos, procesos más
pesados, procesos zombie y uptime. Los discos de `snap` y similares se ocultan para no meter ruido.

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

Cada hallazgo **crítico** suma 12 puntos de penalización y cada **aviso** 4, con un máximo de 35 por
categoría para que un solo área (por ejemplo, muchas dependencias vulnerables) no hunda la nota. La
nota es `100 / (1 + penalización/60)`: sin hallazgos es 100, con 60 de penalización es 50, y baja de
forma suave sin llegar de golpe a 0. Los hallazgos informativos no restan.

| Puntuación | Color |
|---|---|
| 80–100 | Verde |
| 55–79 | Ámbar |
| 0–54 | Rojo |

## Seguridad de la propia app

**Creación de la cuenta**
- No hay usuario ni contraseña por defecto. En el primer acceso se crean en la web, y solo con el
  **código de un solo uso** que imprime el instalador (12 caracteres aleatorios); así nadie que
  encuentre la URL antes que tú puede reclamar la cuenta. El código se destruye al crearla.

**Contraseñas**
- Guardadas con **PBKDF2-SHA256** (600 000 iteraciones, sal aleatoria); nunca en texto plano.
- Política: 10–128 caracteres, sin tu nombre de usuario, sin palabras/secuencias comunes
  (`password`, `123456`, `qwerty`, `admin`…) y con variedad de tipos, salvo que sea una frase de 16+.
- Verificación en tiempo constante y con el mismo coste exista o no el usuario (no se puede
  averiguar qué usuarios existen). Máximo 2 verificaciones simultáneas para que una avalancha de
  intentos no agote la CPU.

**Defensa contra fuerza bruta**
- **Bloqueo por IP** de 15 minutos tras 5 fallos (login, cambio de cuenta y código de configuración).
- **Frenado global:** si hay muchos fallos recientes desde cualquier origen (ataque distribuido con
  muchas IPs), cada intento se retrasa hasta 5 s más, sin bloquear al usuario legítimo.
- El cambio de contraseña desde **Cuenta** también está limitado, así que una sesión robada no sirve
  para adivinar la contraseña actual.
- Detrás de un proxy local solo se confía en `X-Forwarded-For` si la conexión viene de `127.0.0.1`,
  y se usa el último valor (el que añade tu proxy), para que no se pueda falsificar la IP.
- **fail2ban:** si está instalado, el instalador crea el filtro y la *jail* `devdoctor`
  (5 fallos en 10 min → baneo de 1 h) usando el log del servicio.

**Sesiones**
- Cookie `__Host-dd_session` con `HttpOnly; Secure; SameSite=Strict`, token aleatorio de 256 bits nuevo
  en cada login (sin fijación de sesión).
- Caduca a las **12 h** y por **30 min de inactividad**; se ata al navegador (User-Agent); máximo 20
  sesiones simultáneas. Cambiar usuario/contraseña cierra todas.

**Navegador y red**
- Protección CSRF triple: `SameSite=Strict`, POST solo `application/json` y verificación de
  `Origin`/`Sec-Fetch-Site`.
- `Content-Security-Policy` estricta: sin scripts externos ni `unsafe-inline` en scripts (el script
  se autoriza por hash), sin iframes, `form-action 'self'`. Además `HSTS`, `X-Frame-Options: DENY`,
  `nosniff`, `no-store`, `COOP/CORP same-origin` y `Permissions-Policy`.
- TLS 1.2 como mínimo. Límites de tamaño de petición y cabeceras, y timeouts anti-*slowloris*.
- Puerto aleatorio alto (61000–64999): poco probable que choque con otra app y no aparece en los
  escaneos habituales de puertos conocidos.

**Sistema**
- Servicio systemd con `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`,
  `PrivateTmp` y escritura permitida solo en `/etc/devdoctor`.
- No hace llamadas a servicios externos por su cuenta (solo `composer audit` / `npm audit`, que
  consultan sus propios registros, y `trivy` si lo instalas).

**Recomendaciones:** restringe el puerto por firewall a tu IP o usa una VPN si es posible, y para
uso público ponlo detrás de Nginx o Apache con un certificado válido.

## Poner DevDoctor detrás de Nginx o Apache

Útil para tener un dominio propio (p. ej. `doctor.midominio.com`) con un certificado reconocido por el
navegador, en el puerto 443. En los ejemplos, `62817` es el puerto de DevDoctor (`devdoctor url`).

Requisitos comunes:

- DevDoctor debe colgar de la **raíz** de un dominio o subdominio (no de una subruta como `/doctor/`).
- Hay que reenviar la cabecera `Host` original (con puerto, si no es el 443): DevDoctor comprueba que
  el `Origin` de cada petición coincida con ella como defensa CSRF.
- Reenvía la IP real del cliente en `X-Forwarded-For`. DevDoctor solo la usa si la conexión llega desde
  `127.0.0.1`/`::1` (tu proxy) y toma el **último** valor, el que añade tu proxy, así que no se puede falsificar.
- Obtén el certificado antes: `sudo certbot certonly --nginx -d doctor.midominio.com`
  (o `--apache`, o `--standalone`).

### Nginx

```nginx
server {
    listen 80;
    server_name doctor.midominio.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name doctor.midominio.com;

    ssl_certificate     /etc/letsencrypt/live/doctor.midominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/doctor.midominio.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass https://127.0.0.1:62817;
        proxy_ssl_verify off;                         # certificado interno autofirmado
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 90s;
    }
}
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### Apache

Activa los módulos y el sitio:

```bash
sudo a2enmod ssl proxy proxy_http headers rewrite
sudo a2ensite doctor.conf
sudo apachectl configtest && sudo systemctl reload apache2     # RHEL/Alma: httpd
```

`/etc/apache2/sites-available/doctor.conf` (en RHEL: `/etc/httpd/conf.d/doctor.conf`):

```apache
<VirtualHost *:80>
    ServerName doctor.midominio.com
    RewriteEngine On
    RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName doctor.midominio.com

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/doctor.midominio.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/doctor.midominio.com/privkey.pem
    SSLProtocol           -all +TLSv1.2 +TLSv1.3

    # Conexión interna hacia DevDoctor (certificado autofirmado)
    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    SSLProxyCheckPeerExpire off

    ProxyPreserveHost On
    ProxyAddHeaders On                      # añade X-Forwarded-For con la IP real del cliente
    RequestHeader set X-Forwarded-Proto "https"
    ProxyTimeout 90

    ProxyPass        / https://127.0.0.1:62817/
    ProxyPassReverse / https://127.0.0.1:62817/
</VirtualHost>
```

### Después de configurar el proxy

1. Haz que DevDoctor solo escuche en local: pon `"listen": "127.0.0.1"` en `/etc/devdoctor/config.json`
   (o instala con `--listen 127.0.0.1`) y reinicia: `sudo systemctl restart devdoctor`. Así el puerto
   ya no es alcanzable desde fuera y solo se entra por el proxy.
2. Opcional: en `/etc/devdoctor/config.json` pon `"host": "doctor.midominio.com"` y reinicia, para que
   `devdoctor url` muestre tu dominio.
3. La protección anti fuerza bruta de DevDoctor sigue funcionando por IP real gracias a
   `X-Forwarded-For`. Para una capa extra, limita también en el proxy
   (Nginx: `limit_req_zone`; Apache: `mod_evasive` o `mod_security`).
4. Si fail2ban está instalado, su jail `devdoctor` baneará la IP real; como el puerto que protege es el
   de DevDoctor y tu tráfico llega por el proxy, cambia su acción a bloquear el 443 en
   `/etc/fail2ban/jail.d/devdoctor.local` (`port = https,http`).

> **Comprobación rápida:** abre `https://doctor.midominio.com`, inicia sesión y mira el log
> (`journalctl -u devdoctor -f`); si ves `login fallido desde 127.0.0.1` en lugar de tu IP, el proxy no
> está enviando `X-Forwarded-For`.

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
