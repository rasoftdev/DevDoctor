<p align="center">
  <img src="assets/banner.webp" alt="DevDoctor: diagnose, analyze and optimize your development projects" width="100%">
</p>

<p align="center">
  <img src="assets/logo.png" alt="DevDoctor" width="150">
</p>

<p align="center"><b>English</b> · <a href="README.md">Español</a></p>

# DevDoctor

**Diagnostics and web dashboard for Linux servers, in a single binary.**

DevDoctor installs on your server, inspects the environment and publishes a dashboard protected by
username and password at `https://IP:PORT`. It detects PHP/Node version problems, ports in use,
permissions, stopped services, SSL, dependencies, Docker containers and vulnerabilities, and shows the
server's resources live.

> DevDoctor **only reads** the system. It does not install, delete or modify anything outside `/etc/devdoctor`.
> Every finding includes the suggested command to fix it, but you are the one who runs it.

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [First access](#first-access)
- [Commands](#commands)
- [Configuration](#configuration)
- [What DevDoctor checks](#what-devdoctor-checks)
- [Configuration from the dashboard](#configuration-from-the-dashboard)
- [Public security sources](#public-security-sources)
- [Telegram and Slack notifications](#telegram-and-slack-notifications)
- [Health score](#health-score)
- [Security of the app itself](#security-of-the-app-itself)
- [Putting DevDoctor behind Nginx or Apache](#putting-devdoctor-behind-nginx-or-apache)
- [API](#api)
- [Project structure](#project-structure)
- [Development and building](#development-and-building)
- [Updating and uninstalling](#updating-and-uninstalling)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Author and contact](#author-and-contact)
- [License](#license)

---

## Features

- **A single binary** written in Go, with no dependencies on the server (no PHP, Node or Python).
  The dashboard is embedded; it works without internet and without CDNs.
- **Automatic URL** with the server's IP and a high, uncommon port (random between 61000 and 64999,
  outside the range Linux uses for outgoing connections and checked to be free), served over HTTPS with a
  self-signed certificate that is generated automatically.
- **Configurable login:** username and password defined at install time and editable from the dashboard
  (**Account** button) or with `devdoctor passwd`.
- **Live resources** (refreshed every 2 s): CPU with breakdown (user, system, I/O wait, steal), RAM
  (cache and available) and swap, network (bytes, packets and errors), **disk I/O** (MB/s and IOPS), load,
  **TCP connections**, processes and threads, temperature (if the hardware exposes it), disks with inodes,
  top-consuming processes, uptime and IPs.
- **Full diagnostics** scheduled every 15 minutes or on demand, with a health score from 0 to 100. When you
  press **Scan now**, the dashboard shows a blurred layer with the logo and the elapsed time until it
  finishes (automatic scans do not interrupt the screen).
- **Docker:** versions inside containers, status, dangerous configuration and image CVEs.
- **Security alerts** (separate panel, once a day or on demand) crossing your software with php.net,
  nodejs.org, endoflife.date, CISA KEV, NVD, OSV.dev, Ubuntu Security and GitHub Advisories
  (see [Public security sources](#public-security-sources)).
- **Notifications** to Telegram and Slack when a new problem appears.
- **Terminal mode:** `devdoctor scan` produces the same diagnosis without starting the server.
- **Hardened systemd service** that restarts itself if it fails.

## Requirements

| | |
|---|---|
| System | Linux with systemd (Debian/Ubuntu, RHEL/Alma/Rocky, etc.) |
| Architecture | `amd64` or `arm64` |
| Permissions | `root` to install and to read `/etc/shadow`, `journalctl`, etc. |
| System tools | `ss` (iproute2), `df`, `ps`. The rest is optional |
| Optional | `composer`, `npm` (dependency audits), `docker`, `trivy` (image CVEs), `ufw`/`firewalld` |

To **build** you need Go 1.24 or later (not needed on the server).

## Installation

### Option A — One command (download, install and clean up)

The repository includes `get.sh`: it clones the repo into a temporary folder, builds (downloading a
temporary Go if the server does not have one), installs the service and **removes everything temporary**
when it finishes.

```bash
curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash

# with options (port, host…):
curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash -s -- --port 8443 --host 203.0.113.10

# update: run the same command again (keeps account and configuration)
# uninstall:
curl -fsSL https://raw.githubusercontent.com/rasoftdev/DevDoctor/main/get.sh | sudo bash -s -- uninstall
```

Requires `git` and `curl` on the server. As with any `curl | bash`, review the script first if you do
not trust the source: <https://github.com/rasoftdev/DevDoctor/blob/main/get.sh>.

### Option B — Build and copy by hand

#### 1. Build

On your development machine (Windows, macOS or Linux with Go installed):

```bash
bash scripts/build.sh
```

It produces in `dist/`: `devdoctor-linux-amd64`, `devdoctor-linux-arm64`, `install.sh` and `devdoctor.service`.

#### 2. Copy to the server

```bash
scp -r dist user@SERVER_IP:~/devdoctor
```

#### 3. Install

```bash
ssh user@SERVER_IP
cd ~/devdoctor
sudo ./install.sh
```

Installer options (passed on to `devdoctor init`):

```bash
sudo ./install.sh --port 8443 --host 203.0.113.10
# Only for unattended installs (scripts): credentials on the command line
sudo ./install.sh --user admin --password 'AVeryLongPassword123!'
```

| Option | Description | Default |
|---|---|---|
| `--port` | Dashboard port | random free port between 61000 and 64999 |
| `--host` | IP or domain shown in the URL | the server's outgoing IP |
| `--listen` | Listening interface; use `127.0.0.1` if you will put it behind Nginx/Apache | all |
| `--password` | Optional. If you omit it (recommended), **you create the username and password on the web** at first access | — |
| `--user` | Username, only together with `--password` | `admin` |

When it finishes you will see something like this (installer output is shown in Spanish):

```
  DevDoctor listo
  ───────────────
  URL:        https://192.168.0.182:62817
  Código:     wGNTZm9jnuMZ

  Abre la URL, introduce el código y crea tu usuario y contraseña en la web.
```

> **Firewall:** if you use `ufw`, open the port: `sudo ufw allow 62817/tcp`.
> **Cloud servers with a public IP behind NAT:** use `--host PUBLIC_IP`, because the server only knows its
> private IP. DevDoctor does not query external services to find it out.

## First access

1. Open the URL in your browser.
2. The browser will warn about an **untrusted certificate**: that is normal, it is self-signed. Accept the
   exception (or use [Nginx or Apache with a real certificate](#putting-devdoctor-behind-nginx-or-apache)).
3. You will see the **Initial setup** wizard: enter the **code** the installer displayed, choose your
   **username** and your **password**. You will go straight into the dashboard. You can change them later
   under **Account**. (Lost the code? `sudo devdoctor setup-code`.)
4. The first diagnosis takes between 5 and 30 seconds depending on how many projects and containers you have.

## Commands

```
devdoctor init        Creates configuration, TLS certificate and user
devdoctor run         Starts the dashboard (what systemd runs)
devdoctor url         Shows the access URL
devdoctor setup-code  Shows the code to create the account on the web
devdoctor passwd      Resets username/password from the terminal (forgotten or locked out)
devdoctor notify      Sends a test message to Telegram/Slack (notify test)
devdoctor paths       Lists/adds/removes extra folders to look for projects in
devdoctor scan        Runs a diagnosis in the terminal (--json for JSON output)
devdoctor version     Shows the version
```

All of them accept `--config PATH` (default `/etc/devdoctor/config.json`, or the `DEVDOCTOR_CONFIG`
environment variable).

Useful examples:

```bash
devdoctor url                                  # what was the URL again?
sudo devdoctor passwd --password 'NewPassword123456'
sudo devdoctor scan                            # quick diagnosis over SSH
sudo devdoctor scan --json | jq '.findings[] | select(.severity=="crit")'
sudo systemctl status devdoctor
sudo journalctl -u devdoctor -f                # live logs
```

## Configuration

File: `/etc/devdoctor/config.json` (permissions `0600`, root only).

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

| Field | Description |
|---|---|
| `port` / `host` | Listening port and the host shown in the URL |
| `listen` | Listening interface. Empty = all; `127.0.0.1` = local only (for use with Nginx/Apache) |
| `username`, `pass_*` | Credentials (the password is never stored in clear text) |
| `scan_roots` | **Additional** directories to look for projects in. `/var/www`, `/srv`, `/home` and `/opt` are always checked |
| `intel_disabled` | `true` disables queries to public security sources |
| `nvd_api_key` | Free NVD key (optional): speeds up queries |
| `notify` | Notifications: `telegram_token`, `telegram_chat_id`, `slack_webhook`, `min_severity` (`crit`/`warn`), `recent_window` (`day`/`week`/`month`/`all`), `lang`, `recovery` |
| `scan_interval_min` | Minutes between automatic diagnoses (15 by default) |

After editing by hand: `sudo systemctl restart devdoctor`.

Other files in `/etc/devdoctor/`: `tls.crt` and `tls.key` (self-signed certificate, valid for 825 days and
renewed automatically on restart when fewer than 30 remain).

## What DevDoctor checks

### Resources (live)
CPU (total and user/system/iowait/steal breakdown), memory (used, cache, available), swap, network
(↓/↑, packets/s and errors), disk I/O (read, write and IOPS), load 1/5/15 and per core, TCP connections
(established, time-wait, listening), processes and threads, temperature, disks with inode usage, heaviest
processes, zombie processes and uptime. `snap` and similar disks are hidden to avoid noise.

### Versions
PHP (including multiple versions such as `php8.1` and `php8.3`), Node.js, npm, Composer, Python, Nginx,
Apache, MySQL/MariaDB, PostgreSQL, Redis, Docker, Git and OpenSSL. PHP and Node are compared against their
end-of-support dates: **critical** if they are no longer supported, **warning** if fewer than 180 days
remain or if Node is an odd-numbered release (not LTS).

### Ports
Lists every listening TCP/UDP port with its process. It flags as **critical** the following when open to
the whole network: MySQL/MariaDB, PostgreSQL, Redis, MongoDB, Memcached, Elasticsearch, CouchDB, SQL
Server, Telnet and the Docker API without TLS; and as **warning** FTP, RDP and VNC.

### Services
Enabled services that are not active (nginx, apache, php-fpm, mysql, postgresql, redis, docker, ssh,
fail2ban, cron, supervisor, etc.) with the last lines of their log. It detects **port conflicts**, for
example nginx down because Apache holds port 80. It also lists any other failed systemd unit.

### SSL
Let's Encrypt certificates and those referenced in Nginx/Apache/Caddy: expired, about to expire
(≤ 14 days critical, ≤ 30 days warning), self-signed, and paths that no longer exist. It also tests whether
local HTTPS accepts TLS 1.0/1.1 and warns if there is a site on port 80 without HTTPS.

### Permissions
`/etc/shadow`, `/etc/passwd`, `sudoers`, private SSH keys, the sticky bit on `/tmp`; and inside the web
roots: code files with 777/666 permissions, world-writable directories, `.env` and `wp-config.php`
readable by anyone, exposed `.sql`/`.zip` backups, `.git` repositories, and Laravel's `storage/` or
`bootstrap/cache` without write permission for the web user.

### Projects and dependencies
Detects projects (`composer.json`, `package.json`, `wp-config.php`) and recognizes Laravel, WordPress,
Symfony, Next.js and Nuxt. For each one:

- compares `require.php` / `engines.node` with what is installed (supports `^`, `~`, `>=`, `||`, wildcards),
- detects **missing PHP extensions** (`ext-*`),
- warns about `vendor/` or `node_modules/` not installed, missing or outdated lockfiles, and invalid JSON,
- runs `composer audit` and `npm audit` and counts known vulnerabilities (cached for 1 hour).

### Docker
With `docker` installed it checks every container:

- **Internal versions** (PHP, Node, Python, Go, Nginx) via environment variables or `docker exec`,
- status: restart loops, out-of-memory kills (OOM), exits with errors, with recent logs,
- CPU and RAM per container,
- dangerous configuration: `--privileged`, `docker.sock` mounts, databases published to the whole network,
  running as root, `latest` tags,
- image age,
- **high and critical CVEs** if `trivy` is installed (up to 6 images per diagnosis).

### Server security
SSH (`PermitRootLogin`, empty passwords or password login), active firewall, fail2ban, **pending security**
updates (apt and dnf), reboot required, extra UID 0 users, accounts without a password, NTP
synchronization, OOM kills in the last week, and **IPs with failed SSH attempts** in the last 24 hours.

## Configuration from the dashboard

The **Settings** button in the dashboard (gear icon) lets you, without touching files or restarting anything:

- **Extra folders to look for projects in** (one per line). They are added to the ones DevDoctor already checks by itself.

Pressing **Save and scan** writes to `config.json` and launches an immediate diagnosis. Folders must be
absolute paths (`/` is not allowed); maximum 30.

### Where does it look for projects?

A **project** is a folder with `composer.json`, `package.json` or `wp-config.php`, or a site with
`index.php`/`index.html` inside a web folder. DevDoctor searches, up to 4 levels deep, in:

1. `/var/www`, `/srv`, `/home` and `/opt`.
2. The **real docroots** it finds in your Nginx/Apache/Caddy configuration (`root`, `DocumentRoot`),
   wherever they are, and the parent folder of each one (the project root).
3. The host folders that **your Docker containers mount** (bind mounts).
4. The extra folders you add from the dashboard or with the CLI:

```bash
sudo devdoctor paths list
sudo devdoctor paths add /data/sites
sudo devdoctor paths remove /data/sites
```

`vendor`, `node_modules`, hidden folders, `snap`, `.cache`… are ignored, and at most 60 projects are
analyzed. If the **Projects** tab comes out empty, it shows exactly which folders it searched.

## Public security sources

DevDoctor queries free public APIs (no key needed) and crosses them with **what you have installed**, to
warn you about known problems as soon as they are published, such as a serious PHP flaw.

These alerts are **separate from the server scan**: they appear under the bell button **Security alerts** in
the header (with a counter), which opens its own panel with the status of each source and, for every
alert, the official link and the command to fix it. They are **not** mixed with findings and do not change
the health score.

- **Once a day, automatic.** The first query starts by itself after the first scan and then repeats every
  24 h (`intel_interval_hours` in `config.json`). It runs in the background and neither slows down nor is
  chained to the general scan.
- **Check now.** The panel has its own button to launch it whenever you want, with a progress bar.
- **Period filter.** Each alert shows the date of what it reports (version release, CVE or advisory
  publication) and you can filter by **24 h, 7 days, 30 days or All**, with the number of alerts in each
  period. Alerts without a date (current state, such as unpatched packages) only appear under "All".
- **From the terminal:** `devdoctor scan --intel` adds these alerts to the diagnosis (the first time it
  takes a while because of NVD).

| Source | What it provides |
|---|---|
| **php.net** | New versions of your PHP branch and which ones are security releases |
| **nodejs.org** | The same for Node.js (each release's `security` flag) |
| **endoflife.date** | End of support for the operating system and software (Nginx, Apache, MySQL, MariaDB, PostgreSQL, Redis, Python, OpenSSL); it also keeps the PHP and Node dates up to date |
| **CISA KEV** | Vulnerabilities already being exploited, added in the last 120 days, for the software you use |
| **GitHub Security Advisories (php-src)** | Recent security advisories from the PHP project itself that affect your version |
| **OSV.dev** | Dependency vulnerabilities (Composer and npm) when `composer audit`/`npm audit` are not available. It aggregates GitHub and Packagist advisories |
| **NVD (NIST)** | High/critical CVEs matching the exact version of software that does **not** come from your distribution (hand-compiled, PPA, NodeSource…) |
| **Ubuntu Security** | CVEs of your Ubuntu packages that **do not have a fix yet**, taking backports into account |

How false positives are avoided: distributions (Ubuntu, Debian) apply security patches without changing the
version number, so for the distro's official packages an "old version" warning is downgraded to
informational and the distribution's own tracker is used. Packages from third-party repositories (PHP PPA,
NodeSource…) are compared against the official version. The CISA KEV catalog does not state affected
versions, so its alert asks you to **verify** that your version is fixed.

- Responses are **cached on disk** (`/etc/devdoctor/cache`, from 6 h to 7 days depending on the source). If a
  source does not respond, the stored data is used and the panel shows the status of each one: green
  (correct), amber (some request failed or stored data is in use) or red (not responding).
- The first query can take a couple of minutes, because NVD limits requests to 5 every 30 s (with a free
  NVD key in `nvd_api_key` it drops to a few seconds). Since it runs separately, it does not affect the
  speed of the server scan, and afterwards almost everything comes from the cache.
- **Privacy:** only software names and versions are sent (for example `php 8.3.35`) and, for OSV, package
  names and versions from your `composer.lock`/`package-lock.json`. Never IPs, users, paths or content.
- They can be disabled from **Settings → Security sources**, or with `"intel_disabled": true` in `config.json`.
- Limitation: the Debian security tracker is not integrated (on Debian, pending `apt` security updates
  are used).

## Telegram and Slack notifications

From **Settings → Notifications** you can receive a message when DevDoctor detects a **new** problem:
service down, certificate about to expire, dangerous port exposed, alerts from the public security
sources, etc. (notifications cover both the server scan and the security alerts).

**Telegram**
1. Talk to [@BotFather](https://t.me/BotFather), send `/newbot` and copy the **token** (`123456789:AAE...`).
2. Send a message to your bot (or add it to a group/channel) and get your **chat ID** with
   [@userinfobot](https://t.me/userinfobot) (for channels, use `@channelname`).

**Slack**
1. Create an *Incoming Webhook* at <https://api.slack.com/messaging/webhooks> and copy the URL
   (`https://hooks.slack.com/services/...`).

Paste the data, press **Send test message** (it uses the form values without saving them) and then
**Save and scan**. You can also test it from the terminal: `sudo devdoctor notify test`.

How notifications work:
- **Only new problems.** Each problem is reported once; if it is still there on the next scan it is not
  repeated. Values that change on their own (days remaining, disk %, milliseconds) do not count as a
  different problem.
- **First scan:** a summary of the most important things at that moment is sent, without flooding you with
  everything that already exists.
- **Threshold:** critical only (default) or critical and warnings.
- **Only recent items:** of the security alerts that have a publication date, only those published within
  the window you choose are reported (24 hours, **7 days** by default, 30 days or unlimited); older ones
  are silently discarded. Problems detected on your server are always reported when they appear.
- **Resolved** (optional): when a problem disappears for two consecutive scans, you are told it was resolved.
- It is sent in the language you had selected in the dashboard when saving, with the suggested command to
  fix it and the link to the official advisory.
- If sending fails (no internet, wrong token), the problem is not marked as reported and is retried on the
  next scan. The state is stored in `/etc/devdoctor/notified.json`.

Security: the token and the webhook are stored in `config.json` (permissions `0600`, root only), are
**never shown again in the dashboard** (only "a value is stored") and are hidden from error messages. The
Slack webhook must be on `hooks.slack.com` and Telegram is only contacted at `api.telegram.org`, so the
server cannot be used to send requests to internal addresses.

## Health score

Each **critical** finding adds 12 penalty points and each **warning** 4, with a maximum of 35 per category
so that a single area (for example, many vulnerable dependencies) does not sink the score. The score is
`100 / (1 + penalty/60)`: with no findings it is 100, with 60 penalty it is 50, and it drops smoothly
without suddenly reaching 0. Informational findings do not subtract.

| Score | Color |
|---|---|
| 80–100 | Green |
| 55–79 | Amber |
| 0–54 | Red |

## Security of the app itself

**Account creation**
- There is no default user or password. At first access they are created on the web, and only with the
  **one-time code** printed by the installer (12 random characters); this way nobody who finds the URL
  before you can claim the account. The code is destroyed when the account is created.

**Passwords**
- Stored with **PBKDF2-SHA256** (600,000 iterations, random salt); never in clear text.
- Policy: 10–128 characters, without your username, without common words/sequences (`password`, `123456`,
  `qwerty`, `admin`…) and with a variety of character types, unless it is a passphrase of 16+ characters.
- Constant-time verification with the same cost whether or not the user exists (you cannot find out which
  users exist). At most 2 simultaneous verifications so that a flood of attempts cannot exhaust the CPU.

**Brute-force defense**
- **Per-IP lockout** of 15 minutes after 5 failures (login, account change and setup code).
- **Global throttling:** if there are many recent failures from any source (a distributed attack with many
  IPs), every attempt is delayed by up to 5 s more, without locking out the legitimate user.
- Changing the password from **Account** is also rate-limited, so a stolen session cannot be used to
  guess the current password.
- Behind a local proxy, `X-Forwarded-For` is only trusted if the connection comes from `127.0.0.1`, and
  the last value is used (the one your proxy adds), so the IP cannot be forged.
- **fail2ban:** if installed, the installer creates the `devdoctor` filter and jail (5 failures in
  10 min → 1 h ban) using the service log.

**Sessions**
- `__Host-dd_session` cookie with `HttpOnly; Secure; SameSite=Strict`, a random 256-bit token that is new
  on every login (no session fixation).
- It expires after **12 h** and after **30 min of inactivity**; it is tied to the browser (User-Agent);
  maximum 20 simultaneous sessions. Changing username/password closes all of them.

**Browser and network**
- Triple CSRF protection: `SameSite=Strict`, POST only as `application/json`, and `Origin`/`Sec-Fetch-Site`
  verification.
- Strict `Content-Security-Policy`: no external scripts or `unsafe-inline` for scripts (the script is
  authorized by hash), no iframes, `form-action 'self'`. Plus `HSTS`, `X-Frame-Options: DENY`, `nosniff`,
  `no-store`, `COOP/CORP same-origin` and `Permissions-Policy`.
- TLS 1.2 minimum. Request and header size limits, and anti-*slowloris* timeouts.
- Random high port (61000–64999): unlikely to clash with another app and it does not show up in the usual
  scans of well-known ports.

**System**
- systemd service with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`
  and write access only to `/etc/devdoctor`.
- It makes no calls to external services on its own (only `composer audit` / `npm audit`, which query
  their own registries, and `trivy` if you install it).

**Recommendations:** restrict the port by firewall to your IP or use a VPN if possible, and for public
use put it behind Nginx or Apache with a valid certificate.

## Putting DevDoctor behind Nginx or Apache

Useful for having your own domain (e.g. `doctor.mydomain.com`) with a certificate the browser recognizes,
on port 443. In the examples, `62817` is DevDoctor's port (`devdoctor url`).

Common requirements:

- DevDoctor must hang off the **root** of a domain or subdomain (not a subpath such as `/doctor/`).
- The original `Host` header must be forwarded (with the port, if it is not 443): DevDoctor checks that the
  `Origin` of every request matches it as a CSRF defense.
- Forward the real client IP in `X-Forwarded-For`. DevDoctor only uses it if the connection arrives from
  `127.0.0.1`/`::1` (your proxy) and takes the **last** value, the one your proxy adds, so it cannot be
  forged.
- Get the certificate first: `sudo certbot certonly --nginx -d doctor.mydomain.com`
  (or `--apache`, or `--standalone`).

### Nginx

```nginx
server {
    listen 80;
    server_name doctor.mydomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name doctor.mydomain.com;

    ssl_certificate     /etc/letsencrypt/live/doctor.mydomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/doctor.mydomain.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass https://127.0.0.1:62817;
        proxy_ssl_verify off;                         # internal self-signed certificate
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

Enable the modules and the site:

```bash
sudo a2enmod ssl proxy proxy_http headers rewrite
sudo a2ensite doctor.conf
sudo apachectl configtest && sudo systemctl reload apache2     # RHEL/Alma: httpd
```

`/etc/apache2/sites-available/doctor.conf` (on RHEL: `/etc/httpd/conf.d/doctor.conf`):

```apache
<VirtualHost *:80>
    ServerName doctor.mydomain.com
    RewriteEngine On
    RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName doctor.mydomain.com

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/doctor.mydomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/doctor.mydomain.com/privkey.pem
    SSLProtocol           -all +TLSv1.2 +TLSv1.3

    # Internal connection to DevDoctor (self-signed certificate)
    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    SSLProxyCheckPeerExpire off

    ProxyPreserveHost On
    ProxyAddHeaders On                      # adds X-Forwarded-For with the client's real IP
    RequestHeader set X-Forwarded-Proto "https"
    ProxyTimeout 90

    ProxyPass        / https://127.0.0.1:62817/
    ProxyPassReverse / https://127.0.0.1:62817/
</VirtualHost>
```

### After configuring the proxy

1. Make DevDoctor listen only locally: set `"listen": "127.0.0.1"` in `/etc/devdoctor/config.json`
   (or install with `--listen 127.0.0.1`) and restart: `sudo systemctl restart devdoctor`. This way the
   port is no longer reachable from outside and you can only get in through the proxy.
2. Optional: in `/etc/devdoctor/config.json` set `"host": "doctor.mydomain.com"` and restart, so that
   `devdoctor url` shows your domain.
3. DevDoctor's brute-force protection keeps working per real IP thanks to `X-Forwarded-For`. For an extra
   layer, also limit at the proxy (Nginx: `limit_req_zone`; Apache: `mod_evasive` or `mod_security`).
4. If fail2ban is installed, its `devdoctor` jail will ban the real IP; since the port it protects is
   DevDoctor's and your traffic arrives through the proxy, change its action to block 443 in
   `/etc/fail2ban/jail.d/devdoctor.local` (`port = https,http`).

> **Quick check:** open `https://doctor.mydomain.com`, log in and watch the log
> (`journalctl -u devdoctor -f`); if you see `login fallido desde 127.0.0.1` (the log text is in Spanish,
> "failed login from") instead of your IP, the proxy is not sending `X-Forwarded-For`.

## API

All routes return JSON. Except `/` and `/api/login`, they require the session cookie.

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Dashboard |
| `POST` | `/api/login` | `{"username","password"}` → creates the session |
| `POST` | `/api/logout` | Closes the session |
| `GET` | `/api/me` | User and version |
| `GET` | `/api/metrics` | Live resources and history (90 samples) |
| `GET` | `/api/report` | Latest diagnosis and whether one is in progress |
| `POST` | `/api/scan` | Launches a diagnosis now |
| `POST` | `/api/account` | `{"current","username","password"}` changes the credentials |

POST requests must carry `Content-Type: application/json`.

## Project structure

```
DevDoctor/
├── cmd/devdoctor/          CLI: init, run, url, passwd, scan, version
├── internal/
│   ├── config/             configuration, password hash, self-signed TLS certificate
│   ├── sh/                 running external commands with a timeout
│   ├── sysinfo/            live metrics (/proc, df, ps) and history
│   ├── scanner/            diagnostic engine
│   │   ├── scanner.go        types, parallel execution and scoring
│   │   ├── check_versions.go versions and end of support
│   │   ├── check_ports.go    ports and services
│   │   ├── check_ssl.go      certificates and TLS
│   │   ├── check_perms.go    permissions
│   │   ├── check_projects.go projects, composer and npm
│   │   ├── check_docker.go   containers
│   │   ├── check_intel.go    crossing your software with the security sources
│   │   ├── check_security.go security and resources
│   │   └── semver.go         constraint evaluator (^, ~, >=, ||)
│   ├── intel/              clients for the public security sources (with disk cache)
│   ├── notify/             Telegram and Slack notifications
│   ├── server/             HTTPS, JSON API, sessions, attempt limiting
│   ├── web/                dashboard (HTML/CSS/JS in a single embedded file)
│   └── version/            version
├── deploy/                 install.sh and devdoctor.service
├── scripts/build.sh        cross-compilation linux/amd64 and linux/arm64
├── go.mod
└── README.md
```

## Development and building

```bash
go vet ./...
go build ./cmd/devdoctor                 # binary for your system (real diagnosis requires Linux)
bash scripts/build.sh                    # static Linux binaries in dist/
```

To try it without touching the system, use another configuration path:

```bash
./devdoctor init --config ./dev/config.json --port 9555 --password 'TestPassword123'
./devdoctor run  --config ./dev/config.json
```

To add a new check: create `internal/scanner/check_<topic>.go` with a function `checkTopic(c *Collector)`,
register the call in the `RunSync` list (`scanner.go`) and use
`c.add(category, severity, title, detail, fix)` to emit findings.

## Updating and uninstalling

**Update:** build, copy `dist/` to the server and run `sudo ./install.sh` again. It keeps the existing
configuration, password and certificate.

**Uninstall:**

```bash
sudo systemctl disable --now devdoctor
sudo rm /etc/systemd/system/devdoctor.service /usr/local/bin/devdoctor
sudo rm -rf /etc/devdoctor
sudo systemctl daemon-reload
```

## Troubleshooting

### I forgot my password / I am locked out

On the server (over SSH):

```bash
sudo devdoctor passwd                                    # generates a random password and shows it
sudo devdoctor passwd --password 'MyNewPassword-2026!'   # or one you choose
sudo devdoctor passwd --user other --password '…'        # you can also change the username
```

The command saves the new credentials and **restarts the service**, which closes all sessions and clears
the failed-attempt lockout (which lives in memory). With `--no-restart` it does not restart. It also works
if you never created the account from the web.

| Symptom | What to do |
|---|---|
| The URL does not open | `sudo systemctl status devdoctor`; check that the port is open in the firewall (`ufw allow PORT/tcp`) and in your cloud provider's panel |
| The URL shows a private IP | Reinstall with `--host PUBLIC_IP` or edit `host` in `config.json` and restart |
| `El puerto N ya está ocupado` (port N is already in use) | Pick another one with `--port` |
| I forgot the password or got locked out | `sudo devdoctor passwd` creates a new password, restarts the service and clears the lockout (see above) |
| "Too many attempts" | Wait 15 minutes, or run `sudo devdoctor passwd` (restarts the service and clears the lockout) |
| Projects shown as "not audited" | The server has no internet access or `composer`/`npm` is missing |
| The Docker tab shows no data | `docker` is not installed or the service has no access to `/var/run/docker.sock` |
| SSH/security data is missing | Run the service as root (which is what the default unit does) |
| Service logs | `sudo journalctl -u devdoctor -n 50` |

## Known limitations

- Linux with systemd only; on other systems the binary compiles but there is no data to analyze.
- Vulnerability scans depend on external tools (`composer audit`, `npm audit`, `trivy`) and on having an
  internet connection.
- Dependency probing is limited to 40 projects and 4 levels of depth.
- Detecting versions inside containers with no shell and no version environment variables (e.g.
  `distroless` images) is not possible.
- It is a best-practices diagnosis, and **does not replace** a professional security audit.

## Author and contact

Created by **Ricardo Alvarez** ([RASOFTDEV](https://github.com/rasoftdev)).

- Email: [dev@ricardoalvarez.co](mailto:dev@ricardoalvarez.co)
- Website: [me.ricardoalvarez.co](https://me.ricardoalvarez.co)

Found a bug or want to propose a new check? Write to the contact email.

## License

DevDoctor is free software under the **MIT license**: anyone may use, copy, modify and distribute it,
including for commercial purposes, as long as the copyright notice is kept. See the
[LICENSE](LICENSE) file. The software is provided "as is", without warranty of any kind.
