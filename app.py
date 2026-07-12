import io
import json
import os
import re
import secrets
import tarfile
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from functools import wraps

import docker
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
client = docker.from_env()
jobs = {}
jobs_lock = threading.Lock()
settings_lock = threading.Lock()
SETTINGS_PATH = "/data/settings.json"
DEFAULT_SETTINGS = {"auto_renew": False, "renew_interval_days": 1, "last_auto_renew": None}

DOMAIN_RE = re.compile(r"^(localhost|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,})$")
IDENT_RE = re.compile(r"^[A-Za-z0-9_]{1,63}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}$")


class ActionError(Exception):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_settings():
    with settings_lock:
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
        except (OSError, ValueError, TypeError):
            saved = {}
        return {**DEFAULT_SETTINGS, **saved}


def save_settings(settings):
    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    temporary = SETTINGS_PATH + ".tmp"
    with settings_lock:
        with open(temporary, "w", encoding="utf-8") as f:
            json.dump(settings, f)
        os.replace(temporary, SETTINGS_PATH)


def authenticated(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify(error="Authentication required"), 401
        return fn(*args, **kwargs)
    return wrapped


def csrf_ok():
    return secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session.get("csrf", ""))


def env_map(container):
    return dict(item.split("=", 1) if "=" in item else (item, "") for item in container.attrs["Config"].get("Env", []))


def discover(kind):
    override = os.environ.get("OLS_CONTAINER" if kind == "ols" else "MYSQL_CONTAINER", "").strip()
    if override:
        try:
            return client.containers.get(override)
        except docker.errors.NotFound as exc:
            raise ActionError(f"Configured container '{override}' was not found") from exc

    candidates = []
    for c in client.containers.list(all=True):
        labels = c.labels or {}
        service = labels.get("com.docker.compose.service", "").lower()
        image = (c.attrs.get("Config", {}).get("Image") or "").lower()
        name = c.name.lower()
        if kind == "ols" and (service == "litespeed" or name == "litespeed" or "openlitespeed" in image):
            candidates.append(c)
        if kind == "mysql" and (service in ("mysql", "mariadb") or "mariadb" in image or image.startswith("mysql:")):
            candidates.append(c)
    running = [c for c in candidates if c.status == "running"]
    pool = running or candidates
    if not pool:
        raise ActionError(f"No {'OpenLiteSpeed' if kind == 'ols' else 'MariaDB/MySQL'} container detected")
    projects = {c.labels.get("com.docker.compose.project") for c in pool}
    if len(pool) > 1 and len(projects) > 1:
        raise ActionError(f"Multiple {kind} containers detected; set the explicit container name in dashboard .env")
    return pool[0]


def exec_in(container, command, user="root", env=None):
    if container.status != "running":
        raise ActionError(f"Container '{container.name}' is not running")
    # Do not use a login shell here. The upstream image's /root/.profile may
    # source ACME files that do not exist until ACME has been installed.
    result = container.exec_run(["/bin/bash", "-c", command], user=user, environment=env or {}, demux=True)
    stdout, stderr = result.output or (b"", b"")
    output = (stdout or b"").decode("utf-8", "replace") + (stderr or b"").decode("utf-8", "replace")
    if result.exit_code != 0:
        raise ActionError(output.strip() or f"Command failed with exit code {result.exit_code}")
    return output.strip()


def q(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def domain(value):
    value = (value or "").strip().lower()
    if value.startswith("www."):
        value = value[4:]
    if not DOMAIN_RE.fullmatch(value):
        raise ActionError("Enter a valid root domain, without a URL path")
    return value


def identifier(value, label):
    value = (value or "").strip()
    if not IDENT_RE.fullmatch(value):
        raise ActionError(f"{label} may contain letters, numbers and underscores only (maximum 63)")
    return value


def restart_ols(ols):
    return exec_in(ols, "/usr/local/lsws/bin/lswsctrl restart")


def put_files(container, destination, files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data, mode in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            archive.addfile(info, io.BytesIO(data))
    stream.seek(0)
    exec_in(container, f"mkdir -p {q(destination)}")
    if not container.put_archive(destination, stream.read()):
        raise ActionError("Could not copy certificate files into the OpenLiteSpeed container")


def require_tools(ols, *names):
    for name in names:
        exec_in(ols, f"command -v {q(name)} >/dev/null || {{ echo 'Required helper {name} is not mounted in the OpenLiteSpeed container'; exit 1; }}")


def perform(action, p):
    ols = discover("ols")
    output = []
    if action == "restart":
        output.append(restart_ols(ols))
    elif action == "webadmin_password":
        password = p.get("password", "")
        if len(password) < 12:
            raise ActionError("WebAdmin password must be at least 12 characters")
        script = 'A=/usr/local/lsws/admin; PHP=$A/fcgi-bin/admin_php; [ -x "$PHP" ] || PHP=$A/fcgi-bin/admin_php5; echo "admin:$($PHP -q $A/misc/htpasswd.php "$NEW_PASSWORD")" > $A/conf/htpasswd'
        output.append(exec_in(ols, script, user="lsadm", env={"NEW_PASSWORD": password}))
    elif action == "modsecurity":
        mode = p.get("mode")
        if mode not in ("enable", "disable"):
            raise ActionError("Invalid ModSecurity mode")
        require_tools(ols, "owaspctl.sh")
        output.append(exec_in(ols, f"owaspctl.sh --{mode}"))
        output.append(restart_ols(ols))
    elif action == "upgrade":
        output.append(exec_in(ols, "/usr/local/lsws/admin/misc/lsup.sh"))
    elif action == "serial":
        serial = (p.get("serial") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,128}", serial):
            raise ActionError("Invalid serial value")
        require_tools(ols, "serialctl.sh")
        output.append(exec_in(ols, f"serialctl.sh --serial {q(serial)}"))
        output.append(restart_ols(ols))
    elif action in ("domain_add", "domain_delete"):
        d = domain(p.get("domain"))
        require_tools(ols, "domainctl.sh")
        flag = "--add" if action == "domain_add" else "--del"
        output.append(exec_in(ols, f"cd /usr/local/lsws/conf && domainctl.sh {flag} {q(d)}", user="lsadm"))
        if action == "domain_add":
            output.append(exec_in(ols, f"mkdir -p /var/www/vhosts/{q(d)}/html /var/www/vhosts/{q(d)}/logs /var/www/vhosts/{q(d)}/certs"))
        output.append(restart_ols(ols))
    elif action in ("database_create", "database_delete"):
        db = discover("mysql")
        dbname = identifier(p.get("database"), "Database")
        username = identifier(p.get("username") or dbname, "Username")
        root_password = env_map(db).get("MYSQL_ROOT_PASSWORD")
        if not root_password:
            raise ActionError("MYSQL_ROOT_PASSWORD was not found in the database container environment")
        if action == "database_create":
            password = p.get("password") or secrets.token_urlsafe(18)
            if len(password) < 8 or any(x in password for x in "'\"\\$`"):
                raise ActionError("Database password must be 8+ characters and cannot contain quotes, backslash, $, or backtick")
            sql = f"CREATE DATABASE `{dbname}`; CREATE USER IF NOT EXISTS '{username}'@'%' IDENTIFIED BY '{password}'; GRANT ALL ON `{dbname}`.* TO '{username}'@'%'; FLUSH PRIVILEGES;"
            output.append(exec_in(db, "mariadb -uroot --password=\"$MYSQL_ROOT_PASSWORD\" -e " + q(sql), env={"MYSQL_ROOT_PASSWORD": root_password}))
            d = p.get("domain")
            if d:
                d = domain(d)
                credential = f'"Database":"{dbname}"\n"Username":"{username}"\n"Password":"{password}"\n'
                exec_in(ols, f"test -d /var/www/vhosts/{q(d)} && printf %s {q(credential)} > /var/www/vhosts/{q(d)}/.db_pass")
            output.append(f"Database: {dbname}\nUsername: {username}\nPassword: {password}")
        else:
            sql = f"DROP DATABASE IF EXISTS `{dbname}`; DROP USER IF EXISTS '{username}'@'%'; FLUSH PRIVILEGES;"
            output.append(exec_in(db, "mariadb -uroot --password=\"$MYSQL_ROOT_PASSWORD\" -e " + q(sql), env={"MYSQL_ROOT_PASSWORD": root_password}))
            output.append(f"Deleted database {dbname} and user {username}")
    elif action == "wordpress":
        d = domain(p.get("domain"))
        require_tools(ols, "appinstallctl.sh")
        output.append(exec_in(ols, f"appinstallctl.sh --app wordpress --domain {q(d)}"))
        output.append(restart_ols(ols))
    elif action == "demo_site":
        d = domain(p.get("domain"))
        dbname = identifier(p.get("database"), "Database")
        username = identifier(p.get("username"), "Username")
        perform("domain_add", {"domain": d})
        output.append(perform("database_create", {"domain": d, "database": dbname, "username": username, "password": p.get("password")}) )
        output.append(perform("wordpress", {"domain": d}))
    elif action.startswith("acme_"):
        acme = "/root/.acme.sh/acme.sh"
        if action == "acme_install":
            require_tools(ols, "certhookctl.sh")
            email = (p.get("email") or "").strip()
            if not EMAIL_RE.fullmatch(email) or len(email) > 254:
                raise ActionError("Enter a valid email address")
            src = "https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.2/acme.sh"
            output.append(exec_in(ols, f"cd /root && wget -q {q(src)} -O acme-installer.sh && chmod 700 acme-installer.sh && ./acme-installer.sh --install --cert-home /root/.acme.sh/certs --accountemail {q(email)} && {acme} --set-default-ca --server letsencrypt && rm -f acme-installer.sh"))
            output.append(exec_in(ols, "certhookctl.sh"))
        elif action == "acme_uninstall":
            exec_in(ols, f"test -x {acme} || {{ echo 'ACME client is not installed'; exit 1; }}")
            output.append(exec_in(ols, f"{acme} --uninstall"))
        elif action == "acme_renew_all":
            exec_in(ols, f"test -x {acme} || {{ echo 'ACME client is not installed'; exit 1; }}")
            force = " --force" if p.get("force") else ""
            output.append(exec_in(ols, f"{acme} --renew-all{force}"))
            output.append(restart_ols(ols))
        else:
            exec_in(ols, f"test -x {acme} || {{ echo 'ACME client is not installed'; exit 1; }}")
            d = domain(p.get("domain"))
            op = {"acme_issue": "issue", "acme_renew": "renew", "acme_revoke": "revoke", "acme_remove": "remove"}.get(action)
            if not op:
                raise ActionError("Unknown ACME action")
            force = " --force" if p.get("force") and op in ("issue", "renew") else ""
            if op == "issue":
                cmd = f"{acme} --issue -d {q(d)} -d {q('www.' + d)} -w {q('/var/www/vhosts/' + d + '/html')}{force}"
            else:
                cmd = f"{acme} --{op} --domain {q(d)}{force}"
            output.append(exec_in(ols, cmd))
            output.append(restart_ols(ols))
    elif action == "local_cert":
        d = domain(p.get("domain"))
        ca_key, ca_cert = load_or_create_ca()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, d)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 2))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(d), x509.DNSName("www." + d)]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        put_files(ols, f"/usr/local/lsws/conf/cert/{d}", [("cert.pem", cert_pem, 0o644), ("key.pem", key_pem, 0o600)])
        output.append(exec_in(ols, local_ssl_script(d)))
        output.append(restart_ols(ols))
        output.append("Local certificate installed. Download and trust the dashboard CA from Settings before browsing the site.")
    elif action == "local_cert_remove":
        d = domain(p.get("domain"))
        output.append(exec_in(ols, local_ssl_remove_script(d)))
        output.append(restart_ols(ols))
    else:
        raise ActionError("Unknown action")
    return "\n".join(str(x) for x in output if x)


def load_or_create_ca():
    key_path, cert_path = "/data/local-ca-key.pem", "/data/local-ca.pem"
    if os.path.exists(key_path) and os.path.exists(cert_path):
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return key, cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OLS Dashboard Local CA"), x509.NameAttribute(NameOID.COMMON_NAME, "OLS Dashboard Local CA")])
    start = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start)
            .not_valid_after(start.replace(year=start.year + 10)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def local_ssl_script(d):
    return f"""
set -e
C=/usr/local/lsws/conf; H=$C/httpd_config.conf; T=$C/templates/docker-local.conf
if [ ! -f "$T" ]; then cp $C/templates/docker.conf "$T"; sed -i '/^  vhssl  {{/,/^  }}/d; $d' "$T"; printf '%s\n' '  vhssl  {{' '    keyFile /usr/local/lsws/conf/cert/$VH_NAME/key.pem' '    certFile /usr/local/lsws/conf/cert/$VH_NAME/cert.pem' '    certChain 1' '  }}' '}}' >> "$T"; fi
grep -q '^vhTemplate dockerLocal {{' "$H" || printf '\nvhTemplate dockerLocal {{\n  templateFile conf/templates/docker-local.conf\n  listeners HTTP, HTTPS\n}}\n' >> "$H"
V=$(grep -B2 'vhDomain.*{d}' "$H" | grep member | tail -1 | awk '{{print $2}}'); [ -n "$V" ] || {{ echo 'Virtual host not found'; exit 1; }}
sed -i "/^vhTemplate docker {{/,/^}}/ {{ /member $V {{/,/}}/d; }}" "$H"
sed -n '/^vhTemplate dockerLocal {{/,/^}}/p' "$H" | grep -q "member $V" || sed -i "/^vhTemplate dockerLocal {{/,/^}}/ {{ /^}}/ i\\  member $V {{\\n    vhDomain {d},www.{d}\\n  }}
}}" "$H"
"""


def local_ssl_remove_script(d):
    return f"""
set -e
H=/usr/local/lsws/conf/httpd_config.conf
V=$(grep -B2 'vhDomain.*{d}' "$H" | grep member | tail -1 | awk '{{print $2}}')
if [ -n "$V" ]; then sed -i "/^vhTemplate dockerLocal {{/,/^}}/ {{ /member $V {{/,/}}/d; }}" "$H"; sed -n '/^vhTemplate docker {{/,/^}}/p' "$H" | grep -q "member $V" || sed -i "/^vhTemplate docker {{/,/^}}/ {{ /^}}/ i\\  member $V {{\\n    vhDomain {d},www.{d}\\n  }}
}}" "$H"; fi
rm -rf {q('/usr/local/lsws/conf/cert/' + d)}
"""


def run_job(job_id, action, params):
    try:
        result = perform(action, params)
        state, error = "success", None
    except Exception as exc:
        state, result, error = "failed", "", str(exc)
        app.logger.error("Action %s failed: %s\n%s", action, exc, traceback.format_exc())
    with jobs_lock:
        jobs[job_id].update(state=state, output=result, error=error, finished_at=now())


def queue_job(action, params=None):
    job_id = uuid.uuid4().hex
    job = {"id": job_id, "action": action, "state": "running", "created_at": now(), "finished_at": None, "output": "", "error": None}
    with jobs_lock:
        jobs[job_id] = job
        if len(jobs) > 100:
            oldest = next(iter(jobs))
            if oldest != job_id:
                jobs.pop(oldest, None)
    threading.Thread(target=run_job, args=(job_id, action, params or {}), daemon=True).start()
    return job


def auto_renew_loop():
    time.sleep(10)
    while True:
        try:
            settings = load_settings()
            if settings["auto_renew"]:
                last = settings.get("last_auto_renew")
                last_dt = datetime.fromisoformat(last) if last else None
                due_seconds = int(settings["renew_interval_days"]) * 86400
                if not last_dt or (datetime.now(timezone.utc) - last_dt).total_seconds() >= due_seconds:
                    queue_job("acme_renew_all", {"automatic": True})
                    settings["last_auto_renew"] = now()
                    save_settings(settings)
        except Exception:
            app.logger.exception("Automatic certificate renewal check failed")
        time.sleep(3600)


@app.route("/")
def index():
    if not session.get("authenticated"):
        return render_template("login.html")
    return render_template("index.html", csrf=session["csrf"])


@app.post("/login")
def login():
    expected = os.environ.get("DASHBOARD_PASSWORD", "")
    if not expected or not secrets.compare_digest(request.form.get("password", ""), expected):
        return render_template("login.html", error="Invalid password"), 401
    session.clear()
    session.update(authenticated=True, csrf=secrets.token_urlsafe(32))
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/api/status")
@authenticated
def status():
    data = {}
    for kind in ("ols", "mysql"):
        try:
            c = discover(kind)
            data[kind] = {"found": True, "name": c.name, "status": c.status, "image": c.attrs["Config"]["Image"]}
        except Exception as exc:
            data[kind] = {"found": False, "error": str(exc)}
    return jsonify(data)


@app.get("/api/inventory")
@authenticated
def inventory():
    result = {"domains": [], "databases": [], "applications": [], "certificates": [], "errors": {}}
    try:
        ols = discover("ols")
        domain_output = exec_in(ols, "if [ -f /usr/local/lsws/conf/httpd_config.conf ]; then sed -n 's/^[[:space:]]*vhDomain[[:space:]]*//p' /usr/local/lsws/conf/httpd_config.conf | tr ',' '\\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^www\\.//' | sed '/^$/d' | sort -u; elif [ -f /usr/local/lsws/conf/httpd_config.xml ]; then sed -n 's:.*<vhDomain>\\([^<]*\\)</vhDomain>.*:\\1:p' /usr/local/lsws/conf/httpd_config.xml | tr ',' '\\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^www\\.//' | sed '/^$/d' | sort -u; fi; true")
        result["domains"] = sorted({line.strip() for line in domain_output.splitlines() if line.strip()})

        app_output = exec_in(ols, "for p in /var/www/vhosts/*; do [ -f \"$p/html/wp-config.php\" ] && basename \"$p\"; done; true")
        result["applications"] = [{"domain": item.strip(), "application": "WordPress"} for item in app_output.splitlines() if item.strip()]

        acme_output = exec_in(ols, "if [ -d /root/.acme.sh/certs ]; then for p in /root/.acme.sh/certs/*; do [ -d \"$p\" ] && basename \"$p\"; done; fi; true")
        local_output = exec_in(ols, "if [ -d /usr/local/lsws/conf/cert ]; then for p in /usr/local/lsws/conf/cert/*; do [ -d \"$p\" ] && [ -f \"$p/cert.pem\" ] && basename \"$p\"; done; fi; true")
        certs = {(name.strip(), "Let's Encrypt / ACME") for name in acme_output.splitlines() if name.strip()}
        certs.update((name.strip(), "Local CA") for name in local_output.splitlines() if name.strip())
        result["certificates"] = [{"domain": name, "type": cert_type} for name, cert_type in sorted(certs)]
    except Exception as exc:
        result["errors"]["ols"] = str(exc)

    try:
        db = discover("mysql")
        root_password = env_map(db).get("MYSQL_ROOT_PASSWORD")
        if not root_password:
            raise ActionError("MYSQL_ROOT_PASSWORD was not found in the database container environment")
        sql = "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema','mysql','performance_schema','sys') ORDER BY SCHEMA_NAME;"
        db_output = exec_in(db, "mariadb -N -B -uroot --password=\"$MYSQL_ROOT_PASSWORD\" -e " + q(sql), env={"MYSQL_ROOT_PASSWORD": root_password})
        result["databases"] = [line.strip() for line in db_output.splitlines() if line.strip()]
    except Exception as exc:
        result["errors"]["mysql"] = str(exc)
    return jsonify(result)


@app.post("/api/actions/<action>")
@authenticated
def action(action):
    if not csrf_ok():
        return jsonify(error="Invalid CSRF token"), 403
    params = request.get_json(silent=True) or {}
    job = queue_job(action, params)
    return jsonify(job), 202


@app.get("/api/settings")
@authenticated
def get_settings():
    return jsonify(load_settings())


@app.put("/api/settings/auto-renew")
@authenticated
def update_auto_renew():
    if not csrf_ok():
        return jsonify(error="Invalid CSRF token"), 403
    payload = request.get_json(silent=True) or {}
    enabled = payload.get("auto_renew") is True
    try:
        interval = int(payload.get("renew_interval_days", 1))
    except (TypeError, ValueError):
        return jsonify(error="Invalid renewal interval"), 400
    if interval not in (1, 3, 7, 14, 30):
        return jsonify(error="Renewal interval must be 1, 3, 7, 14, or 30 days"), 400
    settings = load_settings()
    settings.update(auto_renew=enabled, renew_interval_days=interval)
    save_settings(settings)
    return jsonify(settings)


@app.get("/api/jobs")
@authenticated
def list_jobs():
    with jobs_lock:
        return jsonify(list(reversed(list(jobs.values()))))


@app.get("/api/jobs/<job_id>")
@authenticated
def get_job(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    return jsonify(job) if job else (jsonify(error="Job not found"), 404)


@app.get("/api/local-ca.pem")
@authenticated
def ca_download():
    _, cert = load_or_create_ca()
    return Response(cert.public_bytes(serialization.Encoding.PEM), mimetype="application/x-pem-file", headers={"Content-Disposition": "attachment; filename=ols-dashboard-local-ca.pem"})


threading.Thread(target=auto_renew_loop, daemon=True, name="acme-auto-renew").start()
