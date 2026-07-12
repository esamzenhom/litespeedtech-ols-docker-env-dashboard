# OLS Control Dashboard

A standalone Docker Compose dashboard for an **already running** `ols-docker-env` stack. It discovers OpenLiteSpeed and MariaDB/MySQL containers through Docker Compose labels, container names, and image names. The original stack does not need to be edited or joined to the dashboard network.

The OpenLiteSpeed Docker environment managed by this dashboard is the official [`litespeedtech/ols-docker-env`](https://github.com/litespeedtech/ols-docker-env) project. The local `OLS-DOCKER-ENV-MASTER` directory is a checkout/copy of that upstream repository.

## Start

```bash
cd DASHBOARD
cp .env.example .env
openssl rand -hex 32   # paste this into SECRET_KEY in .env
# Set a long DASHBOARD_PASSWORD in .env
docker compose up -d --build
```

Open <http://localhost:8090> and sign in with `DASHBOARD_PASSWORD`.

The OLS stack can live in any directory and Compose project. Start it first. If more than one matching stack exists, set `OLS_CONTAINER` and `MYSQL_CONTAINER` in `.env` to the desired container names.

## Included controls

- Detect OpenLiteSpeed and MariaDB/MySQL container health
- Add/remove domains and restart OLS
- Create/delete databases and store WordPress `.db_pass` credentials
- Install WordPress or provision domain + database + WordPress
- Install/uninstall ACME, issue/renew/revoke/remove certificates, renew all
- Persistently schedule automatic ACME renew-all checks every 1, 3, 7, 14, or 30 days
- Generate local-development certificates, configure local TLS, and download the persistent local CA
- Set WebAdmin password, restart/upgrade OLS, enable/disable ModSecurity, and apply an Enterprise serial or trial
- Asynchronous action history and captured command output

For local certificates, download the dashboard CA and add it to the trust store of each browser/host that uses the development domain. Unlike the original host-side `mkcert --install`, a container cannot silently change the host trust store.

## Security

The dashboard mounts `/var/run/docker.sock`, which grants Docker-host administrative power. Keep it on a private/admin network, use a strong password, and do not expose port 8090 directly to the public Internet. Put it behind HTTPS and an additional access-control layer for remote use.

The API exposes only predefined operations with input validation; it does not provide arbitrary shell execution. Secrets entered in forms are used for the requested operation, but successful database-creation output contains the generated credentials in the in-memory activity list until the dashboard container restarts.

## Stop

```bash
docker compose down
```

Add `-v` only if you also want to delete the dashboard local CA.

## Tests

With the dashboard and OLS stack running, copy and execute the live reversible test:

```bash
docker cp tests/e2e.py ols-control-dashboard:/tmp/e2e.py
docker exec ols-control-dashboard python /tmp/e2e.py
```

The test uses `dashboard-e2e.test` and `dashboard_e2e`, then removes their OLS, database, and certificate configuration. It intentionally leaves licensing, public certificate authorities, and server binaries unchanged. Their command construction is covered separately:

```bash
docker cp tests/command_paths.py ols-control-dashboard:/tmp/command_paths.py
docker exec ols-control-dashboard python /tmp/command_paths.py
```
