#!/usr/bin/env python3
"""Live dashboard API smoke test. Intended to run inside the dashboard container."""
import os
import re
import sys
import time

import requests


BASE = os.environ.get("TEST_BASE_URL", "http://127.0.0.1:8080")
PASSWORD = os.environ["DASHBOARD_PASSWORD"]
DOMAIN = os.environ.get("TEST_DOMAIN", "dashboard-e2e.test")
DATABASE = os.environ.get("TEST_DATABASE", "dashboard_e2e")
USERNAME = os.environ.get("TEST_USERNAME", "dashboard_e2e")
DB_PASSWORD = os.environ.get("TEST_DB_PASSWORD", "DashboardE2e-2026")
session = requests.Session()
csrf = ""


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def login():
    response = session.post(BASE + "/login", data={"password": PASSWORD}, allow_redirects=True, timeout=10)
    response.raise_for_status()
    match = re.search(r'name="csrf-token" content="([^"]+)"', response.text)
    check(match, "CSRF token missing after login")
    global csrf
    csrf = match.group(1)


def get(path):
    response = session.get(BASE + path, timeout=20)
    response.raise_for_status()
    return response.json()


def action(name, payload=None, expect_success=True, timeout=900):
    response = session.post(BASE + "/api/actions/" + name, json=payload or {}, headers={"X-CSRF-Token": csrf}, timeout=20)
    response.raise_for_status()
    job = response.json()
    deadline = time.time() + timeout
    while job["state"] == "running" and time.time() < deadline:
        time.sleep(1)
        job = get("/api/jobs/" + job["id"])
    check(job["state"] != "running", f"{name} timed out")
    if expect_success:
        check(job["state"] == "success", f"{name} failed: {job.get('error')}")
    else:
        check(job["state"] == "failed", f"{name} unexpectedly succeeded")
    print(f"PASS action {name}: {job['state']}")
    return job


def cleanup():
    for name, payload in (
        ("local_cert_remove", {"domain": DOMAIN}),
        ("database_delete", {"database": DATABASE, "username": USERNAME}),
        ("domain_delete", {"domain": DOMAIN}),
    ):
        try:
            action(name, payload)
        except Exception as exc:
            print(f"CLEANUP warning {name}: {exc}", file=sys.stderr)


def main():
    login()
    check(get("/health")["status"] == "ok", "Health endpoint failed")
    status = get("/api/status")
    check(status["ols"]["found"] and status["mysql"]["found"], "OLS/MySQL discovery failed")
    print("PASS health, authentication, and container discovery")

    inventory = get("/api/inventory")
    check(not inventory["errors"], f"Inventory errors: {inventory['errors']}")
    print("PASS domain, database, application, and certificate inventory")

    # Validation/security paths.
    action("domain_add", {"domain": "bad domain; id"}, expect_success=False)
    action("webadmin_password", {"password": "short"}, expect_success=False)
    action("serial", {"serial": "bad serial; id"}, expect_success=False)
    print("PASS command injection and secret validation")

    previous = get("/api/settings")
    response = session.put(BASE + "/api/settings/auto-renew", json={"auto_renew": True, "renew_interval_days": 7}, headers={"X-CSRF-Token": csrf}, timeout=10)
    response.raise_for_status()
    check(get("/api/settings")["auto_renew"], "Auto-renew did not enable")
    response = session.put(BASE + "/api/settings/auto-renew", json={"auto_renew": previous["auto_renew"], "renew_interval_days": previous["renew_interval_days"]}, headers={"X-CSRF-Token": csrf}, timeout=10)
    response.raise_for_status()
    print("PASS automatic-renew settings")

    try:
        action("restart")
        action("domain_add", {"domain": DOMAIN})
        check(DOMAIN in get("/api/inventory")["domains"], "New domain absent from inventory")
        action("database_create", {"domain": DOMAIN, "database": DATABASE, "username": USERNAME, "password": DB_PASSWORD})
        check(DATABASE in get("/api/inventory")["databases"], "New database absent from inventory")
        action("wordpress", {"domain": DOMAIN}, timeout=900)
        apps = get("/api/inventory")["applications"]
        check(any(item["domain"] == DOMAIN and item["application"] == "WordPress" for item in apps), "WordPress absent from inventory")
        action("local_cert", {"domain": DOMAIN})
        certs = get("/api/inventory")["certificates"]
        check(any(item["domain"] == DOMAIN and item["type"] == "Local CA" for item in certs), "Local certificate absent from inventory")
        ca = session.get(BASE + "/api/local-ca.pem", timeout=10)
        ca.raise_for_status()
        check(b"BEGIN CERTIFICATE" in ca.content, "Local CA download is invalid")
        print("PASS domain, database, WordPress, local TLS, CA download, and inventory lifecycle")
    finally:
        cleanup()

    inventory = get("/api/inventory")
    check(DOMAIN not in inventory["domains"], "Temporary domain was not removed")
    check(DATABASE not in inventory["databases"], "Temporary database was not removed")
    print("PASS cleanup and final inventory")


if __name__ == "__main__":
    main()
