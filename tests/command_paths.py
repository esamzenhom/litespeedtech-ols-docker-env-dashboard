#!/usr/bin/env python3
"""Non-mutating command-path coverage for operations unsafe to run in E2E."""
import sys

sys.path.insert(0, "/app")
import app


class FakeContainer:
    status = "running"
    name = "fake"
    attrs = {"Config": {"Env": ["MYSQL_ROOT_PASSWORD=test"], "Image": "fake"}}


commands = []
fake = FakeContainer()


def fake_discover(_kind):
    return fake


def fake_exec(_container, command, user="root", env=None):
    commands.append((command, user, env or {}))
    return "ok"


app.discover = fake_discover
app.exec_in = fake_exec

cases = [
    ("upgrade", {}),
    ("serial", {"serial": "TRIAL"}),
    ("acme_install", {"email": "admin@example.com"}),
    ("acme_uninstall", {}),
    ("acme_issue", {"domain": "example.com", "force": True}),
    ("acme_renew", {"domain": "example.com", "force": True}),
    ("acme_renew_all", {"force": True}),
    ("acme_revoke", {"domain": "example.com"}),
    ("acme_remove", {"domain": "example.com"}),
]

for action, payload in cases:
    before = len(commands)
    app.perform(action, payload)
    assert len(commands) > before, f"{action} emitted no container commands"
    print(f"PASS command path {action}")
