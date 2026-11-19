#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 The Anzen contributors
"""lib/receiver.py — HTTP side of `anzen --receiver` (push agents).

It only moves bytes. Every decision (is the key approved, is the signature
good, is this an anzen report, is the name free) is made by lib/agent.sh,
called through anzen.sh. Standard library only. Plain HTTP: a reverse proxy in
front does TLS.

Agent port (AGENT_LISTEN), for the hosts:
  GET  /enrol         bootstrap script for a new host
  GET  /anzen.tar.gz  this controller's anzen
  POST /enrol         a public key asking for approval
  POST /report        a signed JSON report from an approved key
  POST /poll          a signed "poll <time>"; answers "scan" or "idle"

Admin port (AGENT_ADMIN_LISTEN), for the admin's browser: lib/controller.html
and its JSON API. Signing in takes the token in AGENT_ADMIN_TOKEN_FILE. Every
change needs the session cookie and the page's CSRF value, and is written to
audit.log in the state directory.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

ANZEN_SH = os.environ["ANZEN_SH"]
CONF = os.environ.get("ANZEN_CONF", "")
STATE = os.environ["AGENT_STATE_DIR"]
PUBLIC_URL = os.environ.get("AGENT_PUBLIC_URL", "")
MAX_REPORT = int(os.environ.get("AGENT_MAX_BYTES", 20 * 1024 * 1024))
# agent.sh return codes for a signed upload
SIGNED_STATUS = {0: 200, 3: 403, 4: 400}
NAME = r"[A-Za-z0-9_-]{1,40}"
CODE = r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}"
# Both ports end in the same history and key files: one anzen call at a time
LOCK = threading.Lock()


def anzen(args, env=None):
    """Run anzen.sh with ARGS; returns (return code, stdout, last stderr line)."""
    cmd = ["bash", ANZEN_SH] + args + (["--config=" + CONF] if CONF else [])
    try:
        with LOCK:
            r = subprocess.run(cmd, env={**os.environ, **(env or {})}, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=600, check=False)
    except subprocess.TimeoutExpired:
        return 1, b"", "timed out"
    err = r.stderr.decode("utf-8", "replace")
    if err:
        sys.stderr.write(err)
    return r.returncode, r.stdout, (err.strip().splitlines() or [""])[-1]


def op(name, env=None):
    rc, out, _ = anzen(["--agent-op=" + name], env)
    return rc, out


class Base(BaseHTTPRequestHandler):
    timeout = 30  # seconds a client may stall
    server_version = "anzen"
    sys_version = ""

    def reply(self, code, body=b"", ctype="text/plain", headers=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def body(self, limit):
        """The request body, or None after an error reply."""
        n = self.headers.get("Content-Length", "")
        if not n.isdigit():
            self.reply(411)
            return None
        if not 0 < int(n) <= limit:
            self.reply(413)
            return None
        data = self.rfile.read(int(n))
        if len(data) != int(n):
            self.reply(400)
            return None
        return data


class Agent(Base):
    def do_GET(self):
        if self.path == "/enrol":
            rc, out = op("script")
            self.reply(200 if rc == 0 else 500, out, "text/x-shellscript")
        elif self.path == "/anzen.tar.gz":
            rc, out = op("tarball")
            self.reply(200 if rc == 0 else 500, out, "application/gzip")
        else:
            self.reply(404)

    def do_POST(self):
        if self.path == "/enrol":
            self.enrol()
        elif self.path == "/report":
            self.signed("report", MAX_REPORT)
        elif self.path == "/poll":
            self.signed("poll", 64)
        else:
            self.reply(404)

    def enrol(self):
        data = self.body(2048)
        if data is None:
            return
        name = re.sub(r"[^A-Za-z0-9._-]", "", self.headers.get("X-Anzen-Name", ""))[:64]
        with tempfile.NamedTemporaryFile() as f:
            f.write(data)
            f.flush()
            rc, out = op("enrol", {"ANZEN_AGENT_BODY": f.name, "ANZEN_AGENT_NAME": name})
        self.reply({0: 202, 2: 429}.get(rc, 400), out.strip())

    def signed(self, what, limit):
        """A body signed by an approved key, handed to agent.sh."""
        agent = self.headers.get("X-Anzen-Agent", "")
        # Before the body is read: strangers cannot make the controller store megabytes
        if not re.fullmatch(r"[0-9a-f]{64}", agent) or \
                not os.path.isfile(os.path.join(STATE, "approved", agent + ".pem")):
            self.reply(403)
            return
        sig = self.headers.get("X-Anzen-Signature", "")
        try:
            if len(sig) > 1024:
                raise ValueError
            sig = base64.b64decode(sig, validate=True)
        except (ValueError, binascii.Error):
            self.reply(400)
            return
        data = self.body(limit)
        if data is None:
            return
        with tempfile.NamedTemporaryFile() as fs, tempfile.NamedTemporaryFile() as fb:
            fs.write(sig)
            fs.flush()
            fb.write(data)
            fb.flush()
            rc, out = op(what, {"ANZEN_AGENT_ID": agent, "ANZEN_AGENT_SIG": fs.name,
                                "ANZEN_AGENT_BODY": fb.name})
        self.reply(SIGNED_STATUS.get(rc, 500), out.strip() if rc == 0 and what == "poll" else b"")


# ── Web controller ───────────────────────────────────────────────────────────

def _mac(token, what):
    return hmac.new(token.encode(), what, hashlib.sha256).hexdigest()


class Admin(Base):
    token = ""      # set in main()
    page = ""       # lib/controller.html

    def who(self):
        """Who to name in the audit log: the proxy's login header when there is one."""
        user = self.headers.get("Remote-User") or self.headers.get("X-Forwarded-User") or "-"
        addr = self.headers.get("X-Forwarded-For") or self.client_address[0]
        clean = lambda v: re.sub(r"[^A-Za-z0-9@._:, -]", "", v)[:80]
        return clean(user) + " " + clean(addr)

    def audit(self, action, target, ok):
        line = "\t".join([time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), self.who(), action,
                          target, "ok" if ok else "failed"])
        fd = os.open(os.path.join(STATE, "audit.log"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(line + "\n")

    def authed(self):
        c = SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except Exception:  # a cookie header the parser refuses
            return False
        v = c.get("anzen_admin")
        return bool(v) and hmac.compare_digest(v.value, _mac(self.token, b"session"))

    def html(self, code, view, error="", headers=()):
        nonce = secrets.token_urlsafe(16)
        csrf = _mac(self.token, b"csrf") if view == "app" else ""
        body = (self.page.replace("__NONCE__", nonce).replace("__VIEW__", view)
                .replace("__CSRF__", csrf).replace("__ERROR__", error))
        self.reply(code, body.encode(), "text/html; charset=utf-8", (
            ("Content-Security-Policy",
             "default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src 'self'; "
             "form-action 'self'; base-uri 'none'; frame-ancestors 'none'" % (nonce, nonce)),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
            ("Cache-Control", "no-store")) + tuple(headers))

    def json(self, code, obj):
        self.reply(code, json.dumps(obj).encode(), "application/json",
                   (("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")))

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self.html(200, "app" if self.authed() else "login")
        elif path == "/api/state":
            if not self.authed():
                self.json(401, {"ok": False})
                return
            self.json(200, self.state())
        else:
            self.reply(404)

    def state(self):
        _, out = op("state")
        keys = ("state", "code", "name", "last", "seen", "scan", "score", "fail", "warn")
        agents = []
        for line in out.decode("utf-8", "replace").splitlines():
            a = dict(zip(keys, line.split("\t")))
            if len(a) == len(keys):
                a["scan"] = a["scan"] == "1"
                agents.append(a)
        log = []
        try:
            with open(os.path.join(STATE, "audit.log"), encoding="utf-8", errors="replace") as f:
                for line in f.readlines()[-50:]:
                    p = line.rstrip("\n").split("\t")
                    if len(p) == 5:
                        log.append(dict(zip(("time", "who", "action", "target", "result"), p)))
        except OSError:
            pass
        return {"ok": True, "now": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "enrol": "curl -fsSL %s/enrol | sudo sh" % PUBLIC_URL, "agents": agents,
                "log": log[::-1]}

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/login":
            self.login()
            return
        if not self.authed() or not hmac.compare_digest(
                self.headers.get("X-Anzen-Csrf", ""), _mac(self.token, b"csrf")):
            self.json(403, {"ok": False, "message": "Sign in again"})
            return
        if path == "/logout":
            self.reply(200, b'{"ok": true}', "application/json",
                       (("Set-Cookie", "anzen_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),))
            return
        data = self.body(1024)
        if data is None:
            return
        try:
            req = json.loads(data)

            def get(k, pattern):
                if not re.fullmatch(pattern, req[k]):
                    raise ValueError(k)
                return req[k]
            # Only these shapes reach anzen.sh, each as one argument
            args, target = {
                "/api/approve": lambda: ("--agent-approve=%s:%s" % (get("code", CODE), get("name", NAME)),
                                         "%s as %s" % (req["code"], req["name"])),
                "/api/reject": lambda: ("--agent-revoke=" + get("code", CODE), req["code"]),
                "/api/revoke": lambda: ("--agent-revoke=" + get("name", NAME), req["name"]),
                "/api/rename": lambda: ("--agent-rename=%s:%s" % (get("name", NAME), get("new", NAME)),
                                        "%s to %s" % (req["name"], req["new"])),
                "/api/scan": lambda: ("--agent-scan=" + get("name", NAME), req["name"]),
            }[path]()
        except (KeyError, TypeError, ValueError):
            self.json(400, {"ok": False, "message": "Not a valid request"})
            return
        rc, out, err = anzen([args])
        self.audit(path.rsplit("/", 1)[1], target, rc == 0)
        msg = out.decode("utf-8", "replace").strip().splitlines()
        self.json(200 if rc == 0 else 409,
                  {"ok": rc == 0, "message": (msg[-1] if msg and rc == 0 else err) or "Failed"})

    def login(self):
        data = self.body(512)
        if data is None:
            return
        given = parse_qs(data.decode("utf-8", "replace")).get("token", [""])[0].strip()
        ok = hmac.compare_digest(given.encode(), self.token.encode())
        self.audit("sign-in", "-", ok)
        if not ok:
            self.html(401, "login", "That is not the token.")
            return
        cookie = "anzen_admin=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200" % _mac(self.token, b"session")
        if self.headers.get("X-Forwarded-Proto") == "https":
            cookie += "; Secure"
        self.reply(303, headers=(("Location", "./"), ("Set-Cookie", cookie)))


def listen(addr, handler):
    host, _, port = addr.rpartition(":")
    return HTTPServer((host, int(port)), handler)


def main():
    agent = listen(os.environ.get("AGENT_LISTEN", "127.0.0.1:8787"), Agent)
    admin_addr = os.environ.get("AGENT_ADMIN_LISTEN", "")
    if not admin_addr:
        agent.serve_forever()
        return
    with open(os.environ["AGENT_ADMIN_TOKEN_FILE"], encoding="ascii") as f:
        Admin.token = f.read().strip()
    if len(Admin.token) < 32:
        sys.exit("ERROR: the admin token file holds no usable token")
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "controller.html"),
              encoding="utf-8") as f:
        Admin.page = f.read()
    threading.Thread(target=agent.serve_forever, daemon=True).start()
    listen(admin_addr, Admin).serve_forever()


if __name__ == "__main__":
    main()
