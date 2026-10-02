"""
End-to-end browser tests for Privipod, using Playwright.

These start their own Privipod servers with temporary databases, so no server needs to
be running first:

* ``server`` - the main server, with server-stored keys enabled
* ``keyfile_server`` - a server run with ``--no-server-keys``, for key file flows

Each test creates its own users, so tests do not share keys or pods. Tests can reach
into a server's database to set up states the UI won't allow, such as expired pods.

Run with ``--headed`` or ``--slowmo 500`` to watch, or ``--tracing retain-on-failure``
to keep a Playwright trace of failures.
"""

import itertools
import socket
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests
from playwright.sync_api import BrowserContext

from .utils import login

REPO_ROOT = Path(__file__).parent.parent.parent
PASSWORD = "e2e-password"
_user_ids = itertools.count(1)


@dataclass
class User:
    username: str
    password: str = PASSWORD


class Server:
    """A running Privipod server process with its own database."""

    def __init__(self, tmp_path: Path, name: str, args: list[str]):
        self.store = tmp_path / f"{name}.db"
        self.log_path = tmp_path / f"{name}.log"
        self.name = name
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        # Use localhost rather than 127.0.0.1 - browsers treat it as a secure context,
        # which Web Crypto and the Secure session cookies need
        self.url = f"http://localhost:{port}"
        self._log = self.log_path.open("w")
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "privipod",
                f"127.0.0.1:{port}",
                "--store",
                str(self.store),
                "--secret-key",
                "e2e-secret-key",
                *args,
            ],
            cwd=REPO_ROOT,
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )
        self._wait_for_health()

    def _wait_for_health(self, timeout: float = 30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                if requests.get(f"{self.url}/health/", timeout=1).ok:
                    return
            except requests.ConnectionError:
                pass
            time.sleep(0.2)
        self.stop()
        raise RuntimeError(
            f"Privipod server {self.name} failed to start:\n{self.log_path.read_text()}"
        )

    def stop(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self._log.close()

    # -- Database access ------------------------------------------------------

    def query(self, sql: str, *params) -> list[tuple]:
        conn = sqlite3.connect(self.store, timeout=10)
        try:
            with conn:
                return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def create_user(self, prefix: str = "user") -> User:
        from django.contrib.auth.hashers import make_password

        user = User(f"{prefix}{next(_user_ids)}")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self.query(
            "INSERT INTO auth_user (password, is_superuser, username, first_name,"
            " last_name, email, is_staff, is_active, date_joined)"
            " VALUES (?, 0, ?, '', '', '', 0, 1, ?)",
            make_password(user.password),
            user.username,
            now,
        )
        return user

    def pod(self, kind: str, hash: str) -> dict:
        """Return a pod's row as a dict - kind is "receive" or "send" """
        conn = sqlite3.connect(self.store, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                f"SELECT * FROM privipod_{kind}pod WHERE hash = ?", (hash,)
            ).fetchone()
            return dict(row)
        finally:
            conn.close()

    def log_events(self, kind: str, hash: str) -> list[tuple[str, str, str | None]]:
        """Return (event, detail, username) for a pod's log, oldest first"""
        return self.query(
            f"SELECT log.event, log.detail, user.username FROM privipod_{kind}log log"
            f" JOIN privipod_{kind}pod pod ON pod.id = log.pod_id"
            " LEFT JOIN auth_user user ON user.id = log.user_id"
            " WHERE pod.hash = ? ORDER BY log.id",
            hash,
        )

    def expire(self, kind: str, hash: str):
        """Move a pod's deadline into the past"""
        self.query(
            f"UPDATE privipod_{kind}pod SET deadline = '2000-01-01 00:00:00'"
            " WHERE hash = ?",
            hash,
        )


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    srv = Server(tmp_path_factory.mktemp("server"), "server", [])
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def keyfile_server(tmp_path_factory):
    srv = Server(tmp_path_factory.mktemp("keyfile"), "keyfile", ["--no-server-keys"])
    yield srv
    srv.stop()


@pytest.fixture
def browser_context_args(browser_context_args, request):
    """
    Pass a timezone to browser contexts with ``@pytest.mark.timezone("Europe/Berlin")``
    """
    # actor() sets base_url for whichever server the actor is using
    args = {k: v for k, v in browser_context_args.items() if k != "base_url"}
    marker = request.node.get_closest_marker("timezone")
    if marker:
        args["timezone_id"] = marker.args[0]
    return args


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "timezone(name): run browser contexts in the given timezone"
    )


class Actor:
    """A person in a test: their own browser context, and optionally a user account"""

    def __init__(self, context: BrowserContext, server: Server, user: User | None):
        self.context = context
        self.server = server
        self.user = user
        self.page = context.new_page()
        self.errors: list[str] = []
        self.page.on("pageerror", lambda err: self.errors.append(str(err)))
        if user:
            login(self.page, user)


@pytest.fixture
def actor(new_context, server):
    """
    Factory for actors, each with their own browser context::

        alice = actor("alice")  # a new user, logged in
        anon = actor()  # an anonymous visitor
        laptop = actor(user=alice.user)  # the same user on a fresh browser
        carol = actor("carol", on=keyfile_server)  # a user on another server
    """
    actors = []

    def make(
        prefix: str | None = None, on: Server | None = None, user: User | None = None
    ) -> Actor:
        srv = on or server
        if prefix:
            user = srv.create_user(prefix)
        a = Actor(new_context(base_url=srv.url), srv, user)
        actors.append(a)
        return a

    yield make

    # Fail tests which raised uncaught errors in the browser
    errors = [err for a in actors for err in a.errors]
    assert not errors, f"Uncaught errors in browser: {errors}"


@pytest.fixture
def alice(actor) -> Actor:
    return actor("alice")


@pytest.fixture
def bob(actor) -> Actor:
    return actor("bob")


@pytest.fixture
def anon(actor) -> Actor:
    return actor()
