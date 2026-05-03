"""
Shared fixtures for Privipod unit tests.

These tests run against Django directly (no live server needed).
The nanodjango app is configured here and Django is set up before
pytest-django's trylast pytest_configure hook finalises it.
"""

import pytest


def pytest_configure(config):
    """Configure Django via nanodjango before pytest-django finalises setup."""
    import privipod.config as _config

    _config.secret_key = "test-secret-key-do-not-use-in-production"
    _config.store = None
    _config.debug = False
    _config.hostnames = []
    _config.max_size_mb = 10

    # nanodjango expects to run from inside privipod/, where 'migrations' is a top-level
    # module. When pytest runs from the repo root, 'migrations' isn't importable. We add
    # privipod/ to sys.path so nanodjango's migration loader finds 'migrations' correctly.
    import sys
    from pathlib import Path

    privipod_pkg_dir = str(Path(__file__).parent.parent / "privipod")
    if privipod_pkg_dir not in sys.path:
        sys.path.insert(0, privipod_pkg_dir)

    import privipod.server  # noqa: F401 - triggers Django setup via nanodjango


@pytest.fixture
def user(db):
    from django.contrib.auth.models import User

    return User.objects.create_user(username="testuser", password="testpass")


@pytest.fixture
def other_user(db):
    from django.contrib.auth.models import User

    return User.objects.create_user(username="otheruser", password="otherpass")


@pytest.fixture
def auth_client(client, user):
    client.force_login(user)
    return client


@pytest.fixture
def make_pod(db, user):
    """Factory fixture: call make_pod(**kwargs) to create a Pod."""
    from privipod.server import Pod

    def _make(owner=None, **kwargs):
        kwargs.setdefault("name", "Test Pod")
        kwargs.setdefault("hash", "testhash-abc-123")
        kwargs.setdefault("public_key", '{"kty":"RSA","n":"test","e":"AQAB"}')
        return Pod.objects.create(owner=owner or user, **kwargs)

    return _make
