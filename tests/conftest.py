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

    # Serve static files by their plain names. The production manifest storage needs
    # collectstatic to have run first, and caches whichever manifest it finds on first
    # use - the e2e servers regenerate it mid-session.
    from django.conf import settings

    settings.STORAGES = {
        **settings.STORAGES,
        "staticfiles": {
            "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
        },
    }
    # Unit tests don't serve static files; stops WhiteNoise warning it isn't collected
    settings.STATIC_ROOT = None


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
    from privipod.server import ReceivePod

    def _make(owner=None, **kwargs):
        kwargs.setdefault("name", "Test Pod")
        kwargs.setdefault("hash", "testhash-abc-123")
        kwargs.setdefault("public_key", '{"kty":"RSA","n":"test","e":"AQAB"}')
        return ReceivePod.objects.create(owner=owner or user, **kwargs)

    return _make


@pytest.fixture
def third_user(db):
    from django.contrib.auth.models import User

    return User.objects.create_user(username="thirduser", password="thirdpass")


@pytest.fixture
def make_send_pod(db, user):
    """Factory fixture: call make_send_pod(**kwargs) to create a SendPod."""
    from privipod.server import SendPod

    VALID_ENCRYPTED = '{"encryptedKey":"abc","encryptedData":"xyz","iv":"iv1"}'

    def _make(owner=None, **kwargs):
        kwargs.setdefault("name", "Test Send Pod")
        kwargs.setdefault("hash", "send-testhash-123")
        kwargs.setdefault("encrypted_secret", VALID_ENCRYPTED.encode())
        kwargs.setdefault("secret_type", "text")
        return SendPod.objects.create(owner=owner or user, **kwargs)

    return _make
