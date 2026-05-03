"""Tests for health endpoint, confirm-read view, and CSP middleware."""

import json

import pytest
from django.urls import reverse

from privipod.server import Pod

VALID_ENCRYPTED = json.dumps(
    {"encryptedKey": "abc123", "encryptedData": "xyz456", "iv": "ivval"}
)


@pytest.mark.django_db
class TestHealthView:
    def test_returns_200(self, client):
        resp = client.get(reverse("health"))
        assert resp.status_code == 200

    def test_returns_ok_json(self, client):
        resp = client.get(reverse("health"))
        assert json.loads(resp.content) == {"status": "ok"}

    def test_accessible_without_auth(self, client):
        resp = client.get(reverse("health"))
        assert resp.status_code == 200


@pytest.mark.django_db
class TestPodConfirmReadView:
    def test_anonymous_redirects_to_login(self, client, make_pod):
        pod = make_pod(
            hash="confirm-anon",
            status=Pod.Status.SENT,
            self_destruct=True,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        resp = client.post(reverse("pod_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_owner_self_destruct_sent_deletes_pod(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-delete",
            status=Pod.Status.SENT,
            self_destruct=True,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        resp = auth_client.post(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert resp.status_code == 200
        assert json.loads(resp.content) == {"status": "ok"}
        assert not Pod.objects.filter(hash="confirm-delete").exists()

    def test_non_self_destruct_pod_returns_404(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-no-sd",
            status=Pod.Status.SENT,
            self_destruct=False,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        resp = auth_client.post(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert resp.status_code == 404
        assert Pod.objects.filter(hash="confirm-no-sd").exists()

    def test_pending_self_destruct_pod_returns_404(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-pending",
            status=Pod.Status.PENDING,
            self_destruct=True,
        )
        resp = auth_client.post(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert resp.status_code == 404

    def test_non_owner_returns_404(self, client, other_user, make_pod):
        pod = make_pod(
            hash="confirm-non-owner",
            status=Pod.Status.SENT,
            self_destruct=True,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        client.force_login(other_user)
        resp = client.post(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert resp.status_code == 404
        assert Pod.objects.filter(hash="confirm-non-owner").exists()

    def test_get_not_allowed(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-get",
            status=Pod.Status.SENT,
            self_destruct=True,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        resp = auth_client.get(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert resp.status_code == 405


@pytest.mark.django_db
class TestCSPMiddleware:
    def test_csp_header_present_on_health(self, client):
        resp = client.get(reverse("health"))
        assert "Content-Security-Policy" in resp

    def test_csp_header_includes_default_src_self(self, client):
        resp = client.get(reverse("health"))
        csp = resp["Content-Security-Policy"]
        assert "default-src 'self'" in csp

    def test_csp_header_on_login_page(self, client):
        resp = client.get(reverse("login"))
        assert "Content-Security-Policy" in resp
