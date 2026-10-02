"""Tests for health endpoint, confirm-read view, and CSP middleware."""

import json
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from privipod.server import ReceivePod, ReceiveLog

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
            status=ReceivePod.Status.RECEIVED,
            self_destruct=True,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        resp = client.post(reverse("pod_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_owner_self_destruct_sent_destroys_pod(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-delete",
            status=ReceivePod.Status.RECEIVED,
            self_destruct=True,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        resp = auth_client.post(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert resp.status_code == 200
        assert json.loads(resp.content) == {"status": "ok"}
        pod.refresh_from_db()
        assert pod.status == ReceivePod.Status.DESTROYED
        assert pod.encrypted_secret is None

    def test_non_self_destruct_sent_pod_returns_ok(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-no-sd",
            status=ReceivePod.Status.RECEIVED,
            self_destruct=False,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        resp = auth_client.post(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert resp.status_code == 200
        assert json.loads(resp.content) == {"status": "ok"}
        assert ReceivePod.objects.filter(hash="confirm-no-sd").exists()

    def test_non_self_destruct_creates_decrypted_log(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-no-sd-log",
            status=ReceivePod.Status.RECEIVED,
            self_destruct=False,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        auth_client.post(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert ReceiveLog.objects.filter(
            pod=pod, event=ReceiveLog.Event.DECRYPTED
        ).exists()
        assert not ReceiveLog.objects.filter(
            pod=pod, event=ReceiveLog.Event.ACCESSED
        ).exists()

    def test_every_decrypt_is_logged(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-repeat",
            status=ReceivePod.Status.RECEIVED,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        url = reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        auth_client.post(url)
        auth_client.post(url)
        assert pod.logs.filter(event=ReceiveLog.Event.DECRYPTED).count() == 2

    def test_expired_pod_is_destroyed_not_logged_decrypted(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-expired",
            status=ReceivePod.Status.RECEIVED,
            encrypted_secret=VALID_ENCRYPTED.encode(),
            deadline=timezone.now() - timedelta(hours=1),
        )
        resp = auth_client.post(reverse("pod_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 404
        pod.refresh_from_db()
        assert pod.status == ReceivePod.Status.DESTROYED
        assert not pod.logs.filter(event=ReceiveLog.Event.DECRYPTED).exists()

    def test_pending_self_destruct_pod_returns_404(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-pending",
            status=ReceivePod.Status.PENDING,
            self_destruct=True,
        )
        resp = auth_client.post(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert resp.status_code == 404

    def test_non_owner_returns_404(self, client, other_user, make_pod):
        pod = make_pod(
            hash="confirm-non-owner",
            status=ReceivePod.Status.RECEIVED,
            self_destruct=True,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        client.force_login(other_user)
        resp = client.post(
            reverse("pod_confirm_read", kwargs={"hash": pod.hash})
        )
        assert resp.status_code == 404
        assert ReceivePod.objects.filter(hash="confirm-non-owner").exists()

    def test_get_not_allowed(self, auth_client, make_pod):
        pod = make_pod(
            hash="confirm-get",
            status=ReceivePod.Status.RECEIVED,
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
