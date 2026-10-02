"""Tests for the pod status JSON polling endpoint."""

import json
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from privipod.server import ReceivePod

VALID_ENCRYPTED = json.dumps(
    {"encryptedKey": "abc123", "encryptedData": "xyz456", "iv": "ivval"}
)


@pytest.mark.django_db
class TestPodStatusView:
    def test_anonymous_redirects_to_login(self, client, make_pod):
        pod = make_pod()
        resp = client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_non_owner_returns_404(self, client, other_user, make_pod):
        pod = make_pod(hash="status-not-mine")
        client.force_login(other_user)
        resp = client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        assert resp.status_code == 404

    def test_pending_pod_returns_pending(self, auth_client, make_pod):
        pod = make_pod(hash="status-pending")
        resp = auth_client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        assert json.loads(resp.content)["status"] == "pending"

    def test_received_pod_returns_received_without_secret(self, auth_client, make_pod):
        pod = make_pod(
            hash="status-received",
            status=ReceivePod.Status.RECEIVED,
            encrypted_secret=VALID_ENCRYPTED.encode(),
            secret_type=ReceivePod.SecretType.TEXT,
        )
        resp = auth_client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        assert json.loads(resp.content) == {"status": "received"}

    def test_self_destruct_received_pod_returns_received(self, auth_client, make_pod):
        pod = make_pod(
            hash="status-self-destruct",
            status=ReceivePod.Status.RECEIVED,
            encrypted_secret=VALID_ENCRYPTED.encode(),
            self_destruct=True,
        )
        resp = auth_client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        assert json.loads(resp.content) == {"status": "received"}

    def test_expired_pod_is_destroyed(self, auth_client, make_pod):
        pod = make_pod(
            hash="status-expired",
            status=ReceivePod.Status.RECEIVED,
            encrypted_secret=VALID_ENCRYPTED.encode(),
            deadline=timezone.now() - timedelta(hours=1),
        )
        resp = auth_client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        assert json.loads(resp.content) == {"status": "destroyed"}
        pod.refresh_from_db()
        assert pod.encrypted_secret is None

    def test_nonexistent_pod_returns_404(self, auth_client):
        resp = auth_client.get(
            reverse("pod_status", kwargs={"hash": "no-such-hash"})
        )
        assert resp.status_code == 404
