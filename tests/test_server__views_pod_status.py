"""Tests for the pod status JSON polling endpoint."""

import json

import pytest
from django.urls import reverse

from privipod.server import Pod

VALID_ENCRYPTED = json.dumps(
    {"encryptedKey": "abc123", "encryptedData": "xyz456", "iv": "ivval"}
)
VALID_ENCRYPTED_FN = json.dumps({"encryptedKey": "k", "encryptedData": "fn", "iv": "i"})


@pytest.mark.django_db
class TestPodStatusView:
    def test_anonymous_returns_403(self, client, make_pod):
        pod = make_pod()
        resp = client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        assert resp.status_code == 403
        assert json.loads(resp.content)["status"] == "auth_required"

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

    def test_sent_pod_returns_secret(self, auth_client, make_pod):
        pod = make_pod(
            hash="status-sent",
            status=Pod.Status.SENT,
            encrypted_secret=VALID_ENCRYPTED.encode(),
            secret_type=Pod.SecretType.TEXT,
        )
        resp = auth_client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data["status"] == "sent"
        assert "encrypted_secret" in data
        assert data["secret_type"] == "text"

    def test_sent_pod_with_filename_includes_filename(self, auth_client, make_pod):
        pod = make_pod(
            hash="status-sent-file",
            status=Pod.Status.SENT,
            encrypted_secret=VALID_ENCRYPTED.encode(),
            encrypted_filename=VALID_ENCRYPTED_FN.encode(),
            secret_type=Pod.SecretType.FILE,
        )
        resp = auth_client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        data = json.loads(resp.content)
        assert "encrypted_filename" in data

    def test_self_destruct_sent_pod_returns_pending(self, auth_client, make_pod):
        pod = make_pod(
            hash="status-self-destruct",
            status=Pod.Status.SENT,
            encrypted_secret=VALID_ENCRYPTED.encode(),
            self_destruct=True,
        )
        resp = auth_client.get(reverse("pod_status", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        assert json.loads(resp.content)["status"] == "pending"

    def test_nonexistent_pod_returns_404(self, auth_client):
        resp = auth_client.get(
            reverse("pod_status", kwargs={"hash": "no-such-hash"})
        )
        assert resp.status_code == 404
