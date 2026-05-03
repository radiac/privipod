"""Tests for the main pod view (view, send, receive)."""

import json
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from privipod.server import Pod

VALID_ENCRYPTED = json.dumps(
    {"encryptedKey": "abc123", "encryptedData": "xyz456", "iv": "ivval"}
)
VALID_ENCRYPTED_FN = json.dumps({"encryptedKey": "k", "encryptedData": "fn", "iv": "i"})


@pytest.mark.django_db
class TestPodViewGet:
    def test_nonexistent_pod_anonymous_redirects_to_login(self, client):
        resp = client.get(reverse("pod_view", kwargs={"hash": "no-such-hash"}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_nonexistent_pod_authenticated_shows_not_found(self, auth_client):
        resp = auth_client.get(reverse("pod_view", kwargs={"hash": "no-such-hash"}))
        assert resp.status_code == 200
        assert "not" in resp.templates[0].name.lower() or "not_found" in resp.templates[0].name

    def test_expired_pod_shows_expired_state(self, auth_client, make_pod):
        pod = make_pod(deadline=timezone.now() - timedelta(hours=1))
        resp = auth_client.get(reverse("pod_view", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        assert resp.context["is_owner"] is False

    def test_require_sender_auth_anonymous_redirects_to_login(self, client, make_pod):
        pod = make_pod(require_sender_auth=True, hash="auth-required")
        resp = client.get(reverse("pod_view", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_owner_sees_send_form_with_query_param(self, auth_client, make_pod):
        pod = make_pod()
        resp = auth_client.get(
            reverse("pod_view", kwargs={"hash": pod.hash}) + "?send"
        )
        assert resp.status_code == 200
        assert resp.context.get("show_send_form") is True

    def test_non_owner_sees_send_form_on_pending_pod(self, client, other_user, make_pod):
        pod = make_pod(hash="non-owner-pod")
        client.force_login(other_user)
        resp = client.get(reverse("pod_view", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        assert "send_form" in resp.context

    def test_owner_sees_encrypted_secret_when_sent(self, auth_client, make_pod):
        pod = make_pod(
            status=Pod.Status.SENT,
            encrypted_secret=VALID_ENCRYPTED.encode(),
            secret_type=Pod.SecretType.TEXT,
            hash="owner-sent-pod",
        )
        resp = auth_client.get(reverse("pod_view", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        assert "encrypted_secret_json" in resp.context


@pytest.mark.django_db
class TestPodViewPost:
    def test_valid_post_marks_pod_sent(self, client, other_user, make_pod):
        pod = make_pod(hash="post-test-pod")
        client.force_login(other_user)
        resp = client.post(
            reverse("pod_view", kwargs={"hash": pod.hash}),
            {
                "encrypted_data": VALID_ENCRYPTED,
                "secret_type": "text",
            },
        )
        assert resp.status_code == 302
        pod.refresh_from_db()
        assert pod.status == Pod.Status.SENT
        assert pod.encrypted_secret is not None

    def test_valid_post_stores_filename(self, client, other_user, make_pod):
        pod = make_pod(hash="post-fn-pod")
        client.force_login(other_user)
        client.post(
            reverse("pod_view", kwargs={"hash": pod.hash}),
            {
                "encrypted_data": VALID_ENCRYPTED,
                "secret_type": "file",
                "encrypted_filename": VALID_ENCRYPTED_FN,
            },
        )
        pod.refresh_from_db()
        assert pod.encrypted_filename is not None

    def test_invalid_json_encrypted_data_redirects_with_error(
        self, client, other_user, make_pod
    ):
        pod = make_pod(hash="invalid-json-pod")
        client.force_login(other_user)
        resp = client.post(
            reverse("pod_view", kwargs={"hash": pod.hash}),
            {
                "encrypted_data": "not-valid-json",
                "secret_type": "text",
            },
        )
        assert resp.status_code == 302
        pod.refresh_from_db()
        assert pod.status == Pod.Status.PENDING

    def test_invalid_json_encrypted_filename_redirects_with_error(
        self, client, other_user, make_pod
    ):
        pod = make_pod(hash="invalid-fn-pod")
        client.force_login(other_user)
        resp = client.post(
            reverse("pod_view", kwargs={"hash": pod.hash}),
            {
                "encrypted_data": VALID_ENCRYPTED,
                "secret_type": "file",
                "encrypted_filename": "not-json",
            },
        )
        assert resp.status_code == 302
        pod.refresh_from_db()
        assert pod.status == Pod.Status.PENDING

    def test_oversized_data_redirects_with_error(self, client, other_user, make_pod):
        from privipod.server import MAX_SIZE_BYTES

        pod = make_pod(hash="oversized-pod")
        client.force_login(other_user)
        big_data = "x" * (MAX_SIZE_BYTES + 1)
        resp = client.post(
            reverse("pod_view", kwargs={"hash": pod.hash}),
            {"encrypted_data": big_data, "secret_type": "text"},
        )
        assert resp.status_code == 302
        pod.refresh_from_db()
        assert pod.status == Pod.Status.PENDING

    def test_atomic_update_returns_zero_for_already_sent_pod(self, make_pod):
        """The atomic PENDING filter returns 0 rows when pod is already SENT.

        This is the mechanism that prevents double-sends in concurrent requests:
        both senders may pass can_send(), but only the first update() call wins.
        """
        pod = make_pod(
            hash="already-sent-pod",
            status=Pod.Status.SENT,
            encrypted_secret=VALID_ENCRYPTED.encode(),
        )
        updated = Pod.objects.filter(
            hash=pod.hash, status=Pod.Status.PENDING
        ).update(status=Pod.Status.SENT)
        assert updated == 0

    def test_owner_cannot_send_without_query_param(self, auth_client, make_pod):
        pod = make_pod(hash="owner-no-send")
        resp = auth_client.post(
            reverse("pod_view", kwargs={"hash": pod.hash}),
            {"encrypted_data": VALID_ENCRYPTED, "secret_type": "text"},
        )
        pod.refresh_from_db()
        assert pod.status == Pod.Status.PENDING

    def test_post_to_expired_pod_does_not_update(self, client, other_user, make_pod):
        pod = make_pod(
            hash="expired-post-pod",
            deadline=timezone.now() - timedelta(hours=1),
        )
        client.force_login(other_user)
        client.post(
            reverse("pod_view", kwargs={"hash": pod.hash}),
            {"encrypted_data": VALID_ENCRYPTED, "secret_type": "text"},
        )
        pod.refresh_from_db()
        assert pod.status == Pod.Status.PENDING
