"""Tests for send pod views: send_view, send_verify, send_confirm_read, send_delete."""

import json
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from privipod.server import SendLog, SendPod

VALID_ENCRYPTED = json.dumps(
    {"encryptedKey": "abc123", "encryptedData": "xyz456", "iv": "ivval"}
)

# 32-byte token used for verify/confirm-read tests that need a known value
KNOWN_TOKEN = b"\xab\xcd\xef" * 10 + b"\x12\x34"
KNOWN_TOKEN_HEX = KNOWN_TOKEN.hex()

# A different 32-byte token used for wrong-token tests
WRONG_TOKEN_HEX = "ff" * 32


@pytest.mark.django_db
class TestSendView:
    def test_anonymous_anon_pod_returns_200(self, client, make_send_pod):
        pod = make_send_pod()
        resp = client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200

    def test_anonymous_anon_pod_has_encrypted_secret_in_context(
        self, client, make_send_pod
    ):
        pod = make_send_pod()
        resp = client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert "encrypted_secret_json" in resp.context

    def test_anonymous_auth_recipient_pod_redirects_to_login(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="send-auth-pod", recipient=other_user)
        resp = client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_wrong_user_auth_recipient_pod_shows_not_found(
        self, client, other_user, third_user, make_send_pod
    ):
        pod = make_send_pod(hash="send-wrong-user", recipient=other_user)
        client.force_login(third_user)
        resp = client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        assert (
            "not_found" in resp.templates[0].name
            or "not" in resp.templates[0].name.lower()
        )

    def test_correct_recipient_has_encrypted_secret_in_context(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="send-correct-recip", recipient=other_user)
        client.force_login(other_user)
        resp = client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert "encrypted_secret_json" in resp.context

    def test_owner_does_not_get_encrypted_secret_in_context(
        self, auth_client, make_send_pod
    ):
        pod = make_send_pod()
        resp = auth_client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert "encrypted_secret_json" not in resp.context

    def test_anon_keyfile_pod_has_read_challenge_in_context(self, client, make_send_pod):
        pod = make_send_pod(
            hash="send-keyfile-challenge",
            read_challenge=b'{"ciphertext":"abc"}',
            verification_token=bytes(range(32)),
        )
        resp = client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert resp.context["read_challenge_json"] == {"ciphertext": "abc"}

    def test_anon_access_code_pod_has_no_read_challenge_in_context(
        self, client, make_send_pod
    ):
        pod = make_send_pod(
            hash="send-access-code-pod",
            encrypted_private_key=b'{"wrapped":"a","iv":"b"}',
            verification_token=bytes(range(32)),
        )
        resp = client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert "read_challenge_json" not in resp.context

    def test_nonexistent_pod_anonymous_redirects_to_login(self, client):
        resp = client.get(reverse("send_view", kwargs={"hash": "no-such-hash"}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_nonexistent_pod_authenticated_shows_not_found(self, auth_client):
        resp = auth_client.get(reverse("send_view", kwargs={"hash": "no-such-hash"}))
        assert resp.status_code == 200
        assert (
            "not_found" in resp.templates[0].name
            or "not" in resp.templates[0].name.lower()
        )

    @pytest.mark.parametrize(
        "status",
        [SendPod.Status.PENDING, SendPod.Status.READ, SendPod.Status.LOCKED],
    )
    def test_expired_pod_is_destroyed_on_view(self, auth_client, make_send_pod, status):
        pod = make_send_pod(status=status, deadline=timezone.now() - timedelta(hours=1))
        resp = auth_client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        assert "encrypted_secret_json" not in resp.context
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED
        assert pod.encrypted_secret is None
        assert pod.logs.filter(event=SendLog.Event.DESTROYED, detail="expired").exists()


@pytest.mark.django_db
class TestSendViewOwnerButtons:
    @pytest.mark.parametrize(
        "status",
        [
            SendPod.Status.PENDING,
            SendPod.Status.READ,
            SendPod.Status.LOCKED,
            SendPod.Status.DESTROYED,
        ],
    )
    def test_one_delete_button(self, auth_client, make_send_pod, status):
        pod = make_send_pod(status=status)
        resp = auth_client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert resp.content.decode().count("Delete Pod") == 1

    def test_pending_anon_pod_has_copy_url(self, auth_client, make_send_pod):
        pod = make_send_pod()
        resp = auth_client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert b"Copy URL" in resp.content
        assert b"Unlock Pod" not in resp.content

    @pytest.mark.parametrize(
        "status, css, text",
        [
            (SendPod.Status.PENDING, "info", "Waiting to be decrypted"),
            (SendPod.Status.READ, "success", "The recipient has decrypted the secret"),
            (SendPod.Status.LOCKED, "error", "the pod is locked"),
            (SendPod.Status.DESTROYED, "warning", "has been destroyed"),
        ],
    )
    def test_status_message(self, auth_client, make_send_pod, status, css, text):
        pod = make_send_pod(status=status, recipient=None)
        resp = auth_client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        html = resp.content.decode()
        assert f'class="message {css}"' in html
        assert text in html
        assert "pod-status" not in html

    def test_locked_pod_has_unlock(self, auth_client, make_send_pod):
        pod = make_send_pod(status=SendPod.Status.LOCKED)
        resp = auth_client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert b"Unlock Pod" in resp.content
        assert b"Copy URL" not in resp.content


@pytest.mark.django_db
class TestSendViewAccessLog:
    def test_auth_recipient_page_load_logs_accessed(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="al-recipient", recipient=other_user)
        client.force_login(other_user)
        client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        log = pod.logs.get()
        assert log.event == SendLog.Event.ACCESSED
        assert log.user == other_user

    def test_keyfile_anon_page_load_logs_accessed(self, client, make_send_pod):
        pod = make_send_pod(hash="al-keyfile", read_challenge=b'{"ciphertext":"abc"}')
        resp = client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert "encrypted_secret_json" in resp.context
        assert "read_challenge_json" in resp.context
        log = pod.logs.get()
        assert log.event == SendLog.Event.ACCESSED
        assert log.user is None

    def test_access_code_anon_page_does_not_embed_secret(self, client, make_send_pod):
        pod = make_send_pod(
            hash="al-access-code",
            encrypted_private_key=b'{"wrapped":"key","iv":"salt"}',
            verification_token=KNOWN_TOKEN,
        )
        resp = client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert "encrypted_secret_json" not in resp.context
        assert not pod.logs.exists()

    def test_owner_page_load_does_not_log(self, auth_client, make_send_pod):
        pod = make_send_pod(hash="al-owner")
        auth_client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert not pod.logs.exists()

    def test_inaccessible_pod_does_not_log(self, client, make_send_pod):
        pod = make_send_pod(hash="al-locked", status=SendPod.Status.LOCKED)
        client.get(reverse("send_view", kwargs={"hash": pod.hash}))
        assert not pod.logs.exists()


@pytest.mark.django_db
class TestSendStatusView:
    def test_anonymous_redirects_to_login(self, client, make_send_pod):
        pod = make_send_pod()
        resp = client.get(reverse("send_status", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302

    def test_owner_gets_status(self, auth_client, make_send_pod):
        pod = make_send_pod(status=SendPod.Status.READ)
        resp = auth_client.get(reverse("send_status", kwargs={"hash": pod.hash}))
        assert json.loads(resp.content) == {"status": "read"}

    def test_expired_pod_is_destroyed(self, auth_client, make_send_pod):
        pod = make_send_pod(deadline=timezone.now() - timedelta(hours=1))
        resp = auth_client.get(reverse("send_status", kwargs={"hash": pod.hash}))
        assert json.loads(resp.content) == {"status": "destroyed"}
        pod.refresh_from_db()
        assert pod.encrypted_secret is None


@pytest.mark.django_db
class TestSendVerifyView:
    def test_no_pod_returns_404(self, client):
        resp = client.post(
            reverse("send_verify", kwargs={"hash": "no-such-hash"}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        assert resp.status_code == 404

    def test_locked_pod_returns_403(self, client, make_send_pod):
        pod = make_send_pod(
            status=SendPod.Status.LOCKED,
            verification_token=KNOWN_TOKEN,
        )
        resp = client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        assert resp.status_code == 403

    def test_auth_recipient_pod_returns_400(self, client, other_user, make_send_pod):
        pod = make_send_pod(
            recipient=other_user,
            verification_token=KNOWN_TOKEN,
        )
        resp = client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        assert resp.status_code == 400

    def test_no_verification_token_on_pod_returns_400(self, client, make_send_pod):
        pod = make_send_pod()
        resp = client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        assert resp.status_code == 400

    def test_wrong_token_returns_403(self, client, make_send_pod):
        pod = make_send_pod(verification_token=KNOWN_TOKEN)
        resp = client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": WRONG_TOKEN_HEX},
        )
        assert resp.status_code == 403

    def test_wrong_token_increments_attempt_count(self, client, make_send_pod):
        pod = make_send_pod(verification_token=KNOWN_TOKEN)
        client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": WRONG_TOKEN_HEX},
        )
        pod.refresh_from_db()
        assert pod.attempt_count == 1

    def test_wrong_token_only_refetches_attempt_count(
        self, client, make_send_pod, monkeypatch
    ):
        # A failed guess should re-read just the counter, not the encrypted payloads -
        # pins the fields= scope so a future edit can't silently widen it back out
        from privipod.server import SendPod as SendPodModel

        pod = make_send_pod(verification_token=KNOWN_TOKEN)
        calls = []
        original = SendPodModel.refresh_from_db

        def spy(self, *args, **kwargs):
            calls.append(kwargs.get("fields"))
            return original(self, *args, **kwargs)

        monkeypatch.setattr(SendPodModel, "refresh_from_db", spy)
        client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": WRONG_TOKEN_HEX},
        )
        assert calls == [["attempt_count"]]

    def test_max_attempts_locks_pod(self, client, make_send_pod):
        pod = make_send_pod(verification_token=KNOWN_TOKEN)
        url = reverse("send_verify", kwargs={"hash": pod.hash})
        for _ in range(SendPod.MAX_ATTEMPTS):
            resp = client.post(url, {"verification_token": WRONG_TOKEN_HEX})
        assert resp.status_code == 403
        data = json.loads(resp.content)
        assert "locked" in data["error"]
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.LOCKED

    def test_correct_token_returns_200(self, client, make_send_pod):
        pod = make_send_pod(
            hash="verify-correct",
            verification_token=KNOWN_TOKEN,
            encrypted_private_key=b'{"wrapped":"test","iv":"test"}',
        )
        resp = client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        assert resp.status_code == 200

    def test_correct_token_response_contains_encrypted_secret(
        self, client, make_send_pod
    ):
        pod = make_send_pod(
            hash="verify-payload",
            verification_token=KNOWN_TOKEN,
            encrypted_private_key=b'{"wrapped":"test","iv":"test"}',
        )
        resp = client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        data = json.loads(resp.content)
        assert "encrypted_secret" in data

    def test_correct_token_response_contains_encrypted_private_key(
        self, client, make_send_pod
    ):
        pod = make_send_pod(
            hash="verify-privkey",
            verification_token=KNOWN_TOKEN,
            encrypted_private_key=b'{"wrapped":"test","iv":"test"}',
        )
        resp = client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        data = json.loads(resp.content)
        assert data["encrypted_private_key"] is not None

    def test_correct_token_resets_attempt_count(self, client, make_send_pod):
        pod = make_send_pod(
            hash="verify-reset",
            verification_token=KNOWN_TOKEN,
            attempt_count=2,
        )
        client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        pod.refresh_from_db()
        assert pod.attempt_count == 0

    def test_correct_token_creates_accessed_log(self, client, make_send_pod):
        pod = make_send_pod(
            hash="verify-log",
            verification_token=KNOWN_TOKEN,
        )
        client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        assert SendLog.objects.filter(pod=pod, event=SendLog.Event.ACCESSED).exists()

    def test_expired_pod_is_destroyed_and_refused(self, client, make_send_pod):
        pod = make_send_pod(
            hash="verify-expired",
            encrypted_private_key=b'{"wrapped":"key","iv":"salt"}',
            verification_token=KNOWN_TOKEN,
            deadline=timezone.now() - timedelta(hours=1),
        )
        resp = client.post(
            reverse("send_verify", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX},
        )
        assert resp.status_code == 403
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED
        assert not pod.logs.filter(event=SendLog.Event.ACCESSED).exists()

    def test_get_not_allowed(self, client, make_send_pod):
        pod = make_send_pod()
        resp = client.get(reverse("send_verify", kwargs={"hash": pod.hash}))
        assert resp.status_code == 405


@pytest.mark.django_db
class TestSendConfirmReadView:
    # --- Authenticated-recipient pod tests ---

    def test_auth_recipient_pod_unauthenticated_returns_403(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="cr-anon-auth", recipient=other_user)
        resp = client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 403

    def test_auth_recipient_pod_wrong_user_returns_403(
        self, client, other_user, third_user, make_send_pod
    ):
        pod = make_send_pod(hash="cr-wrong-user", recipient=other_user)
        client.force_login(third_user)
        resp = client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 403

    def test_auth_recipient_pod_correct_recipient_returns_200(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="cr-correct", recipient=other_user)
        client.force_login(other_user)
        resp = client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200

    def test_auth_recipient_pod_correct_recipient_sets_status_read(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="cr-status", recipient=other_user)
        client.force_login(other_user)
        client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.READ

    def test_auth_recipient_pod_correct_recipient_creates_decrypted_log(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="cr-log", recipient=other_user)
        client.force_login(other_user)
        client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert SendLog.objects.filter(pod=pod, event=SendLog.Event.DECRYPTED).exists()
        assert not SendLog.objects.filter(
            pod=pod, event=SendLog.Event.ACCESSED
        ).exists()

    def test_auth_recipient_pod_correct_recipient_log_has_recipient_user(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="cr-log-user", recipient=other_user)
        client.force_login(other_user)
        client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        log = SendLog.objects.get(pod=pod, event=SendLog.Event.DECRYPTED)
        assert log.user == other_user

    def test_auth_recipient_self_destruct_destroys_pod(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="cr-sd", recipient=other_user, self_destruct=True)
        client.force_login(other_user)
        resp = client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED

    def test_auth_recipient_self_destruct_creates_destroyed_log(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(hash="cr-sd-log", recipient=other_user, self_destruct=True)
        client.force_login(other_user)
        client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert SendLog.objects.filter(pod=pod, event=SendLog.Event.DESTROYED).exists()

    def test_auth_recipient_pod_already_read_returns_200(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(
            hash="cr-idempotent",
            recipient=other_user,
            status=SendPod.Status.READ,
        )
        client.force_login(other_user)
        resp = client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200

    def test_auth_recipient_pod_already_read_logs_decrypted_again(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(
            hash="cr-idempotent-log",
            recipient=other_user,
            status=SendPod.Status.READ,
        )
        client.force_login(other_user)
        client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert list(pod.logs.values_list("event", flat=True)) == [
            SendLog.Event.DECRYPTED
        ]
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.READ

    def test_expired_pod_returns_404_and_is_destroyed(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod(
            hash="cr-expired",
            recipient=other_user,
            deadline=timezone.now() - timedelta(hours=1),
        )
        client.force_login(other_user)
        resp = client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 404
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED
        assert not pod.logs.filter(event=SendLog.Event.DECRYPTED).exists()

    # --- Anonymous pod with verification_token tests ---

    def test_anon_pod_with_token_empty_submission_returns_403(
        self, client, make_send_pod
    ):
        # bytes.fromhex("") succeeds returning b"", so HMAC comparison fails → 403
        pod = make_send_pod(hash="cr-anon-no-tok", verification_token=bytes(range(32)))
        resp = client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 403

    def test_anon_pod_with_token_wrong_token_returns_403(self, client, make_send_pod):
        pod = make_send_pod(hash="cr-anon-wrong", verification_token=bytes(range(32)))
        resp = client.post(
            reverse("send_confirm_read", kwargs={"hash": pod.hash}),
            {"verification_token": WRONG_TOKEN_HEX},
        )
        assert resp.status_code == 403

    def test_anon_pod_with_token_correct_token_returns_200(self, client, make_send_pod):
        token = bytes(range(32))
        pod = make_send_pod(hash="cr-anon-ok", verification_token=token)
        resp = client.post(
            reverse("send_confirm_read", kwargs={"hash": pod.hash}),
            {"verification_token": token.hex()},
        )
        assert resp.status_code == 200

    def test_anon_pod_with_token_correct_token_sets_status_read(
        self, client, make_send_pod
    ):
        token = bytes(range(32))
        pod = make_send_pod(hash="cr-anon-status", verification_token=token)
        client.post(
            reverse("send_confirm_read", kwargs={"hash": pod.hash}),
            {"verification_token": token.hex()},
        )
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.READ

    def test_anon_pod_self_destruct_correct_token_destroys_pod(
        self, client, make_send_pod
    ):
        token = bytes(range(32))
        pod = make_send_pod(
            hash="cr-anon-sd",
            verification_token=token,
            self_destruct=True,
        )
        resp = client.post(
            reverse("send_confirm_read", kwargs={"hash": pod.hash}),
            {"verification_token": token.hex()},
        )
        assert resp.status_code == 200
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED

    # --- Anonymous pod with NO verification_token at all (neither access-code nor
    # keyfile challenge flow set one) - reachable only via a direct POST to
    # /create/send/, since the real UI always sets a token for anonymous pods ---

    def test_anon_pod_with_no_token_is_forbidden(self, client, make_send_pod):
        pod = make_send_pod(hash="cr-no-proof")
        resp = client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 403

    def test_anon_pod_with_no_token_does_not_change_status(self, client, make_send_pod):
        pod = make_send_pod(hash="cr-no-proof-status")
        client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.PENDING

    def test_anon_pod_with_no_token_does_not_log(self, client, make_send_pod):
        pod = make_send_pod(hash="cr-no-proof-log")
        client.post(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert not pod.logs.exists()

    # --- Keyfile flow: no encrypted_private_key, but still has a verification_token
    # derived from the read-challenge nonce (see SendPod.read_challenge) ---

    def test_keyfile_pod_with_token_sets_status_read(self, client, make_send_pod):
        token = bytes(range(32))
        pod = make_send_pod(hash="cr-keyfile-status", verification_token=token)
        client.post(
            reverse("send_confirm_read", kwargs={"hash": pod.hash}),
            {"verification_token": token.hex()},
        )
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.READ

    # --- Method check ---

    def test_get_not_allowed(self, client, make_send_pod):
        pod = make_send_pod()
        resp = client.get(reverse("send_confirm_read", kwargs={"hash": pod.hash}))
        assert resp.status_code == 405


@pytest.mark.django_db
class TestSendStoreKeyView:
    WRAPPED_KEY = json.dumps({"wrapped": "abc", "iv": "def"})

    def test_anonymous_post_redirects_to_login(self, client, make_send_pod):
        pod = make_send_pod()
        resp = client.post(reverse("send_store_key", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_owner_post_stores_key_and_token(self, auth_client, make_send_pod):
        pod = make_send_pod()
        resp = auth_client.post(
            reverse("send_store_key", kwargs={"hash": pod.hash}),
            {
                "verification_token": KNOWN_TOKEN_HEX,
                "encrypted_private_key": self.WRAPPED_KEY,
            },
        )
        assert resp.status_code == 200
        pod.refresh_from_db()
        assert pod.encrypted_private_key == self.WRAPPED_KEY.encode()
        assert pod.verification_token == KNOWN_TOKEN

    def test_owner_post_clears_stale_read_challenge(self, auth_client, make_send_pod):
        pod = make_send_pod(
            read_challenge=b'{"ciphertext":"abc"}',
            verification_token=bytes(range(32)),
        )
        auth_client.post(
            reverse("send_store_key", kwargs={"hash": pod.hash}),
            {
                "verification_token": KNOWN_TOKEN_HEX,
                "encrypted_private_key": self.WRAPPED_KEY,
            },
        )
        pod.refresh_from_db()
        assert pod.read_challenge is None

    def test_non_owner_post_returns_404(self, client, other_user, make_send_pod):
        pod = make_send_pod()
        client.force_login(other_user)
        resp = client.post(
            reverse("send_store_key", kwargs={"hash": pod.hash}),
            {"verification_token": KNOWN_TOKEN_HEX, "encrypted_private_key": self.WRAPPED_KEY},
        )
        assert resp.status_code == 404

    def test_missing_fields_returns_400(self, auth_client, make_send_pod):
        pod = make_send_pod()
        resp = auth_client.post(reverse("send_store_key", kwargs={"hash": pod.hash}))
        assert resp.status_code == 400


@pytest.mark.django_db
class TestSendStoreKeyViewDestroyed:
    WRAPPED_KEY = json.dumps({"wrapped": "abc", "iv": "def"})

    def test_destroyed_pod_is_refused(self, auth_client, make_send_pod):
        pod = make_send_pod(status=SendPod.Status.DESTROYED, encrypted_secret=None)
        resp = auth_client.post(
            reverse("send_store_key", kwargs={"hash": pod.hash}),
            {
                "verification_token": KNOWN_TOKEN_HEX,
                "encrypted_private_key": self.WRAPPED_KEY,
            },
        )
        assert resp.status_code == 409
        pod.refresh_from_db()
        assert pod.encrypted_private_key is None
        assert pod.verification_token is None

    def test_expired_pod_is_destroyed_and_refused(self, auth_client, make_send_pod):
        pod = make_send_pod(deadline=timezone.now() - timedelta(hours=1))
        resp = auth_client.post(
            reverse("send_store_key", kwargs={"hash": pod.hash}),
            {
                "verification_token": KNOWN_TOKEN_HEX,
                "encrypted_private_key": self.WRAPPED_KEY,
            },
        )
        assert resp.status_code == 409
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED
        assert pod.encrypted_private_key is None


@pytest.mark.django_db
class TestSendUnlockView:
    def test_anonymous_post_redirects_to_login(self, client, make_send_pod):
        pod = make_send_pod(status=SendPod.Status.LOCKED)
        resp = client.post(reverse("send_unlock", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_owner_post_sets_status_pending(self, auth_client, make_send_pod):
        pod = make_send_pod(status=SendPod.Status.LOCKED, attempt_count=5)
        auth_client.post(reverse("send_unlock", kwargs={"hash": pod.hash}))
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.PENDING
        assert pod.attempt_count == 0

    def test_owner_post_keeps_encrypted_secret(self, auth_client, make_send_pod):
        pod = make_send_pod(status=SendPod.Status.LOCKED)
        auth_client.post(reverse("send_unlock", kwargs={"hash": pod.hash}))
        pod.refresh_from_db()
        assert pod.encrypted_secret is not None

    def test_owner_post_redirects_to_send_view(self, auth_client, make_send_pod):
        pod = make_send_pod(status=SendPod.Status.LOCKED)
        resp = auth_client.post(reverse("send_unlock", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert resp["Location"] == reverse("send_view", kwargs={"hash": pod.hash})

    def test_non_owner_post_does_not_unlock(self, client, other_user, make_send_pod):
        pod = make_send_pod(status=SendPod.Status.LOCKED)
        client.force_login(other_user)
        client.post(reverse("send_unlock", kwargs={"hash": pod.hash}))
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.LOCKED

    def test_expired_locked_pod_is_destroyed_not_unlocked(
        self, auth_client, make_send_pod
    ):
        pod = make_send_pod(
            status=SendPod.Status.LOCKED, deadline=timezone.now() - timedelta(hours=1)
        )
        resp = auth_client.post(reverse("send_unlock", kwargs={"hash": pod.hash}))
        assert resp["Location"] == reverse("send_view", kwargs={"hash": pod.hash})
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED
        assert pod.encrypted_secret is None

    def test_owner_post_on_non_locked_pod_does_nothing(self, auth_client, make_send_pod):
        pod = make_send_pod(status=SendPod.Status.PENDING)
        resp = auth_client.post(reverse("send_unlock", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert resp["Location"] == reverse("dashboard")
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.PENDING


@pytest.mark.django_db
class TestSendDeleteView:
    def test_authenticated_get_returns_405(self, auth_client, make_send_pod):
        pod = make_send_pod()
        resp = auth_client.get(reverse("send_delete", kwargs={"hash": pod.hash}))
        assert resp.status_code == 405

    def test_anonymous_post_redirects_to_login(self, client, make_send_pod):
        pod = make_send_pod()
        resp = client.post(reverse("send_delete", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_owner_post_deletes_pod(self, auth_client, make_send_pod):
        pod = make_send_pod()
        auth_client.post(reverse("send_delete", kwargs={"hash": pod.hash}))
        assert not SendPod.objects.filter(hash=pod.hash).exists()

    def test_owner_post_redirects_to_dashboard(self, auth_client, make_send_pod):
        pod = make_send_pod()
        resp = auth_client.post(reverse("send_delete", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert resp["Location"] == reverse("dashboard")

    def test_non_owner_post_does_not_delete_pod(
        self, client, other_user, make_send_pod
    ):
        pod = make_send_pod()
        client.force_login(other_user)
        client.post(reverse("send_delete", kwargs={"hash": pod.hash}))
        assert SendPod.objects.filter(hash=pod.hash).exists()
