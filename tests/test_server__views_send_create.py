"""Tests for the send pod creation view (/send/create/)."""

import json
import secrets
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from privipod.server import SendPod
from privipod.views.send import pod_hash_signer

VALID_ENCRYPTED = json.dumps(
    {"encryptedKey": "abc123", "encryptedData": "xyz456", "iv": "ivval"}
)


@pytest.fixture
def pod_hash():
    return secrets.token_urlsafe(32)


@pytest.mark.django_db
class TestSendCreateViewGet:
    def test_anonymous_get_redirects_to_login(self, client):
        resp = client.get(reverse("send_create"))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_authenticated_get_returns_200(self, auth_client):
        resp = auth_client.get(reverse("send_create"))
        assert resp.status_code == 200

    def test_authenticated_get_includes_form_in_context(self, auth_client):
        resp = auth_client.get(reverse("send_create"))
        assert "form" in resp.context

    def test_recipient_choices_exclude_current_user(self, auth_client, user, other_user):
        resp = auth_client.get(reverse("send_create"))
        choices = [v for v, _ in resp.context["form"].fields["recipient_username"].choices]
        assert user.username not in choices

    def test_recipient_choices_include_other_users(self, auth_client, other_user):
        resp = auth_client.get(reverse("send_create"))
        choices = [v for v, _ in resp.context["form"].fields["recipient_username"].choices]
        assert other_user.username in choices

    def test_hidden_fields_are_not_rendered_twice(self, auth_client):
        # encrypted_secret/secret_type/encrypted_filename are HiddenInput fields,
        # so form.hidden_fields already renders them; a second explicit
        # {{ form.field }} render produces a duplicate name= input, and the
        # browser then submits an empty duplicate that shadows the JS-set one.
        import re

        resp = auth_client.get(reverse("send_create"))
        html = resp.content.decode()
        for name in ("encrypted_secret", "secret_type", "encrypted_filename"):
            count = len(re.findall(rf'name="{name}"', html))
            assert count == 1, f'input[name="{name}"] appears {count} times, expected 1'


@pytest.mark.django_db
class TestSendCreateViewPost:
    def test_valid_post_no_recipient_creates_pod(self, auth_client, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": VALID_ENCRYPTED, "secret_type": "text", "pod_hash": pod_hash_signer.sign(pod_hash)},
        )
        assert SendPod.objects.count() == 1

    def test_valid_post_no_recipient_has_none_recipient(self, auth_client, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": VALID_ENCRYPTED, "secret_type": "text", "pod_hash": pod_hash_signer.sign(pod_hash)},
        )
        pod = SendPod.objects.first()
        assert pod.recipient is None

    def test_valid_post_redirects_to_send_view(self, auth_client, pod_hash):
        resp = auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": VALID_ENCRYPTED, "secret_type": "text", "pod_hash": pod_hash_signer.sign(pod_hash)},
        )
        assert resp.status_code == 302
        assert resp["Location"] == reverse("send_view", kwargs={"hash": pod_hash})

    def test_valid_post_sets_owner_to_current_user(self, auth_client, user, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": VALID_ENCRYPTED, "secret_type": "text", "pod_hash": pod_hash_signer.sign(pod_hash)},
        )
        pod = SendPod.objects.first()
        assert pod.owner == user

    def test_valid_post_sets_status_pending(self, auth_client, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": VALID_ENCRYPTED, "secret_type": "text", "pod_hash": pod_hash_signer.sign(pod_hash)},
        )
        pod = SendPod.objects.first()
        assert pod.status == SendPod.Status.PENDING

    def test_valid_post_with_recipient_sets_recipient(self, auth_client, other_user, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {
                "encrypted_secret": VALID_ENCRYPTED,
                "secret_type": "text",
                "recipient_username": other_user.username,
                "pod_hash": pod_hash_signer.sign(pod_hash),
            },
        )
        pod = SendPod.objects.first()
        assert pod.recipient == other_user

    def test_unknown_recipient_username_does_not_create_pod(self, auth_client, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {
                "encrypted_secret": VALID_ENCRYPTED,
                "secret_type": "text",
                "recipient_username": "no-such-user",
                "pod_hash": pod_hash_signer.sign(pod_hash),
            },
        )
        assert SendPod.objects.count() == 0

    def test_unknown_recipient_username_fails_validation(self, auth_client, pod_hash):
        resp = auth_client.post(
            reverse("send_create"),
            {
                "encrypted_secret": VALID_ENCRYPTED,
                "secret_type": "text",
                "recipient_username": "no-such-user",
                "pod_hash": pod_hash_signer.sign(pod_hash),
            },
        )
        assert resp.status_code == 200
        assert resp.context["form"].errors

    def test_invalid_json_encrypted_secret_does_not_create_pod(self, auth_client, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": "not-valid-json", "secret_type": "text", "pod_hash": pod_hash_signer.sign(pod_hash)},
        )
        assert SendPod.objects.count() == 0

    def test_oversized_data_does_not_create_pod(self, auth_client, pod_hash):
        from privipod.server import MAX_SIZE_BYTES

        big_data = "x" * (MAX_SIZE_BYTES + 1)
        auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": big_data, "secret_type": "text", "pod_hash": pod_hash_signer.sign(pod_hash)},
        )
        assert SendPod.objects.count() == 0

    def test_hash_collision_redirects_back(self, auth_client, make_send_pod, pod_hash):
        make_send_pod(hash=pod_hash)
        resp = auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": VALID_ENCRYPTED, "secret_type": "text", "pod_hash": pod_hash_signer.sign(pod_hash)},
        )
        assert resp.status_code == 302
        assert resp["Location"] == reverse("send_create")

    def test_get_returns_pod_hash_in_context(self, auth_client):
        resp = auth_client.get(reverse("send_create"))
        assert "pod_hash" in resp.context
        assert resp.context["pod_hash"]

    def test_get_form_pod_hash_is_signed(self, auth_client):
        resp = auth_client.get(reverse("send_create"))
        signed = resp.context["form"].initial["pod_hash"]
        assert pod_hash_signer.unsign(signed) == resp.context["pod_hash"]

    def test_unsigned_pod_hash_is_rejected(self, auth_client, pod_hash):
        resp = auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": VALID_ENCRYPTED, "secret_type": "text", "pod_hash": pod_hash},
        )
        assert resp.status_code == 302
        assert resp["Location"] == reverse("send_create")
        assert SendPod.objects.count() == 0

    def test_tampered_pod_hash_is_rejected(self, auth_client, pod_hash):
        signed = pod_hash_signer.sign(pod_hash)
        resp = auth_client.post(
            reverse("send_create"),
            {
                "encrypted_secret": VALID_ENCRYPTED,
                "secret_type": "text",
                "pod_hash": "short" + signed[len(pod_hash) :],
            },
        )
        assert resp.status_code == 302
        assert SendPod.objects.count() == 0

    def test_utc_deadline_is_accepted(self, auth_client, pod_hash):
        deadline = (timezone.now() + timedelta(hours=1)).replace(microsecond=0)
        auth_client.post(
            reverse("send_create"),
            {
                "encrypted_secret": VALID_ENCRYPTED,
                "secret_type": "text",
                "pod_hash": pod_hash_signer.sign(pod_hash),
                "deadline": deadline.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            },
        )
        assert SendPod.objects.get().deadline == deadline

    def test_past_deadline_is_rejected(self, auth_client, pod_hash):
        deadline = timezone.now() - timedelta(minutes=1)
        resp = auth_client.post(
            reverse("send_create"),
            {
                "encrypted_secret": VALID_ENCRYPTED,
                "secret_type": "text",
                "pod_hash": pod_hash_signer.sign(pod_hash),
                "deadline": deadline.isoformat(),
            },
        )
        assert resp.status_code == 200
        assert "deadline" in resp.context["form"].errors
        assert resp.context["pod_hash"] == pod_hash
        assert SendPod.objects.count() == 0


@pytest.mark.django_db
class TestSendCreateViewPostAnonKeyStorage:
    """Anonymous-pod key-storage fields: access-code wrapping vs. keyfile challenge."""

    VALID_WRAPPED_KEY = json.dumps({"wrapped": "abc", "iv": "def"})
    VALID_CHALLENGE = json.dumps({"ciphertext": "abc"})
    TOKEN_HEX = ("ab" * 32)

    def test_access_code_fields_store_encrypted_private_key(self, auth_client, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {
                "encrypted_secret": VALID_ENCRYPTED,
                "secret_type": "text",
                "pod_hash": pod_hash_signer.sign(pod_hash),
                "encrypted_private_key": self.VALID_WRAPPED_KEY,
                "verification_token": self.TOKEN_HEX,
            },
        )
        pod = SendPod.objects.first()
        assert pod.encrypted_private_key == self.VALID_WRAPPED_KEY.encode()
        assert pod.verification_token == bytes.fromhex(self.TOKEN_HEX)
        assert pod.read_challenge is None

    def test_read_challenge_fields_store_read_challenge(self, auth_client, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {
                "encrypted_secret": VALID_ENCRYPTED,
                "secret_type": "text",
                "pod_hash": pod_hash_signer.sign(pod_hash),
                "read_challenge": self.VALID_CHALLENGE,
                "verification_token": self.TOKEN_HEX,
            },
        )
        pod = SendPod.objects.first()
        assert pod.read_challenge == self.VALID_CHALLENGE.encode()
        assert pod.verification_token == bytes.fromhex(self.TOKEN_HEX)
        assert pod.encrypted_private_key is None

    def test_invalid_read_challenge_json_does_not_create_pod(self, auth_client, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {
                "encrypted_secret": VALID_ENCRYPTED,
                "secret_type": "text",
                "pod_hash": pod_hash_signer.sign(pod_hash),
                "read_challenge": "not-json",
                "verification_token": self.TOKEN_HEX,
            },
        )
        assert SendPod.objects.count() == 0

    def test_no_key_fields_leaves_both_unset(self, auth_client, pod_hash):
        auth_client.post(
            reverse("send_create"),
            {"encrypted_secret": VALID_ENCRYPTED, "secret_type": "text", "pod_hash": pod_hash_signer.sign(pod_hash)},
        )
        pod = SendPod.objects.first()
        assert pod.encrypted_private_key is None
        assert pod.read_challenge is None
        assert pod.verification_token is None
