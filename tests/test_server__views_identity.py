"""Tests for identity and user public key views."""

import json

import pytest
from django.urls import reverse

VALID_IDENTITY_KEY = json.dumps({"kty": "RSA", "n": "test_modulus", "e": "AQAB"})


@pytest.mark.django_db
class TestIdentitySetupView:
    def test_anonymous_redirects_to_login(self, client):
        resp = client.post(
            reverse("identity_setup"),
            {"identity_public_key": VALID_IDENTITY_KEY},
        )
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_missing_key_no_existing_profile_returns_400(self, auth_client):
        resp = auth_client.post(reverse("identity_setup"), {})
        assert resp.status_code == 400

    def test_valid_key_returns_200(self, auth_client):
        resp = auth_client.post(
            reverse("identity_setup"),
            {"identity_public_key": VALID_IDENTITY_KEY},
        )
        assert resp.status_code == 200

    def test_valid_key_returns_ok_status(self, auth_client):
        resp = auth_client.post(
            reverse("identity_setup"),
            {"identity_public_key": VALID_IDENTITY_KEY},
        )
        data = json.loads(resp.content)
        assert data["status"] == "ok"

    def test_valid_key_creates_user_profile(self, auth_client, user):
        from privipod.server import UserProfile

        auth_client.post(
            reverse("identity_setup"),
            {"identity_public_key": VALID_IDENTITY_KEY},
        )
        assert UserProfile.objects.filter(user=user).exists()

    def test_valid_key_stores_public_key(self, auth_client, user):
        from privipod.server import UserProfile

        auth_client.post(
            reverse("identity_setup"),
            {"identity_public_key": VALID_IDENTITY_KEY},
        )
        profile = UserProfile.objects.get(user=user)
        assert profile.identity_public_key == VALID_IDENTITY_KEY

    def test_second_call_updates_public_key(self, auth_client, user):
        from privipod.server import UserProfile

        updated_key = json.dumps({"kty": "RSA", "n": "new_modulus", "e": "AQAB"})
        auth_client.post(
            reverse("identity_setup"),
            {"identity_public_key": VALID_IDENTITY_KEY},
        )
        auth_client.post(
            reverse("identity_setup"),
            {"identity_public_key": updated_key},
        )
        profile = UserProfile.objects.get(user=user)
        assert profile.identity_public_key == updated_key

    def test_invalid_json_key_returns_400(self, auth_client):
        resp = auth_client.post(
            reverse("identity_setup"),
            {"identity_public_key": "not-valid-json"},
        )
        assert resp.status_code == 400

    def test_missing_key_with_existing_profile_returns_200(self, auth_client, user):
        from privipod.server import UserProfile

        # Pre-create profile with a key so the "missing key" path doesn't error
        UserProfile.objects.create(user=user, identity_public_key=VALID_IDENTITY_KEY)
        resp = auth_client.post(reverse("identity_setup"), {})
        assert resp.status_code == 200


@pytest.mark.django_db
class TestIdentityGetKeyView:
    def test_anonymous_redirects_to_login(self, client):
        resp = client.get(reverse("identity_get_key"))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_no_profile_returns_200(self, auth_client):
        resp = auth_client.get(reverse("identity_get_key"))
        assert resp.status_code == 200

    def test_no_profile_has_identity_key_false(self, auth_client):
        resp = auth_client.get(reverse("identity_get_key"))
        data = json.loads(resp.content)
        assert data["has_identity_key"] is False

    def test_no_profile_encrypted_private_key_is_none(self, auth_client):
        resp = auth_client.get(reverse("identity_get_key"))
        data = json.loads(resp.content)
        assert data["encrypted_private_key"] is None

    def test_profile_with_key_returns_200(self, auth_client, user):
        from privipod.server import UserProfile

        UserProfile.objects.create(user=user, identity_public_key=VALID_IDENTITY_KEY)
        resp = auth_client.get(reverse("identity_get_key"))
        assert resp.status_code == 200

    def test_profile_with_key_has_identity_key_true(self, auth_client, user):
        from privipod.server import UserProfile

        UserProfile.objects.create(user=user, identity_public_key=VALID_IDENTITY_KEY)
        resp = auth_client.get(reverse("identity_get_key"))
        data = json.loads(resp.content)
        assert data["has_identity_key"] is True

    def test_profile_without_public_key_has_identity_key_false(
        self, auth_client, user
    ):
        from privipod.server import UserProfile

        UserProfile.objects.create(user=user, identity_public_key="")
        resp = auth_client.get(reverse("identity_get_key"))
        data = json.loads(resp.content)
        assert data["has_identity_key"] is False


@pytest.mark.django_db
class TestUserPublicKeyView:
    def test_anonymous_redirects_to_login(self, client, other_user):
        resp = client.get(
            reverse("user_public_key", kwargs={"username": other_user.username})
        )
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_user_not_found_returns_404(self, auth_client):
        resp = auth_client.get(
            reverse("user_public_key", kwargs={"username": "nobody"})
        )
        assert resp.status_code == 404

    def test_user_with_no_profile_returns_404(self, auth_client, other_user):
        resp = auth_client.get(
            reverse("user_public_key", kwargs={"username": other_user.username})
        )
        assert resp.status_code == 404

    def test_user_with_empty_identity_key_returns_404(self, auth_client, other_user):
        from privipod.server import UserProfile

        UserProfile.objects.create(user=other_user, identity_public_key="")
        resp = auth_client.get(
            reverse("user_public_key", kwargs={"username": other_user.username})
        )
        assert resp.status_code == 404

    def test_user_with_identity_key_returns_200(self, auth_client, other_user):
        from privipod.server import UserProfile

        UserProfile.objects.create(
            user=other_user, identity_public_key=VALID_IDENTITY_KEY
        )
        resp = auth_client.get(
            reverse("user_public_key", kwargs={"username": other_user.username})
        )
        assert resp.status_code == 200

    def test_user_with_identity_key_response_contains_public_key(
        self, auth_client, other_user
    ):
        from privipod.server import UserProfile

        UserProfile.objects.create(
            user=other_user, identity_public_key=VALID_IDENTITY_KEY
        )
        resp = auth_client.get(
            reverse("user_public_key", kwargs={"username": other_user.username})
        )
        data = json.loads(resp.content)
        assert "public_key" in data

    def test_user_with_identity_key_response_public_key_is_parsed_json(
        self, auth_client, other_user
    ):
        from privipod.server import UserProfile

        UserProfile.objects.create(
            user=other_user, identity_public_key=VALID_IDENTITY_KEY
        )
        resp = auth_client.get(
            reverse("user_public_key", kwargs={"username": other_user.username})
        )
        data = json.loads(resp.content)
        # public_key is returned as a parsed JSON object, not a string
        assert isinstance(data["public_key"], dict)
        assert data["public_key"]["kty"] == "RSA"
