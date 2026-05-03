"""Tests for the pod create view."""

import pytest
from django.urls import reverse

from privipod.server import Pod


@pytest.mark.django_db
class TestPodCreateView:
    def test_anonymous_get_redirects_to_login(self, client):
        resp = client.get(reverse("pod_create"))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_anonymous_post_redirects_to_login(self, client):
        resp = client.post(reverse("pod_create"), {})
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_authenticated_get_returns_form(self, auth_client):
        resp = auth_client.get(reverse("pod_create"))
        assert resp.status_code == 200
        assert "form" in resp.context

    def test_post_creates_pod_with_owner(self, auth_client, user):
        resp = auth_client.post(
            reverse("pod_create"),
            {
                "name": "New Pod",
                "public_key": '{"kty":"RSA","n":"abc","e":"AQAB"}',
            },
        )
        assert resp.status_code == 302
        pod = Pod.objects.get(name="New Pod")
        assert pod.owner == user

    def test_post_generates_unique_hash(self, auth_client):
        auth_client.post(
            reverse("pod_create"),
            {
                "name": "Pod A",
                "public_key": '{"kty":"RSA","n":"abc","e":"AQAB"}',
            },
        )
        auth_client.post(
            reverse("pod_create"),
            {
                "name": "Pod B",
                "public_key": '{"kty":"RSA","n":"abc","e":"AQAB"}',
            },
        )
        hashes = list(Pod.objects.values_list("hash", flat=True))
        assert len(hashes) == len(set(hashes))

    def test_post_redirects_to_pod_view(self, auth_client):
        resp = auth_client.post(
            reverse("pod_create"),
            {
                "name": "Redirect Pod",
                "public_key": '{"kty":"RSA","n":"abc","e":"AQAB"}',
            },
        )
        assert resp.status_code == 302
        pod = Pod.objects.get(name="Redirect Pod")
        assert pod.hash in resp["Location"]

    def test_post_missing_public_key_shows_form_errors(self, auth_client):
        resp = auth_client.post(
            reverse("pod_create"),
            {"name": "Bad Pod"},
        )
        assert resp.status_code == 200
        assert resp.context["form"].errors

    def test_new_pod_has_pending_status(self, auth_client):
        auth_client.post(
            reverse("pod_create"),
            {
                "name": "Status Pod",
                "public_key": '{"kty":"RSA","n":"abc","e":"AQAB"}',
            },
        )
        pod = Pod.objects.get(name="Status Pod")
        assert pod.status == Pod.Status.PENDING
