"""Tests for the dashboard view."""

import pytest
from django.urls import reverse


@pytest.mark.django_db
class TestDashboardView:
    def test_anonymous_redirects_to_login(self, client):
        resp = client.get(reverse("dashboard"))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_authenticated_returns_200(self, auth_client):
        resp = auth_client.get(reverse("dashboard"))
        assert resp.status_code == 200

    def test_shows_only_own_pods(self, auth_client, user, other_user, make_pod):
        my_pod = make_pod(owner=user, name="Mine", hash="hash-mine")
        make_pod(owner=other_user, name="Theirs", hash="hash-theirs")

        resp = auth_client.get(reverse("dashboard"))
        assert resp.status_code == 200
        pods = list(resp.context["pods"])
        assert my_pod in pods
        assert all(p.owner == user for p in pods)

    def test_empty_dashboard_when_no_pods(self, auth_client):
        resp = auth_client.get(reverse("dashboard"))
        assert resp.status_code == 200
        assert list(resp.context["pods"]) == []
