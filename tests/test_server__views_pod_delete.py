"""Tests for the pod delete view."""

import pytest
from django.urls import reverse

from privipod.server import ReceivePod


@pytest.mark.django_db
class TestPodDeleteView:
    def test_get_returns_405(self, auth_client, make_pod):
        pod = make_pod()
        resp = auth_client.get(reverse("pod_delete", kwargs={"hash": pod.hash}))
        assert resp.status_code == 405

    def test_anonymous_post_redirects_to_login(self, client, make_pod):
        pod = make_pod()
        resp = client.post(reverse("pod_delete", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert "/login" in resp["Location"]

    def test_owner_post_deletes_pod(self, auth_client, make_pod):
        pod = make_pod()
        pod_hash = pod.hash
        resp = auth_client.post(reverse("pod_delete", kwargs={"hash": pod_hash}))
        assert resp.status_code == 302
        assert not ReceivePod.objects.filter(hash=pod_hash).exists()

    def test_owner_post_redirects_to_dashboard(self, auth_client, make_pod):
        pod = make_pod()
        resp = auth_client.post(reverse("pod_delete", kwargs={"hash": pod.hash}))
        assert resp["Location"] == reverse("dashboard")

    def test_non_owner_cannot_delete(self, client, other_user, make_pod):
        pod = make_pod(hash="not-mine")
        client.force_login(other_user)
        resp = client.post(reverse("pod_delete", kwargs={"hash": pod.hash}))
        assert resp.status_code == 302
        assert ReceivePod.objects.filter(hash="not-mine").exists()

    def test_nonexistent_pod_redirects_to_dashboard(self, auth_client):
        resp = auth_client.post(
            reverse("pod_delete", kwargs={"hash": "no-such-hash"})
        )
        assert resp.status_code == 302
        assert resp["Location"] == reverse("dashboard")
