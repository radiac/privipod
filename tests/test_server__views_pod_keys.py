"""Tests for receive pod key storage endpoints: store-key, get-key."""

import json
from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from privipod.server import ReceivePod

WRAPPED_KEY = json.dumps({"wrapped": "abc", "iv": "def"})


@pytest.mark.django_db
class TestPodStoreKeyView:
    def test_owner_stores_key(self, auth_client, make_pod):
        pod = make_pod()
        resp = auth_client.post(
            reverse("pod_store_key", kwargs={"hash": pod.hash}),
            {"encrypted_private_key": WRAPPED_KEY},
        )
        assert resp.status_code == 200
        pod.refresh_from_db()
        assert pod.encrypted_private_key == WRAPPED_KEY.encode()

    def test_destroyed_pod_is_refused(self, auth_client, make_pod):
        pod = make_pod(status=ReceivePod.Status.DESTROYED)
        resp = auth_client.post(
            reverse("pod_store_key", kwargs={"hash": pod.hash}),
            {"encrypted_private_key": WRAPPED_KEY},
        )
        assert resp.status_code == 409
        pod.refresh_from_db()
        assert pod.encrypted_private_key is None

    def test_expired_pod_is_destroyed_and_refused(self, auth_client, make_pod):
        pod = make_pod(deadline=timezone.now() - timedelta(hours=1))
        resp = auth_client.post(
            reverse("pod_store_key", kwargs={"hash": pod.hash}),
            {"encrypted_private_key": WRAPPED_KEY},
        )
        assert resp.status_code == 409
        pod.refresh_from_db()
        assert pod.status == ReceivePod.Status.DESTROYED
        assert pod.encrypted_private_key is None


@pytest.mark.django_db
class TestPodGetKeyView:
    def test_expired_pod_returns_no_key(self, auth_client, make_pod):
        pod = make_pod(
            encrypted_private_key=WRAPPED_KEY.encode(),
            deadline=timezone.now() - timedelta(hours=1),
        )
        resp = auth_client.get(reverse("pod_get_key", kwargs={"hash": pod.hash}))
        assert json.loads(resp.content) == {"encrypted_private_key": None}
        pod.refresh_from_db()
        assert pod.status == ReceivePod.Status.DESTROYED


@pytest.mark.django_db
class TestPodRemoveKeyView:
    def test_owner_removes_key(self, auth_client, make_pod):
        pod = make_pod(encrypted_private_key=WRAPPED_KEY.encode())
        resp = auth_client.post(reverse("pod_remove_key", kwargs={"hash": pod.hash}))
        assert resp.status_code == 200
        pod.refresh_from_db()
        assert pod.encrypted_private_key is None

    def test_destroyed_pod_is_refused(self, auth_client, make_pod):
        pod = make_pod(status=ReceivePod.Status.DESTROYED)
        resp = auth_client.post(reverse("pod_remove_key", kwargs={"hash": pod.hash}))
        assert resp.status_code == 409

    def test_expired_pod_is_destroyed_and_refused(self, auth_client, make_pod):
        pod = make_pod(
            encrypted_private_key=WRAPPED_KEY.encode(),
            deadline=timezone.now() - timedelta(hours=1),
        )
        resp = auth_client.post(reverse("pod_remove_key", kwargs={"hash": pod.hash}))
        assert resp.status_code == 409
        pod.refresh_from_db()
        assert pod.status == ReceivePod.Status.DESTROYED
        assert pod.logs.filter(event="destroyed", detail="expired").exists()
