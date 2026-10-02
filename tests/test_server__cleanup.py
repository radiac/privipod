"""Tests for the background expired-pod cleanup sweep."""

from datetime import timedelta

import pytest
from django.utils import timezone

from privipod.server import (
    ReceiveLog,
    ReceivePod,
    SendLog,
    SendPod,
    _cleanup_expired_pods_once,
)


@pytest.fixture
async def owner(db):
    import uuid

    from django.contrib.auth.models import User

    return await User.objects.acreate_user(
        username=f"cleanup-owner-{uuid.uuid4()}", password="pw"
    )


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
class TestCleanupExpiredPods:
    async def test_destroys_expired_pending_receive_pod(self, owner):
        pod = await ReceivePod.objects.acreate(
            owner=owner,
            hash="cleanup-pending",
            public_key='{"kty":"RSA"}',
            status=ReceivePod.Status.PENDING,
            deadline=timezone.now() - timedelta(hours=1),
        )
        await _cleanup_expired_pods_once()
        await pod.arefresh_from_db()
        assert pod.status == ReceivePod.Status.DESTROYED

    async def test_destroys_expired_sent_receive_pod(self, owner):
        pod = await ReceivePod.objects.acreate(
            owner=owner,
            hash="cleanup-sent",
            public_key='{"kty":"RSA"}',
            status=ReceivePod.Status.RECEIVED,
            encrypted_secret=b'{"encryptedKey":"a","encryptedData":"b","iv":"c"}',
            deadline=timezone.now() - timedelta(hours=1),
        )
        await _cleanup_expired_pods_once()
        await pod.arefresh_from_db()
        assert pod.status == ReceivePod.Status.DESTROYED
        assert pod.encrypted_secret is None

    async def test_leaves_unexpired_receive_pod_alone(self, owner):
        pod = await ReceivePod.objects.acreate(
            owner=owner,
            hash="cleanup-future",
            public_key='{"kty":"RSA"}',
            status=ReceivePod.Status.RECEIVED,
            deadline=timezone.now() + timedelta(hours=1),
        )
        await _cleanup_expired_pods_once()
        await pod.arefresh_from_db()
        assert pod.status == ReceivePod.Status.RECEIVED

    async def test_destroys_expired_received_send_pod(self, owner):
        pod = await SendPod.objects.acreate(
            owner=owner,
            hash="cleanup-received",
            encrypted_secret=b'{"encryptedKey":"a","encryptedData":"b","iv":"c"}',
            secret_type="text",
            status=SendPod.Status.READ,
            deadline=timezone.now() - timedelta(hours=1),
        )
        await _cleanup_expired_pods_once()
        await pod.arefresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED
        assert pod.encrypted_secret is None

    async def test_destroys_expired_locked_send_pod(self, owner):
        pod = await SendPod.objects.acreate(
            owner=owner,
            hash="cleanup-locked",
            encrypted_secret=b'{"encryptedKey":"a","encryptedData":"b","iv":"c"}',
            secret_type="text",
            status=SendPod.Status.LOCKED,
            deadline=timezone.now() - timedelta(hours=1),
        )
        await _cleanup_expired_pods_once()
        await pod.arefresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED
        assert pod.encrypted_secret is None

    async def test_logs_expired_receive_pod(self, owner):
        pod = await ReceivePod.objects.acreate(
            owner=owner,
            hash="cleanup-log-receive",
            public_key='{"kty":"RSA"}',
            deadline=timezone.now() - timedelta(hours=1),
        )
        await _cleanup_expired_pods_once()
        logs = [log async for log in ReceiveLog.objects.filter(pod=pod)]
        assert [(log.event, log.detail) for log in logs] == [
            (ReceiveLog.Event.DESTROYED, "expired")
        ]

    async def test_logs_expired_send_pod(self, owner):
        pod = await SendPod.objects.acreate(
            owner=owner,
            hash="cleanup-log-send",
            secret_type="text",
            deadline=timezone.now() - timedelta(hours=1),
        )
        await _cleanup_expired_pods_once()
        logs = [log async for log in SendLog.objects.filter(pod=pod)]
        assert [(log.event, log.detail) for log in logs] == [
            (SendLog.Event.DESTROYED, "expired")
        ]

    async def test_does_not_relog_destroyed_pod(self, owner):
        pod = await SendPod.objects.acreate(
            owner=owner,
            hash="cleanup-already-destroyed",
            secret_type="text",
            status=SendPod.Status.DESTROYED,
            deadline=timezone.now() - timedelta(hours=1),
        )
        await _cleanup_expired_pods_once()
        assert not await SendLog.objects.filter(pod=pod).aexists()
