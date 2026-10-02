"""Tests for SendPod model methods: is_expired, can_access, destroy, expire, lock, unlock."""

from datetime import timedelta

import pytest
from django.utils import timezone


@pytest.fixture
def send_pod_cls():
    from privipod.server import SendPod

    return SendPod


class TestSendPodIsExpired:
    def test_no_deadline_returns_false(self, send_pod_cls):
        pod = send_pod_cls(deadline=None)
        assert pod.is_expired() is False

    def test_future_deadline_returns_false(self, send_pod_cls):
        pod = send_pod_cls(deadline=timezone.now() + timedelta(hours=1))
        assert pod.is_expired() is False

    def test_past_deadline_returns_true(self, send_pod_cls):
        pod = send_pod_cls(deadline=timezone.now() - timedelta(seconds=1))
        assert pod.is_expired() is True


class TestSendPodCanAccess:
    def test_pending_no_deadline_returns_true(self, send_pod_cls):
        pod = send_pod_cls(status=send_pod_cls.Status.PENDING, deadline=None)
        assert pod.can_access() is True

    def test_pending_future_deadline_returns_true(self, send_pod_cls):
        pod = send_pod_cls(
            status=send_pod_cls.Status.PENDING,
            deadline=timezone.now() + timedelta(hours=1),
        )
        assert pod.can_access() is True

    def test_received_no_deadline_returns_true(self, send_pod_cls):
        pod = send_pod_cls(status=send_pod_cls.Status.READ, deadline=None)
        assert pod.can_access() is True

    def test_locked_returns_false(self, send_pod_cls):
        pod = send_pod_cls(status=send_pod_cls.Status.LOCKED, deadline=None)
        assert pod.can_access() is False

    def test_destroyed_returns_false(self, send_pod_cls):
        pod = send_pod_cls(status=send_pod_cls.Status.DESTROYED, deadline=None)
        assert pod.can_access() is False

    def test_pending_expired_returns_false(self, send_pod_cls):
        pod = send_pod_cls(
            status=send_pod_cls.Status.PENDING,
            deadline=timezone.now() - timedelta(seconds=1),
        )
        assert pod.can_access() is False

    def test_received_expired_returns_false(self, send_pod_cls):
        pod = send_pod_cls(
            status=send_pod_cls.Status.READ,
            deadline=timezone.now() - timedelta(seconds=1),
        )
        assert pod.can_access() is False


@pytest.mark.django_db
class TestSendPodDestroy:
    def test_destroy_clears_encrypted_secret(self, make_send_pod):
        pod = make_send_pod()
        pod.destroy()
        assert pod.encrypted_secret is None

    def test_destroy_clears_encrypted_filename(self, make_send_pod):
        pod = make_send_pod(
            encrypted_filename=b'{"encryptedKey":"k","encryptedData":"d","iv":"i"}'
        )
        pod.destroy()
        assert pod.encrypted_filename is None

    def test_destroy_clears_encrypted_private_key(self, make_send_pod):
        pod = make_send_pod(encrypted_private_key=b'{"wrapped":"key","iv":"salt"}')
        pod.destroy()
        assert pod.encrypted_private_key is None

    def test_destroy_clears_verification_token(self, make_send_pod):
        pod = make_send_pod(verification_token=b"a" * 32)
        pod.destroy()
        assert pod.verification_token is None

    def test_destroy_sets_status_destroyed(self, make_send_pod):
        from privipod.server import SendPod

        pod = make_send_pod()
        pod.destroy()
        assert pod.status == SendPod.Status.DESTROYED

    def test_destroy_persists_changes_to_db(self, make_send_pod):
        pod = make_send_pod()
        pod.destroy()
        pod.refresh_from_db()
        assert pod.encrypted_secret is None

    def test_destroy_accepts_custom_status(self, make_send_pod):
        from privipod.server import SendPod

        pod = make_send_pod()
        pod.destroy(status=SendPod.Status.LOCKED)
        assert pod.status == SendPod.Status.LOCKED


class TestSendPodExpire:
    @pytest.mark.parametrize("status", ["pending", "read", "locked"])
    def test_expired_pod_is_destroyed_whatever_its_status(self, make_send_pod, status):
        from privipod.server import SendPod

        pod = make_send_pod(status=status, deadline=timezone.now() - timedelta(hours=1))
        assert pod.expire() is True
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.DESTROYED
        assert pod.encrypted_secret is None

    def test_expire_logs_destroyed_expired(self, make_send_pod):
        from privipod.server import SendLog

        pod = make_send_pod(deadline=timezone.now() - timedelta(hours=1))
        pod.expire()
        log = pod.logs.get()
        assert log.event == SendLog.Event.DESTROYED
        assert log.detail == "expired"
        assert log.user is None

    def test_unexpired_pod_is_left_alone(self, make_send_pod):
        from privipod.server import SendPod

        pod = make_send_pod(deadline=timezone.now() + timedelta(hours=1))
        assert pod.expire() is False
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.PENDING
        assert not pod.logs.exists()

    def test_pod_without_deadline_is_left_alone(self, make_send_pod):
        pod = make_send_pod()
        assert pod.expire() is False
        assert not pod.logs.exists()

    def test_stale_instance_does_not_relog(self, make_send_pod):
        # Simulates a view and the cleanup expiring the same pod concurrently
        from privipod.server import SendPod

        pod = make_send_pod(deadline=timezone.now() - timedelta(hours=1))
        stale = SendPod.objects.get(pk=pod.pk)
        assert pod.expire() is True
        assert stale.expire() is False
        assert stale.status == SendPod.Status.DESTROYED
        assert pod.logs.count() == 1


@pytest.mark.django_db
class TestSendPodLock:
    def test_lock_sets_status_locked(self, make_send_pod):
        from privipod.server import SendPod

        pod = make_send_pod()
        pod.lock()
        assert pod.status == SendPod.Status.LOCKED

    def test_lock_keeps_encrypted_secret(self, make_send_pod):
        # Locking blocks further attempts (via can_access()) but is reversible via
        # unlock(), so the secret must survive - unlike destroy().
        pod = make_send_pod()
        pod.lock()
        assert pod.encrypted_secret is not None

    def test_lock_keeps_verification_token(self, make_send_pod):
        pod = make_send_pod(verification_token=b"a" * 32)
        pod.lock()
        assert pod.verification_token == b"a" * 32

    def test_lock_persists_to_db(self, make_send_pod):
        from privipod.server import SendPod

        pod = make_send_pod()
        pod.lock()
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.LOCKED


@pytest.mark.django_db
class TestSendPodUnlock:
    def test_unlock_sets_status_pending(self, make_send_pod):
        from privipod.server import SendPod

        pod = make_send_pod(status=SendPod.Status.LOCKED, attempt_count=5)
        pod.unlock()
        assert pod.status == SendPod.Status.PENDING

    def test_unlock_resets_attempt_count(self, make_send_pod):
        from privipod.server import SendPod

        pod = make_send_pod(status=SendPod.Status.LOCKED, attempt_count=5)
        pod.unlock()
        assert pod.attempt_count == 0

    def test_unlock_keeps_encrypted_secret(self, make_send_pod):
        from privipod.server import SendPod

        pod = make_send_pod(status=SendPod.Status.LOCKED)
        pod.unlock()
        assert pod.encrypted_secret is not None

    def test_unlock_persists_to_db(self, make_send_pod):
        from privipod.server import SendPod

        pod = make_send_pod(status=SendPod.Status.LOCKED, attempt_count=5)
        pod.unlock()
        pod.refresh_from_db()
        assert pod.status == SendPod.Status.PENDING
        assert pod.attempt_count == 0


class TestSendPodStr:
    def test_str_includes_name_and_status(self, send_pod_cls):
        pod = send_pod_cls(name="Top Secret", status=send_pod_cls.Status.PENDING)
        assert "Top Secret" in str(pod)
        assert "pending" in str(pod)
