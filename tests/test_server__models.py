"""Tests for Pod model methods."""

from datetime import timedelta

import pytest
from django.utils import timezone


@pytest.fixture
def pod_cls():
    from privipod.server import Pod

    return Pod


class TestPodIsExpired:
    def test_no_deadline_returns_false(self, pod_cls):
        pod = pod_cls(deadline=None)
        assert pod.is_expired() is False

    def test_future_deadline_returns_false(self, pod_cls):
        pod = pod_cls(deadline=timezone.now() + timedelta(hours=1))
        assert pod.is_expired() is False

    def test_past_deadline_returns_true(self, pod_cls):
        pod = pod_cls(deadline=timezone.now() - timedelta(seconds=1))
        assert pod.is_expired() is True


class TestPodCanSend:
    def test_pending_not_expired_returns_true(self, pod_cls):
        pod = pod_cls(
            status=pod_cls.Status.PENDING,
            deadline=timezone.now() + timedelta(hours=1),
        )
        assert pod.can_send() is True

    def test_pending_no_deadline_returns_true(self, pod_cls):
        pod = pod_cls(status=pod_cls.Status.PENDING, deadline=None)
        assert pod.can_send() is True

    def test_sent_returns_false(self, pod_cls):
        pod = pod_cls(status=pod_cls.Status.SENT, deadline=None)
        assert pod.can_send() is False

    def test_expired_returns_false(self, pod_cls):
        pod = pod_cls(
            status=pod_cls.Status.PENDING,
            deadline=timezone.now() - timedelta(seconds=1),
        )
        assert pod.can_send() is False


class TestPodStr:
    def test_str_includes_name_and_status(self, pod_cls):
        pod = pod_cls(name="My Secret", status=pod_cls.Status.PENDING)
        assert "My Secret" in str(pod)
        assert "pending" in str(pod)
