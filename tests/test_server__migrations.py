"""Tests for migrations: models in sync, and data migrations."""

import importlib

import pytest
from django.apps import apps
from django.core.management import call_command

from privipod.server import ReceivePod

migration_0002 = importlib.import_module("privipod.migrations.0002_add_send_features")


@pytest.mark.django_db
def test_no_missing_migrations():
    call_command("makemigrations", "privipod", "--check", "--dry-run", verbosity=0)


@pytest.mark.django_db
class TestReceivePodStatusRename:
    def test_sent_is_renamed_to_received(self, make_pod):
        pod = make_pod()
        ReceivePod.objects.filter(pk=pod.pk).update(status="sent")
        migration_0002.rename_sent_to_received(apps, None)
        pod.refresh_from_db()
        assert pod.status == ReceivePod.Status.RECEIVED

    def test_reverse_renames_received_to_sent(self, make_pod):
        pod = make_pod(status=ReceivePod.Status.RECEIVED)
        migration_0002.rename_received_to_sent(apps, None)
        pod.refresh_from_db()
        assert pod.status == "sent"

    def test_other_statuses_are_untouched(self, make_pod):
        pod = make_pod(status=ReceivePod.Status.DESTROYED)
        migration_0002.rename_sent_to_received(apps, None)
        pod.refresh_from_db()
        assert pod.status == ReceivePod.Status.DESTROYED
