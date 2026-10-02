import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def rename_sent_to_received(apps, schema_editor):
    ReceivePod = apps.get_model("privipod", "ReceivePod")
    ReceivePod.objects.filter(status="sent").update(status="received")


def rename_received_to_sent(apps, schema_editor):
    ReceivePod = apps.get_model("privipod", "ReceivePod")
    ReceivePod.objects.filter(status="received").update(status="sent")


class Migration(migrations.Migration):
    dependencies = [
        ("privipod", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Rename Pod → ReceivePod (preserves all existing rows)
        migrations.RenameModel("Pod", "ReceivePod"),
        # Rename sent status to received, add destroyed status and
        # encrypted_private_key to ReceivePod
        migrations.AlterField(
            model_name="receivepod",
            name="status",
            field=models.CharField(
                choices=[
                    ("pending", "Waiting for secret"),
                    ("received", "Secret received"),
                    ("destroyed", "Destroyed"),
                ],
                db_index=True,
                default="pending",
                max_length=20,
            ),
        ),
        migrations.RunPython(rename_sent_to_received, rename_received_to_sent),
        migrations.AddField(
            model_name="receivepod",
            name="encrypted_private_key",
            field=models.BinaryField(blank=True, null=True),
        ),
        # UserProfile
        migrations.CreateModel(
            name="UserProfile",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("identity_public_key", models.TextField(blank=True)),
                (
                    "encrypted_identity_private_key",
                    models.BinaryField(blank=True, null=True),
                ),
                ("identity_key_salt", models.BinaryField(blank=True, null=True)),
                ("onboarding", models.BooleanField(default=False)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="privipod_profile",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"app_label": "privipod"},
        ),
        # SendPod
        migrations.CreateModel(
            name="SendPod",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(blank=True, max_length=255)),
                ("hash", models.CharField(db_index=True, max_length=64, unique=True)),
                (
                    "deadline",
                    models.DateTimeField(blank=True, db_index=True, null=True),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Waiting to be decrypted"),
                            ("read", "Secret decrypted"),
                            ("locked", "Locked - too many attempts"),
                            ("destroyed", "Destroyed"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("encrypted_secret", models.BinaryField(blank=True, null=True)),
                (
                    "secret_type",
                    models.CharField(
                        blank=True,
                        choices=[("text", "Text"), ("file", "File")],
                        default="text",
                        max_length=10,
                    ),
                ),
                ("encrypted_filename", models.BinaryField(blank=True, null=True)),
                ("self_destruct", models.BooleanField(default=False)),
                ("encrypted_private_key", models.BinaryField(blank=True, null=True)),
                ("verification_token", models.BinaryField(blank=True, null=True)),
                ("read_challenge", models.BinaryField(blank=True, null=True)),
                ("attempt_count", models.IntegerField(default=0)),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sent_pods",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "recipient",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="received_send_pods",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["-created_at"], "app_label": "privipod"},
        ),
        # ReceiveLog
        migrations.CreateModel(
            name="ReceiveLog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                (
                    "event",
                    models.CharField(
                        choices=[
                            ("accessed", "Secret accessed"),
                            ("decrypted", "Secret decrypted"),
                            ("destroyed", "Destroyed"),
                        ],
                        max_length=20,
                    ),
                ),
                ("detail", models.CharField(blank=True, max_length=255)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="receive_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "pod",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="logs",
                        to="privipod.receivepod",
                    ),
                ),
            ],
            options={"ordering": ["-timestamp"], "app_label": "privipod"},
        ),
        # SendLog
        migrations.CreateModel(
            name="SendLog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                (
                    "event",
                    models.CharField(
                        choices=[
                            ("attempt_failed", "Failed access attempt"),
                            ("accessed", "Secret accessed"),
                            ("decrypted", "Secret decrypted"),
                            ("locked", "Pod locked"),
                            ("destroyed", "Destroyed"),
                        ],
                        max_length=20,
                    ),
                ),
                ("detail", models.CharField(blank=True, max_length=255)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="send_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "pod",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="logs",
                        to="privipod.sendpod",
                    ),
                ),
            ],
            options={"ordering": ["-timestamp"], "app_label": "privipod"},
        ),
    ]
