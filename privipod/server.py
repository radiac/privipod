# Project must be configured in privipod.config before importing this module
import asyncio
import logging
import os

from asgiref.sync import sync_to_async
from django.core.management.utils import get_random_secret_key
from django.db import models
from django.utils import timezone as django_timezone
from django_style import Nav
from nanodjango import Django

from . import config

logger = logging.getLogger(__name__)

MAX_SIZE_MB = config.max_size_mb
MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024
SQLITE_DATABASE = os.path.abspath(config.store) if config.store else Django.SQLITE_TMP


def setting_middleware(MIDDLEWARE):
    MIDDLEWARE.append("privipod.server.CSPMiddleware")
    return MIDDLEWARE


def setting_templates(TEMPLATES):
    TEMPLATES[0]["OPTIONS"]["context_processors"].append("privipod.server.context_site")
    return TEMPLATES


deployed = bool(config.hostnames)
allowed_hosts = config.hostnames or ["*"]
trusted_origins = [f"https://{h}" for h in config.hostnames]

secret_key = config.secret_key
if not secret_key:
    secret_key = get_random_secret_key()
    logger.warning("No secret key set, generating one instead - see docs for details")

app = Django(
    APP_NAME="privipod",
    SQLITE_DATABASE=SQLITE_DATABASE,
    SECRET_KEY=secret_key,
    LOGIN_REDIRECT_URL="/",
    LOGIN_URL="/login",
    DEBUG=config.debug,
    MIDDLEWARE=setting_middleware,
    TEMPLATES=setting_templates,
    ALLOWED_HOSTS=allowed_hosts,
    CSRF_TRUSTED_ORIGINS=trusted_origins,
    # Safe in both modes: app port is never internet-reachable directly
    SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    # Always True: app requires HTTPS or localhost (a browser secure context)
    SESSION_COOKIE_SECURE=True,
    CSRF_COOKIE_SECURE=True,
    # HSTS only in deployed mode; start at 1 hour, we may want to increase this later
    SECURE_HSTS_SECONDS=3600 if deployed else 0,
    SECURE_HSTS_INCLUDE_SUBDOMAINS=False,
    SECURE_HSTS_PRELOAD=False,
    # 2× gives headroom for encrypted payloads (~1.42× raw) from files moderately over the limit
    DATA_UPLOAD_MAX_MEMORY_SIZE=int(MAX_SIZE_BYTES * 2),
)


def context_site(request) -> dict:
    if request.user.is_authenticated:
        nav = [
            Nav("Your Pods", "dashboard"),
            Nav("Receive Secret", "pod_create"),
            Nav("Send Secret", "send_create"),
            Nav("Manage Keys", "manage_keys"),
            Nav("Logout", "logout"),
        ]
    else:
        nav = [
            Nav("Login", "login"),
        ]
    return {
        "site_title": "Privipod",
        "site_nav": nav,
    }


class CSPMiddleware:
    """
    Content-Security-Policy header
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        return response


class BasePod(models.Model):
    """
    Common pod functionality

    * Expiry/destroy
    """

    DESTROY_FIELDS: tuple = ()

    class Meta:
        abstract = True

    def is_expired(self):
        if self.deadline is None:
            return False
        return django_timezone.now() > self.deadline

    def destroy(self, status=None):
        if status is None:
            status = self.Status.DESTROYED
        for field in self.DESTROY_FIELDS:
            setattr(self, field, None)
        self.status = status
        self.save()

    def expire(self):
        """
        Destroy and log the pod if it is past its deadline
        """
        if not self.is_expired() or self.status == self.Status.DESTROYED:
            return False

        # Prep destroyed values
        destroy_values = {field: None for field in self.DESTROY_FIELDS}

        # Ensure we only destroy once in the event of a race condition
        updated = (
            type(self)
            .objects.filter(pk=self.pk)
            .exclude(status=self.Status.DESTROYED)
            .update(status=self.Status.DESTROYED, **destroy_values)
        )

        # Clear in memory
        for field, value in destroy_values.items():
            setattr(self, field, value)
        self.status = self.Status.DESTROYED

        if not updated:
            return False
        self.logs.create(event=self.logs.model.Event.DESTROYED, detail="expired")
        return True


@app.admin
class ReceivePod(BasePod):
    class Status(models.TextChoices):
        PENDING = "pending", "Waiting for secret"
        RECEIVED = "received", "Secret received"
        DESTROYED = "destroyed", "Destroyed"

    class SecretType(models.TextChoices):
        TEXT = "text", "Text"
        FILE = "file", "File"

    DESTROY_FIELDS = ("encrypted_secret", "encrypted_filename", "encrypted_private_key")

    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    name = models.CharField(
        max_length=255,
        blank=True,
        help_text="Descriptive name for the pod",
    )
    hash = models.CharField(max_length=64, unique=True, db_index=True)
    public_key = models.TextField()
    deadline = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True
    )
    encrypted_secret = models.BinaryField(null=True, blank=True)
    secret_type = models.CharField(
        max_length=10, choices=SecretType.choices, default=SecretType.TEXT, blank=True
    )
    encrypted_filename = models.BinaryField(null=True, blank=True)
    require_sender_auth = models.BooleanField(default=False)
    self_destruct = models.BooleanField(default=False)
    encrypted_private_key = models.BinaryField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        app_label = "privipod"

    def __str__(self):
        return f"ReceivePod {self.name} ({self.status})"

    def can_send(self):
        return self.status == self.Status.PENDING and not self.is_expired()


@app.admin
class UserProfile(models.Model):
    user = models.OneToOneField(
        "auth.User", on_delete=models.CASCADE, related_name="privipod_profile"
    )
    identity_public_key = models.TextField(blank=True)
    encrypted_identity_private_key = models.BinaryField(null=True, blank=True)
    identity_key_salt = models.BinaryField(null=True, blank=True)
    # True once the user has dismissed the dashboard identity-key banner
    onboarding = models.BooleanField(default=False)

    class Meta:
        app_label = "privipod"

    def __str__(self):
        return f"UserProfile({self.user.username})"


@app.admin
class SendPod(BasePod):
    class Status(models.TextChoices):
        PENDING = "pending", "Waiting to be decrypted"
        READ = "read", "Secret decrypted"
        LOCKED = "locked", "Locked - too many attempts"
        DESTROYED = "destroyed", "Destroyed"

    class SecretType(models.TextChoices):
        TEXT = "text", "Text"
        FILE = "file", "File"

    MAX_ATTEMPTS = 5

    owner = models.ForeignKey(
        "auth.User", on_delete=models.CASCADE, related_name="sent_pods"
    )
    recipient = models.ForeignKey(
        "auth.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="received_send_pods",
    )
    name = models.CharField(max_length=255, blank=True)
    hash = models.CharField(max_length=64, unique=True, db_index=True)
    deadline = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True
    )
    encrypted_secret = models.BinaryField(null=True, blank=True)
    secret_type = models.CharField(
        max_length=10, choices=SecretType.choices, default=SecretType.TEXT, blank=True
    )
    encrypted_filename = models.BinaryField(null=True, blank=True)
    self_destruct = models.BooleanField(default=False)
    # Anonymous pods only:
    encrypted_private_key = models.BinaryField(null=True, blank=True)
    verification_token = models.BinaryField(null=True, blank=True)
    read_challenge = models.BinaryField(null=True, blank=True)
    attempt_count = models.IntegerField(default=0)

    DESTROY_FIELDS = (
        "encrypted_secret",
        "encrypted_filename",
        "encrypted_private_key",
        "verification_token",
        "read_challenge",
    )

    class Meta:
        ordering = ["-created_at"]
        app_label = "privipod"

    def __str__(self):
        return f"SendPod {self.name} ({self.status})"

    def can_access(self):
        return (
            self.status in (self.Status.PENDING, self.Status.READ)
            and not self.is_expired()
        )

    def lock(self):
        # Prevent access but leave the secret so it can be unlocked
        self.status = self.Status.LOCKED
        self.save(update_fields=["status"])

    def unlock(self):
        self.status = self.Status.PENDING
        self.attempt_count = 0
        self.save(update_fields=["status", "attempt_count"])


@app.admin
class ReceiveLog(models.Model):
    class Event(models.TextChoices):
        ACCESSED = "accessed", "Secret accessed"
        DECRYPTED = "decrypted", "Secret decrypted"
        DESTROYED = "destroyed", "Destroyed"

    pod = models.ForeignKey(ReceivePod, on_delete=models.CASCADE, related_name="logs")
    user = models.ForeignKey(
        "auth.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="receive_logs",
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    event = models.CharField(max_length=20, choices=Event.choices)
    detail = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-timestamp"]
        app_label = "privipod"

    def __str__(self):
        return f"ReceiveLog {self.event} @ {self.timestamp}"


@app.admin
class SendLog(models.Model):
    # See ReceiveLog for ACCESSED vs DECRYPTED
    class Event(models.TextChoices):
        ATTEMPT_FAILED = "attempt_failed", "Failed access attempt"
        ACCESSED = "accessed", "Secret accessed"
        DECRYPTED = "decrypted", "Secret decrypted"
        LOCKED = "locked", "Pod locked"
        DESTROYED = "destroyed", "Destroyed"

    pod = models.ForeignKey(SendPod, on_delete=models.CASCADE, related_name="logs")
    user = models.ForeignKey(
        "auth.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="send_logs",
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    event = models.CharField(max_length=20, choices=Event.choices)
    detail = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-timestamp"]
        app_label = "privipod"

    def __str__(self):
        return f"SendLog {self.event} @ {self.timestamp}"


async def _cleanup_expired_pods_once():
    """Single sweep: destroy expired pods (wipes secrets, preserves records)."""
    now = django_timezone.now()

    for pod_model, label in ((ReceivePod, "receive"), (SendPod, "send")):
        # Only load what expire() needs - skip the encrypted payloads
        expired = (
            pod_model.objects.filter(deadline__lt=now)
            .exclude(status=pod_model.Status.DESTROYED)
            .only("pk", "deadline", "status")
        )
        count = 0
        async for pod in expired:
            if await sync_to_async(pod.expire)():
                count += 1
        if count > 0:
            logger.info("Destroyed %d expired %s pod(s)", count, label)


async def cleanup_expired_pods():
    """Periodically destroy expired pods (wipes secrets, preserves records)."""
    while True:
        await asyncio.sleep(300)
        await _cleanup_expired_pods_once()


from . import views  # noqa: E402,F401


def main():
    """
    Run privipod

    If running in debug then does not clean up expired pods
    """
    logger.info("Starting Privipod...")
    if deployed:
        logger.info(
            "Running in deployed mode: hostname(s) %s", ", ".join(config.hostnames)
        )
        logger.info(
            "Ensure your reverse proxy strips/overwrites inbound X-Forwarded-* headers."
        )
    else:
        logger.info("Running in untrusted host mode.")
    logger.info(
        "Storage mode: %s", f"disk ({SQLITE_DATABASE})" if config.store else "in-memory"
    )
    logger.info("Max upload size: %dMB", MAX_SIZE_MB)

    if config.debug:
        app.run(
            config.address or "0.0.0.0:8000",
            username=config.user,
            password=config.password,
        )
        return

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    loop.create_task(
        app.create_server(
            config.address or "0.0.0.0:8000",
            log_level="debug" if config.debug else "info",
            is_prod=not config.debug,
            username=config.user,
            password=config.password,
        )
    )
    loop.create_task(cleanup_expired_pods())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
