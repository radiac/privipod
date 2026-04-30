# Project muist be configured in privipod.config before importing this module
import asyncio
import json
import os
import secrets

from django import forms
from django.contrib import messages
from django.db import models
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils import timezone as django_timezone
from django_style import Nav
from nanodjango import Django, defer

with defer:
    from django.contrib.auth.decorators import login_required
    from django.contrib.auth.views import LoginView, LogoutView

from . import config

MAX_SIZE_MB = config.max_size_mb
MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024
SQLITE_DATABASE = os.path.abspath(config.store) if config.store else Django.SQLITE_TMP


def setting_middleware(MIDDLEWARE):
    MIDDLEWARE.append("privipod.server.CSPMiddleware")
    return MIDDLEWARE


def setting_templates(TEMPLATES):
    TEMPLATES[0]["OPTIONS"]["context_processors"].append("privipod.server.context_site")
    return TEMPLATES


allowed_hosts = config.hostnames or ["*"]
trusted_origins = [f"https://{h}" for h in config.hostnames]

app = Django(
    APP_NAME="privipod",
    SQLITE_DATABASE=SQLITE_DATABASE,
    LOGIN_REDIRECT_URL="/",
    LOGIN_URL="/login",
    DEBUG=config.debug,
    MIDDLEWARE=setting_middleware,
    TEMPLATES=setting_templates,
    ALLOWED_HOSTS=allowed_hosts,
    CSRF_TRUSTED_ORIGINS=trusted_origins,
    SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    # 2× gives headroom for encrypted payloads (~1.42× raw) from files moderately over the limit
    DATA_UPLOAD_MAX_MEMORY_SIZE=int(MAX_SIZE_BYTES * 2),
)


@app.admin
class Pod(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SENT = "sent", "Sent"

    class SecretType(models.TextChoices):
        TEXT = "text", "Text"
        FILE = "file", "File"

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

    class Meta:
        ordering = ["-created_at"]
        app_label = "privipod"

    def __str__(self):
        return f"Pod {self.name} ({self.status})"

    def is_expired(self):
        """Check if pod has passed its deadline"""
        if self.deadline is None:
            return False
        return django_timezone.now() > self.deadline

    def can_send(self):
        """Check if secret can be sent to this pod"""
        return self.status == self.Status.PENDING and not self.is_expired()


# Forms
class PodCreateForm(forms.ModelForm):
    class Meta:
        model = Pod
        fields = [
            "name",
            "deadline",
            "require_sender_auth",
            "self_destruct",
            "public_key",
        ]
        widgets = {
            "public_key": forms.HiddenInput(),
            "deadline": forms.DateTimeInput(attrs={"type": "datetime-local"}),
        }
        help_texts = {
            "deadline": "Optional: When this pod should expire",
            "require_sender_auth": "The sender needs to be logged in",
            "self_destruct": "Delete pod immediately after secret is retrieved",
        }


class SendSecretForm(forms.Form):
    encrypted_data = forms.CharField(widget=forms.HiddenInput(), required=True)
    secret_type = forms.CharField(widget=forms.HiddenInput(), required=True)
    encrypted_filename = forms.CharField(required=False, widget=forms.HiddenInput())


# Register auth URLs
app.path("login/", name="login")(LoginView.as_view(extra_context={"title": "Login"}))
app.path("logout/", name="logout")(LogoutView.as_view(next_page=reverse_lazy("login")))


def context_site(request) -> dict:
    if request.user.is_authenticated:
        nav = [
            Nav("Your Pods", "dashboard"),
            Nav("Create Pod", "pod_create"),
            Nav("Logout", "logout"),
        ]

    else:
        nav = [
            Nav("Login", "login"),
        ]

    return {"site_title": "Privipod", "site_nav": nav}


class CSPMiddleware:
    """Add Content-Security-Policy header (not provided by Django's built-in middleware)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        return response


# Views
@app.route("/", name="dashboard")
@login_required
def dashboard(request):
    pods = Pod.objects.filter(owner=request.user)
    return app.render(request, "dashboard.html", {"title": "Your Pods", "pods": pods})


@app.route("/pod/create/", name="pod_create")
@login_required
def pod_create_view(request):
    if request.method == "POST":
        hash = request.POST.get("hash", "")
        form = PodCreateForm(request.POST)
        if form.is_valid() and hash:
            pod = form.save(commit=False)
            pod.owner = request.user
            pod.hash = hash
            pod.save()
            return redirect(reverse("pod_view", kwargs={"hash": hash}))
        return app.render(
            request,
            "pod_create.html",
            {"title": "Create a Pod", "form": form, "hash": hash},
        )

    while True:
        hash = secrets.token_urlsafe(32)
        if not Pod.objects.filter(hash=hash).exists():
            break
    return app.render(
        request,
        "pod_create.html",
        {"title": "Create a Pod", "form": PodCreateForm(), "hash": hash},
    )


@app.route("/pod/<str:hash>/", name="pod_view")
def pod_view(request, hash):
    try:
        pod = Pod.objects.get(hash=hash)
    except Pod.DoesNotExist:
        if not request.user.is_authenticated:
            return redirect(
                f"{reverse('login')}?next={reverse('pod_view', kwargs={'hash': hash})}"
            )
        return app.render(request, "pod_not_found.html", {"title": "Pod Not Found"})

    # Check if expired
    if pod.is_expired():
        return app.render(
            request,
            "pod_view.html",
            {
                "pod": pod,
                "is_owner": False,
            },
        )

    is_owner = request.user.is_authenticated and pod.owner == request.user

    # Check sender authentication requirement
    if pod.require_sender_auth and not is_owner and not request.user.is_authenticated:
        return redirect(
            f"{reverse('login')}?next={reverse('pod_view', kwargs={'hash': hash})}"
        )

    context = {
        "title": f"Pod: {pod.name}",
        "pod": pod,
        "is_owner": is_owner,
    }

    # Check if owner wants to send to themselves
    show_send_form = is_owner and "send" in request.GET and pod.can_send()

    if is_owner and pod.status == Pod.Status.SENT:
        # Embed encrypted secret for recipient to decrypt (parse to dict so json_script works)
        context["encrypted_secret_json"] = json.loads(
            pod.encrypted_secret.decode("utf-8")
        )
        if pod.encrypted_filename:
            context["encrypted_filename_json"] = json.loads(
                pod.encrypted_filename.decode("utf-8")
            )

        # Self-destruct: delete pod after owner views the secret
        if pod.self_destruct:
            pod.delete()

    if (not is_owner or show_send_form) and pod.can_send():
        # Embed public key for sender to encrypt with (parse to dict so json_script works)
        context["public_key_json"] = json.loads(pod.public_key)
        context["send_form"] = SendSecretForm()
        context["show_send_form"] = show_send_form

    if request.method == "POST" and (not is_owner or show_send_form) and pod.can_send():
        send_form = SendSecretForm(request.POST)
        if send_form.is_valid():
            encrypted_data = send_form.cleaned_data["encrypted_data"]

            # Check size
            if len(encrypted_data) > MAX_SIZE_BYTES:
                messages.error(
                    request,
                    f"Encrypted data exceeds maximum size of {MAX_SIZE_MB}MB",
                )
                return redirect(reverse("pod_view", kwargs={"hash": hash}))

            # Store encrypted secret
            pod.encrypted_secret = encrypted_data.encode("utf-8")
            pod.secret_type = send_form.cleaned_data["secret_type"]
            if enc_fn := send_form.cleaned_data.get("encrypted_filename"):
                pod.encrypted_filename = enc_fn.encode("utf-8")
            pod.status = Pod.Status.SENT
            pod.save()

            return redirect(reverse("pod_view", kwargs={"hash": hash}))

    return app.render(request, "pod_view.html", context)


@app.route("/pod/<str:hash>/status/", name="pod_status")
def pod_status_view(request, hash):
    """JSON polling endpoint for the owner to detect when a secret has been sent."""
    if not request.user.is_authenticated:
        return JsonResponse({"status": "auth_required"}, status=403)
    try:
        pod = Pod.objects.get(hash=hash, owner=request.user)
    except Pod.DoesNotExist:
        return JsonResponse({"status": "not_found"}, status=404)

    if pod.status != Pod.Status.SENT or pod.self_destruct:
        return JsonResponse({"status": "pending"})

    data = {
        "status": "sent",
        "encrypted_secret": json.loads(pod.encrypted_secret.decode("utf-8")),
        "secret_type": pod.secret_type,
    }
    if pod.encrypted_filename:
        data["encrypted_filename"] = json.loads(pod.encrypted_filename.decode("utf-8"))
    return JsonResponse(data)


# Background cleanup task
async def cleanup_expired_pods():
    """Periodically delete expired pods"""
    while True:
        await asyncio.sleep(300)  # Run every 5 minutes

        now = django_timezone.now()
        # Use async ORM methods
        count = await Pod.objects.filter(
            deadline__isnull=False, deadline__lt=now
        ).acount()
        if count > 0:
            await Pod.objects.filter(deadline__isnull=False, deadline__lt=now).adelete()
            print(f"Deleted {count} expired pod(s)")


def main():
    """
    Run privipod

    If running in debug then does not clean up expired pods
    """
    print("Starting Privipod...")
    print(
        f"Storage mode: {f'disk ({SQLITE_DATABASE})' if config.store else 'in-memory'}"
    )
    print(f"Max upload size: {MAX_SIZE_MB}MB")

    if config.debug:
        app.run(config.address, username=config.user, password=config.password)
        return

    # Create event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    loop.create_task(
        app.create_server(
            config.address,
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
        print("\nShutting down...")
