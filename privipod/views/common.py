import json

from django import forms
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.http import JsonResponse
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.decorators.http import require_POST

from .. import config
from ..server import ReceivePod, SendPod, UserProfile, app


class DeadlineFormMixin:
    def clean_deadline(self):
        """
        Validate an optional pod deadline is in the future.

        The browser converts the user's local time to UTC before submitting - see
        PrivipodUI.deadlinesToUtc()
        """
        deadline = self.cleaned_data.get("deadline")
        if deadline is not None and deadline <= timezone.now():
            raise forms.ValidationError("The deadline must be in the future.")
        return deadline


app.path("login/", name="login")(LoginView.as_view(extra_context={"title": "Login"}))
app.path("logout/", name="logout")(LogoutView.as_view(next_page=reverse_lazy("login")))


@app.path("/health/", name="health")
def health_view(request):
    return JsonResponse({"status": "ok"})


@app.path("/", name="dashboard")
@login_required
def dashboard(request):
    receive_pods = ReceivePod.objects.filter(owner=request.user)
    send_pods = SendPod.objects.filter(owner=request.user)
    try:
        profile = request.user.privipod_profile
        has_identity_key = bool(profile.identity_public_key)
        onboarding = profile.onboarding
    except UserProfile.DoesNotExist:
        has_identity_key = False
        onboarding = False
    return app.render(
        request,
        "dashboard.html",
        {
            "title": "Your Pods",
            "receive_pods": receive_pods,
            "send_pods": send_pods,
            "has_identity_key": has_identity_key,
            "onboarding": onboarding,
            "allow_server_keys": config.allow_server_keys,
        },
    )


@app.path("/identity/remove-private-key/", name="identity_remove_private_key")
@login_required
@require_POST
def identity_remove_private_key_view(request):
    """
    Remove encrypted identity private key from server (keeps public key)
    """
    try:
        profile = request.user.privipod_profile
    except UserProfile.DoesNotExist:
        return JsonResponse({"error": "no profile"}, status=404)
    profile.encrypted_identity_private_key = None
    profile.identity_key_salt = None
    profile.save(update_fields=["encrypted_identity_private_key", "identity_key_salt"])
    return JsonResponse({"status": "ok"})


@app.path("/identity/dismiss-banner/", name="identity_dismiss_banner")
@login_required
@require_POST
def identity_dismiss_banner_view(request):
    """
    Close the dashboard banner
    """
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    profile.onboarding = True
    profile.save(update_fields=["onboarding"])
    return JsonResponse({"status": "ok"})


@app.path("/keys/", name="manage_keys")
@login_required
def manage_keys_view(request):
    """
    Key management
    """
    try:
        profile = request.user.privipod_profile
        has_server_private_key = bool(profile.encrypted_identity_private_key)
        has_identity_key = bool(profile.identity_public_key)
    except UserProfile.DoesNotExist:
        has_server_private_key = False
        has_identity_key = False

    pods = ReceivePod.objects.filter(owner=request.user).order_by("-created_at")
    pending_recipient_count = SendPod.objects.filter(
        recipient=request.user, status=SendPod.Status.PENDING
    ).count()
    return app.render(
        request,
        "manage_keys.html",
        {
            "title": "Manage Keys",
            "has_identity_key": has_identity_key,
            "has_server_private_key": has_server_private_key,
            "pods": pods,
            "allow_server_keys": config.allow_server_keys,
            "pending_recipient_count": pending_recipient_count,
        },
    )


@app.path("/identity/setup/", name="identity_setup")
@login_required
@require_POST
def identity_setup_view(request):
    """
    Store user's identity public key
    """
    if not config.allow_server_keys and request.POST.get(
        "encrypted_identity_private_key"
    ):
        return JsonResponse({"error": "server key storage is disabled"}, status=403)

    identity_public_key = request.POST.get("identity_public_key", "").strip()
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if identity_public_key:
        try:
            json.loads(identity_public_key)
        except ValueError:
            return JsonResponse({"error": "invalid identity_public_key"}, status=400)
        profile.identity_public_key = identity_public_key
    elif not profile.identity_public_key:
        return JsonResponse({"error": "missing identity_public_key"}, status=400)

    encrypted_priv = request.POST.get("encrypted_identity_private_key", "").strip()
    salt = request.POST.get("identity_key_salt", "").strip()
    if encrypted_priv and salt:
        try:
            json.loads(encrypted_priv)
        except ValueError:
            return JsonResponse(
                {"error": "invalid encrypted_identity_private_key"}, status=400
            )
        profile.encrypted_identity_private_key = encrypted_priv.encode("utf-8")
        try:
            profile.identity_key_salt = bytes.fromhex(salt)
        except ValueError:
            return JsonResponse({"error": "invalid identity_key_salt"}, status=400)
        profile.save()
        messages.success(request, "Private key saved to server.")
        return JsonResponse({"status": "ok"})

    profile.save()
    return JsonResponse({"status": "ok"})


@app.path("/identity/get-key/", name="identity_get_key")
@login_required
def identity_get_key_view(request):
    """
    Return encrypted identity private key and salt for the authenticated user
    """
    try:
        profile = request.user.privipod_profile
    except UserProfile.DoesNotExist:
        return JsonResponse(
            {"has_identity_key": False, "encrypted_private_key": None, "salt": None}
        )

    return JsonResponse(
        {
            "has_identity_key": bool(profile.identity_public_key),
            "encrypted_private_key": (
                profile.encrypted_identity_private_key.decode("utf-8")
                if profile.encrypted_identity_private_key
                else None
            ),
            "salt": (
                profile.identity_key_salt.hex() if profile.identity_key_salt else None
            ),
        }
    )


@app.path("/user/<str:username>/public-key/", name="user_public_key")
@login_required
def user_public_key_view(request, username):
    """
    Return a user's identity public key for send pod creation
    """
    User = get_user_model()
    try:
        target = User.objects.get(username=username)
        profile = target.privipod_profile
    except (User.DoesNotExist, UserProfile.DoesNotExist):
        return JsonResponse({"error": "not found"}, status=404)

    if not profile.identity_public_key:
        return JsonResponse({"error": "user has no identity key"}, status=404)

    return JsonResponse({"public_key": json.loads(profile.identity_public_key)})
