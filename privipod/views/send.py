import hmac
import json
import secrets

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.db import IntegrityError
from django.db.models import F
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.http import require_POST

from .. import config
from ..server import MAX_SIZE_BYTES, MAX_SIZE_MB, SendLog, SendPod, app
from .common import DeadlineFormMixin

# The pod hash is generated before the pod exists because the browser needs it to
# derive key salts; it's signed so the server only accepts hashes it issued.
pod_hash_signer = signing.Signer(salt="privipod.send-pod-hash")


class SendPodCreateForm(DeadlineFormMixin, forms.Form):
    name = forms.CharField(max_length=255, required=False, label="Name")
    recipient_username = forms.ChoiceField(
        choices=[("", "- Anonymous (no account required) -")],
        required=False,
        label="Recipient",
    )
    deadline = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
        label="Expires",
        help_text="Optional",
    )
    self_destruct = forms.BooleanField(
        required=False,
        label="Self-destruct after access",
        help_text="Destroy the secret immediately after it is decrypted",
    )
    encrypted_secret = forms.CharField(widget=forms.HiddenInput(), required=True)
    secret_type = forms.CharField(widget=forms.HiddenInput(), required=True)
    encrypted_filename = forms.CharField(required=False, widget=forms.HiddenInput())
    pod_hash = forms.CharField(widget=forms.HiddenInput(), required=True)
    encrypted_private_key = forms.CharField(required=False, widget=forms.HiddenInput())
    verification_token = forms.CharField(required=False, widget=forms.HiddenInput())
    read_challenge = forms.CharField(required=False, widget=forms.HiddenInput())

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user is not None:
            from django.contrib.auth import get_user_model

            User = get_user_model()
            users = User.objects.exclude(pk=user.pk).order_by("username")
            self.fields["recipient_username"].choices = [
                ("", "- Anonymous (no account required) -"),
            ] + [
                (u.username, f"{u.get_full_name() or u.username} ({u.username})")
                for u in users
            ]

    def clean_pod_hash(self):
        try:
            return pod_hash_signer.unsign(self.cleaned_data["pod_hash"])
        except signing.BadSignature:
            raise forms.ValidationError("Invalid pod hash.")


@app.path("/create/send/", name="send_create")
@login_required
def send_create_view(request):
    from django.contrib.auth import get_user_model

    if request.method == "POST":
        form = SendPodCreateForm(request.POST, user=request.user)
        if "pod_hash" in form.errors:
            # Tampered or stale - the encrypted payload is bound to the hash via its
            # key salts, so it can't be reused with a new one
            messages.error(request, "Invalid pod hash - please try again.")
            return redirect(reverse("send_create"))
        if form.is_valid():
            encrypted_data = form.cleaned_data["encrypted_secret"]

            if len(encrypted_data) > MAX_SIZE_BYTES:
                messages.error(
                    request, f"Encrypted data exceeds maximum size of {MAX_SIZE_MB}MB"
                )
                return redirect(reverse("send_create"))

            try:
                json.loads(encrypted_data)
            except ValueError:
                messages.error(request, "Invalid encrypted data.")
                return redirect(reverse("send_create"))

            enc_fn = form.cleaned_data.get("encrypted_filename")
            if enc_fn:
                try:
                    json.loads(enc_fn)
                except ValueError:
                    messages.error(request, "Invalid encrypted filename.")
                    return redirect(reverse("send_create"))

            recipient = None
            recipient_username = form.cleaned_data.get("recipient_username", "")
            if recipient_username:
                from django.contrib.auth import get_user_model

                try:
                    recipient = get_user_model().objects.get(
                        username=recipient_username
                    )
                except get_user_model().DoesNotExist:
                    messages.error(request, f"User '{recipient_username}' not found.")
                    return redirect(reverse("send_create"))

            pod = SendPod(
                hash=form.cleaned_data["pod_hash"],
                owner=request.user,
                recipient=recipient,
                name=form.cleaned_data.get("name", ""),
                deadline=form.cleaned_data.get("deadline"),
                self_destruct=form.cleaned_data.get("self_destruct", False),
                encrypted_secret=encrypted_data.encode("utf-8"),
                secret_type=form.cleaned_data["secret_type"],
            )
            if enc_fn:
                pod.encrypted_filename = enc_fn.encode("utf-8")

            if not recipient:
                verification_token_hex = form.cleaned_data.get(
                    "verification_token", ""
                ).strip()
                encrypted_priv = form.cleaned_data.get(
                    "encrypted_private_key", ""
                ).strip()
                read_challenge = form.cleaned_data.get("read_challenge", "").strip()

                if (
                    config.allow_server_keys
                    and encrypted_priv
                    and verification_token_hex
                ):
                    try:
                        json.loads(encrypted_priv)
                    except ValueError:
                        messages.error(request, "Invalid encrypted private key.")
                        return redirect(reverse("send_create"))
                    try:
                        pod.verification_token = bytes.fromhex(verification_token_hex)
                    except ValueError:
                        messages.error(request, "Invalid verification token.")
                        return redirect(reverse("send_create"))
                    pod.encrypted_private_key = encrypted_priv.encode("utf-8")
                elif read_challenge and verification_token_hex:
                    # Keyfile-only pod: store the RSA-encrypted challenge and its
                    # expected hash so confirm-read can verify key possession
                    # without the server ever holding the private key.
                    try:
                        json.loads(read_challenge)
                    except ValueError:
                        messages.error(request, "Invalid read challenge.")
                        return redirect(reverse("send_create"))
                    try:
                        pod.verification_token = bytes.fromhex(verification_token_hex)
                    except ValueError:
                        messages.error(request, "Invalid verification token.")
                        return redirect(reverse("send_create"))
                    pod.read_challenge = read_challenge.encode("utf-8")

            try:
                pod.save()
            except IntegrityError:
                messages.error(request, "A hash collision occurred - please try again.")
                return redirect(reverse("send_create"))

            return redirect(reverse("send_view", kwargs={"hash": pod.hash}))

        # Form invalid - re-render
        return app.render(
            request,
            "send_create.html",
            {
                "title": "Send a Secret",
                "form": form,
                "pod_hash": form.cleaned_data["pod_hash"],
                "allow_server_keys": config.allow_server_keys,
            },
        )

    pod_hash = None
    while True:
        pod_hash = secrets.token_urlsafe(32)
        if not SendPod.objects.filter(hash=pod_hash).exists():
            break

    return app.render(
        request,
        "send_create.html",
        {
            "title": "Send a Secret",
            "form": SendPodCreateForm(
                initial={"pod_hash": pod_hash_signer.sign(pod_hash)},
                user=request.user,
            ),
            "pod_hash": pod_hash,
            "allow_server_keys": config.allow_server_keys,
        },
    )


@app.path("/pod/s-<str:hash>/", name="send_view")
def send_view(request, hash):
    try:
        pod = SendPod.objects.get(hash=hash)
    except SendPod.DoesNotExist:
        if not request.user.is_authenticated:
            return redirect(
                f"{reverse('login')}?next={reverse('send_view', kwargs={'hash': hash})}"
            )
        return app.render(request, "pod_not_found.html", {"title": "Pod Not Found"})

    pod.expire()

    is_owner = request.user.is_authenticated and pod.owner == request.user
    is_recipient = (
        request.user.is_authenticated
        and pod.recipient is not None
        and pod.recipient == request.user
    )
    is_anon = pod.recipient is None
    has_server_key = bool(pod.encrypted_private_key)
    log_user = request.user if request.user.is_authenticated else None

    # Authenticated recipient must be logged in
    if not is_anon and not is_owner and not is_recipient:
        if not request.user.is_authenticated:
            return redirect(
                f"{reverse('login')}?next={reverse('send_view', kwargs={'hash': hash})}"
            )
        # Logged in but wrong user
        return app.render(request, "pod_not_found.html", {"title": "Pod Not Found"})

    context = {
        "title": f"Send Pod: {pod.name}" if pod.name else "Send Pod",
        "pod": pod,
        "is_owner": is_owner,
        "is_recipient": is_recipient,
        "is_anon": is_anon,
        "has_server_key": has_server_key,
        "allow_server_keys": config.allow_server_keys,
    }

    # Access-code pods get the secret from send_verify_view
    if (
        (is_recipient or (is_anon and not has_server_key))
        and not is_owner
        and pod.can_access()
    ):
        try:
            context["encrypted_secret_json"] = json.loads(
                pod.encrypted_secret.decode("utf-8")
            )
        except (ValueError, AttributeError):
            messages.error(request, "Stored secret is corrupt and cannot be displayed.")
            return app.render(request, "send_view.html", context)

        if pod.encrypted_filename:
            try:
                context["encrypted_filename_json"] = json.loads(
                    pod.encrypted_filename.decode("utf-8")
                )
            except (ValueError, AttributeError):
                pass

        if is_anon and pod.read_challenge:
            try:
                context["read_challenge_json"] = json.loads(
                    pod.read_challenge.decode("utf-8")
                )
            except (ValueError, AttributeError):
                pass

        SendLog.objects.create(pod=pod, event=SendLog.Event.ACCESSED, user=log_user)

    if is_owner:
        context["logs"] = pod.logs.all()
        context["is_pending"] = pod.status == SendPod.Status.PENDING

    return app.render(request, "send_view.html", context)


@app.path("/pod/s-<str:hash>/status/", name="send_status")
@login_required
def send_status_view(request, hash):
    """
    JSON polling endpoint for the owner to detect when the pod status changes
    """
    try:
        pod = SendPod.objects.get(hash=hash, owner=request.user)
    except SendPod.DoesNotExist:
        return JsonResponse({"status": "not_found"}, status=404)
    pod.expire()
    return JsonResponse({"status": pod.status})


@app.path("/pod/s-<str:hash>/store-key/", name="send_store_key")
@login_required
@require_POST
def send_store_key_view(request, hash):
    """
    Store access-code-wrapped private key on an anonymous send pod
    """
    if not config.allow_server_keys:
        return JsonResponse({"error": "server key storage is disabled"}, status=403)
    try:
        pod = SendPod.objects.get(hash=hash, owner=request.user, recipient=None)
    except SendPod.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)
    pod.expire()
    if pod.status == SendPod.Status.DESTROYED:
        return JsonResponse({"error": "pod destroyed"}, status=409)

    verification_token_hex = request.POST.get("verification_token", "").strip()
    encrypted_private_key = request.POST.get("encrypted_private_key", "").strip()
    if not verification_token_hex or not encrypted_private_key:
        return JsonResponse({"error": "missing fields"}, status=400)

    try:
        token_bytes = bytes.fromhex(verification_token_hex)
    except ValueError:
        return JsonResponse({"error": "invalid verification_token"}, status=400)

    try:
        json.loads(encrypted_private_key)
    except ValueError:
        return JsonResponse({"error": "invalid encrypted_private_key"}, status=400)

    pod.verification_token = token_bytes
    pod.encrypted_private_key = encrypted_private_key.encode("utf-8")
    pod.read_challenge = None  # superseded by the access-code verification_token
    pod.save(
        update_fields=["verification_token", "encrypted_private_key", "read_challenge"]
    )
    messages.success(request, "Key saved to server.")
    return JsonResponse({"status": "ok"})


@app.path("/pod/s-<str:hash>/verify/", name="send_verify")
@require_POST
def send_verify_view(request, hash):
    """
    Verify access code for anonymous send pod

    Return encrypted key and secret on success
    """
    try:
        pod = SendPod.objects.get(hash=hash)
    except SendPod.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)

    pod.expire()
    if not pod.can_access():
        return JsonResponse({"error": "pod not accessible"}, status=403)

    if pod.recipient is not None:
        return JsonResponse({"error": "not an anonymous pod"}, status=400)

    if not pod.verification_token:
        return JsonResponse({"error": "no access code set"}, status=400)

    submitted_hex = request.POST.get("verification_token", "").strip()
    try:
        submitted = bytes.fromhex(submitted_hex)
    except ValueError:
        return JsonResponse({"error": "invalid verification_token"}, status=400)

    stored = bytes(pod.verification_token)
    log_user = request.user if request.user.is_authenticated else None

    if not hmac.compare_digest(stored, submitted):
        # Atomically increment; re-fetch just the count, not the encrypted payloads
        SendPod.objects.filter(pk=pod.pk).update(attempt_count=F("attempt_count") + 1)
        pod.refresh_from_db(fields=["attempt_count"])
        SendLog.objects.create(
            pod=pod,
            event=SendLog.Event.ATTEMPT_FAILED,
            detail=f"attempt {pod.attempt_count}",
            user=log_user,
        )
        if pod.attempt_count >= SendPod.MAX_ATTEMPTS:
            pod.lock()
            SendLog.objects.create(pod=pod, event=SendLog.Event.LOCKED, user=log_user)
            return JsonResponse({"error": "too many attempts - pod locked"}, status=403)
        remaining = SendPod.MAX_ATTEMPTS - pod.attempt_count
        return JsonResponse(
            {"error": "incorrect access code", "remaining": remaining}, status=403
        )

    # Success - reset attempt counter and log
    SendPod.objects.filter(pk=pod.pk).update(attempt_count=0)
    SendLog.objects.create(pod=pod, event=SendLog.Event.ACCESSED, user=log_user)

    try:
        encrypted_secret = json.loads(pod.encrypted_secret.decode("utf-8"))
    except (ValueError, AttributeError):
        return JsonResponse({"error": "corrupt secret"}, status=500)

    data = {
        "status": "ok",
        "encrypted_secret": encrypted_secret,
        "secret_type": pod.secret_type,
        "encrypted_private_key": (
            pod.encrypted_private_key.decode("utf-8")
            if pod.encrypted_private_key
            else None
        ),
    }
    if pod.encrypted_filename:
        try:
            data["encrypted_filename"] = json.loads(
                pod.encrypted_filename.decode("utf-8")
            )
        except (ValueError, AttributeError):
            pass

    return JsonResponse(data)


@app.path("/pod/s-<str:hash>/confirm-read/", name="send_confirm_read")
@require_POST
def send_confirm_read_view(request, hash):
    """
    Called by JS after successful client-side decrypt of a send pod
    """
    try:
        pod = SendPod.objects.get(hash=hash)
    except SendPod.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)
    pod.expire()
    if not pod.can_access():
        return JsonResponse({"error": "not found"}, status=404)

    log_user = request.user if request.user.is_authenticated else None

    if pod.recipient is not None:
        # Authenticated recipient pod
        if not request.user.is_authenticated or request.user != pod.recipient:
            return JsonResponse({"error": "forbidden"}, status=403)

    elif pod.verification_token:
        # Anonymous pod: require proof of key before performing self-destruct
        submitted_hex = request.POST.get("verification_token", "").strip()
        try:
            submitted = bytes.fromhex(submitted_hex)
        except ValueError:
            return JsonResponse({"error": "invalid verification_token"}, status=400)
        if not hmac.compare_digest(bytes(pod.verification_token), submitted):
            return JsonResponse({"error": "forbidden"}, status=403)

    else:
        # Anonymous pod with no verification_token or access code, so there's no way to
        # prove ownership. Should be impossible, but then they said that about flying
        return JsonResponse({"error": "forbidden"}, status=403)

    SendLog.objects.create(pod=pod, event=SendLog.Event.DECRYPTED, user=log_user)

    if pod.status == SendPod.Status.READ:
        # Already read - nothing more to do
        return JsonResponse({"status": "ok"})

    if pod.self_destruct:
        pod.destroy()
        SendLog.objects.create(
            pod=pod,
            event=SendLog.Event.DESTROYED,
            detail="self-destruct",
            user=log_user,
        )
    else:
        pod.status = SendPod.Status.READ
        pod.save(update_fields=["status"])

    return JsonResponse({"status": "ok"})


@app.path("/pod/s-<str:hash>/delete/", name="send_delete")
@login_required
@require_POST
def send_delete_view(request, hash):
    try:
        pod = SendPod.objects.get(hash=hash, owner=request.user)
    except SendPod.DoesNotExist:
        messages.error(request, "Send pod not found.")
        return redirect(reverse("dashboard"))
    pod_name = pod.name or hash[:8]
    pod.delete()
    messages.success(request, f"Send pod '{pod_name}' deleted.")
    return redirect(reverse("dashboard"))


@app.path("/pod/s-<str:hash>/unlock/", name="send_unlock")
@login_required
@require_POST
def send_unlock_view(request, hash):
    try:
        pod = SendPod.objects.get(
            hash=hash, owner=request.user, status=SendPod.Status.LOCKED
        )
    except SendPod.DoesNotExist:
        messages.error(request, "Send pod not found or not locked.")
        return redirect(reverse("dashboard"))
    if pod.expire():
        messages.error(request, "Pod has expired and its secret has been destroyed.")
        return redirect(reverse("send_view", kwargs={"hash": hash}))
    pod.unlock()
    messages.success(request, "Pod unlocked - the recipient can try again.")
    return redirect(reverse("send_view", kwargs={"hash": hash}))
