import json
import secrets

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.http import require_POST

from .. import config
from ..server import MAX_SIZE_BYTES, MAX_SIZE_MB, ReceiveLog, ReceivePod, app
from .common import DeadlineFormMixin


class ReceivePodCreateForm(DeadlineFormMixin, forms.ModelForm):
    class Meta:
        model = ReceivePod
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
            "self_destruct": "Destroy the secret immediately after it is decrypted",
        }


class SendSecretForm(forms.Form):
    encrypted_data = forms.CharField(widget=forms.HiddenInput(), required=True)
    secret_type = forms.CharField(widget=forms.HiddenInput(), required=True)
    encrypted_filename = forms.CharField(required=False, widget=forms.HiddenInput())


@app.path("/create/receive/", name="pod_create")
@login_required
def pod_create_view(request):
    if request.method == "POST":
        form = ReceivePodCreateForm(request.POST)
        if form.is_valid():
            pod = form.save(commit=False)
            pod.owner = request.user
            while True:
                pod.hash = secrets.token_urlsafe(32)
                if not ReceivePod.objects.filter(hash=pod.hash).exists():
                    break
            pod.save()
            return redirect(reverse("pod_view", kwargs={"hash": pod.hash}))

        return app.render(
            request,
            "receive_create.html",
            {
                "title": "Receive a Secret",
                "form": form,
            },
        )

    return app.render(
        request,
        "receive_create.html",
        {
            "title": "Receive a Secret",
            "form": ReceivePodCreateForm(),
        },
    )


@app.path("/pod/r-<str:hash>/", name="pod_view")
def pod_view(request, hash):
    try:
        pod = ReceivePod.objects.get(hash=hash)
    except ReceivePod.DoesNotExist:
        if not request.user.is_authenticated:
            return redirect(
                f"{reverse('login')}?next={reverse('pod_view', kwargs={'hash': hash})}"
            )
        return app.render(request, "pod_not_found.html", {"title": "Pod Not Found"})

    pod.expire()

    is_owner = request.user.is_authenticated and pod.owner == request.user

    if pod.require_sender_auth and not is_owner and not request.user.is_authenticated:
        return redirect(
            f"{reverse('login')}?next={reverse('pod_view', kwargs={'hash': hash})}"
        )

    context = {
        "title": f"Pod: {pod.name}",
        "pod": pod,
        "is_owner": is_owner,
        "allow_server_keys": config.allow_server_keys,
    }

    show_send_form = is_owner and "send" in request.GET and pod.can_send()

    if is_owner:
        context["has_server_key"] = bool(pod.encrypted_private_key)
        context["logs"] = pod.logs.all()

    if is_owner and pod.status == ReceivePod.Status.RECEIVED:
        try:
            context["encrypted_secret_json"] = json.loads(
                pod.encrypted_secret.decode("utf-8")
            )
        except (ValueError, AttributeError):
            messages.error(request, "Stored secret is corrupt and cannot be displayed.")
            return app.render(request, "receive_view.html", context)
        if pod.encrypted_filename:
            try:
                context["encrypted_filename_json"] = json.loads(
                    pod.encrypted_filename.decode("utf-8")
                )
            except (ValueError, AttributeError):
                pass
        ReceiveLog.objects.create(
            pod=pod, event=ReceiveLog.Event.ACCESSED, user=request.user
        )

    if (not is_owner or show_send_form) and pod.can_send():
        try:
            context["public_key_json"] = json.loads(pod.public_key)
        except (ValueError, AttributeError):
            messages.error(request, "Pod public key is corrupt.")
            return redirect(reverse("dashboard"))
        context["send_form"] = SendSecretForm()
        context["show_send_form"] = show_send_form

    if request.method == "POST" and (not is_owner or show_send_form) and pod.can_send():
        send_form = SendSecretForm(request.POST)
        if send_form.is_valid():
            encrypted_data = send_form.cleaned_data["encrypted_data"]

            if len(encrypted_data) > MAX_SIZE_BYTES:
                messages.error(
                    request,
                    f"Encrypted data exceeds maximum size of {MAX_SIZE_MB}MB",
                )
                return redirect(reverse("pod_view", kwargs={"hash": hash}))

            try:
                json.loads(encrypted_data)
            except ValueError:
                messages.error(request, "Invalid encrypted data.")
                return redirect(reverse("pod_view", kwargs={"hash": hash}))

            enc_fn = send_form.cleaned_data.get("encrypted_filename")
            if enc_fn:
                try:
                    json.loads(enc_fn)
                except ValueError:
                    messages.error(request, "Invalid encrypted filename.")
                    return redirect(reverse("pod_view", kwargs={"hash": hash}))

            update_fields = {
                "encrypted_secret": encrypted_data.encode("utf-8"),
                "secret_type": send_form.cleaned_data["secret_type"],
                "status": ReceivePod.Status.RECEIVED,
            }
            if enc_fn:
                update_fields["encrypted_filename"] = enc_fn.encode("utf-8")
            if not ReceivePod.objects.filter(
                hash=hash, status=ReceivePod.Status.PENDING
            ).update(**update_fields):
                messages.error(request, "A secret has already been sent to this pod.")
                return redirect(reverse("pod_view", kwargs={"hash": hash}))

            return redirect(reverse("pod_view", kwargs={"hash": hash}))

    return app.render(request, "receive_view.html", context)


@app.path("/pod/r-<str:hash>/delete/", name="pod_delete")
@login_required
@require_POST
def pod_delete_view(request, hash):
    try:
        pod = ReceivePod.objects.get(hash=hash, owner=request.user)
    except ReceivePod.DoesNotExist:
        messages.error(request, "Pod not found.")
        return redirect(reverse("dashboard"))
    pod_name = pod.name or hash[:8]
    pod.delete()
    messages.success(request, f"Pod '{pod_name}' deleted.")
    return redirect(reverse("dashboard"))


@app.path("/pod/r-<str:hash>/confirm-read/", name="pod_confirm_read")
@login_required
@require_POST
def pod_confirm_read_view(request, hash):
    """
    Confirm decryption
    """
    try:
        pod = ReceivePod.objects.get(hash=hash, owner=request.user)
    except ReceivePod.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)
    pod.expire()
    if pod.status != ReceivePod.Status.RECEIVED:
        return JsonResponse({"error": "not found"}, status=404)
    ReceiveLog.objects.create(
        pod=pod, event=ReceiveLog.Event.DECRYPTED, user=request.user
    )
    if pod.self_destruct:
        pod.destroy()
        ReceiveLog.objects.create(
            pod=pod,
            event=ReceiveLog.Event.DESTROYED,
            detail="self-destruct",
            user=request.user,
        )
    return JsonResponse({"status": "ok"})


@app.path("/pod/r-<str:hash>/store-key/", name="pod_store_key")
@login_required
@require_POST
def pod_store_key_view(request, hash):
    """
    Store encrypted private key for a receive pod
    """
    if not config.allow_server_keys:
        return JsonResponse({"error": "server key storage is disabled"}, status=403)
    try:
        pod = ReceivePod.objects.get(hash=hash, owner=request.user)
    except ReceivePod.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)
    pod.expire()
    if pod.status == ReceivePod.Status.DESTROYED:
        return JsonResponse({"error": "pod destroyed"}, status=409)

    encrypted_private_key = request.POST.get("encrypted_private_key", "").strip()
    if not encrypted_private_key:
        return JsonResponse({"error": "missing encrypted_private_key"}, status=400)

    # Validate it's valid base64-ish JSON (the wrapped key blob)
    try:
        json.loads(encrypted_private_key)
    except ValueError:
        return JsonResponse({"error": "invalid encrypted_private_key"}, status=400)

    pod.encrypted_private_key = encrypted_private_key.encode("utf-8")
    pod.save(update_fields=["encrypted_private_key"])
    messages.success(request, "Key saved to server.")
    return JsonResponse({"status": "ok"})


@app.path("/pod/r-<str:hash>/get-key/", name="pod_get_key")
@login_required
def pod_get_key_view(request, hash):
    """
    Retrieve encrypted private key for a receive pod
    """
    try:
        pod = ReceivePod.objects.get(hash=hash, owner=request.user)
    except ReceivePod.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)
    pod.expire()
    if not pod.encrypted_private_key:
        return JsonResponse({"encrypted_private_key": None})
    return JsonResponse(
        {"encrypted_private_key": pod.encrypted_private_key.decode("utf-8")}
    )


@app.path("/pod/r-<str:hash>/remove-key/", name="pod_remove_key")
@login_required
@require_POST
def pod_remove_key_view(request, hash):
    """
    Remove stored private key for a receive pod
    """
    try:
        pod = ReceivePod.objects.get(hash=hash, owner=request.user)
    except ReceivePod.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)
    pod.expire()
    if pod.status == ReceivePod.Status.DESTROYED:
        return JsonResponse({"error": "pod destroyed"}, status=409)
    pod.encrypted_private_key = None
    pod.save(update_fields=["encrypted_private_key"])
    return JsonResponse({"status": "ok"})


@app.path("/pod/r-<str:hash>/status/", name="pod_status")
@login_required
def pod_status_view(request, hash):
    """
    JSON polling endpoint for the owner to detect when the pod status changes
    """
    try:
        pod = ReceivePod.objects.get(hash=hash, owner=request.user)
    except ReceivePod.DoesNotExist:
        return JsonResponse({"status": "not_found"}, status=404)
    pod.expire()
    return JsonResponse({"status": pod.status})
