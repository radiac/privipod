#!/usr/bin/env python
# /// script
# dependencies = [
#   "nanodjango", "django-style", "django-browser-reload",
# ]
# ///
"""
Privipod - Lightweight encrypted secret transfer service

Usage:
    uv run privipod.py                    # In-memory mode, default port
    uv run privipod.py 8000               # Custom port
    uv run privipod.py localhost:8000     # Custom host and port
    uv run privipod.py --store=privipod.db  # Path to database on disk
    uv run privipod.py --max-size=50      # Set max upload size (MB)
    uv run privipod.py --user=admin --pass=mypass
"""

import argparse
import asyncio
import json
import os
import secrets

from django import forms
from django.db import models
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils import timezone as django_timezone
from django_style import Nav
from nanodjango import Django, defer

with defer:
    from django.contrib.auth.decorators import login_required
    from django.contrib.auth.views import LoginView, LogoutView


# Configuration defaults
MAX_SIZE_MB = 10
MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024
SQLITE_DATABASE = Django.SQLITE_TMP

# Parse CLI arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Privipod - Encrypted secret transfer")
    parser.add_argument(
        "address",
        nargs="?",
        default=None,
        help="Optional address in format [host:]port (eg, 8000, 0.0.0.0:5000)",
    )
    parser.add_argument(
        "--store",
        metavar="PATH",
        help="Path to SQLite database file for disk persistence",
    )
    parser.add_argument(
        "--max-size", type=int, default=MAX_SIZE_MB, help="Max upload size in MB"
    )
    parser.add_argument("--user", type=str, help="Username for login")
    parser.add_argument("--pass", dest="password", type=str, help="Password for user")
    parser.add_argument("--debug", action="store_true", help="Debug mode, for devs")
    parser.add_argument(
        "--hostname",
        action="append",
        dest="hostnames",
        metavar="HOST",
        help="Allowed hostname (eg, example.com); can be repeated. Defaults to any.",
    )
    args = parser.parse_args()

    # Update configuration from args
    MAX_SIZE_MB = args.max_size
    MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024
    if args.store:
        SQLITE_DATABASE = os.path.abspath(args.store)


def setting_middleware(MIDDLEWARE):
    MIDDLEWARE.append("privipod.CSPMiddleware")
    return MIDDLEWARE


def setting_templates(TEMPLATES):
    TEMPLATES[0]["OPTIONS"]["context_processors"].append("privipod.context_site")
    return TEMPLATES


allowed_hosts = args.hostnames or ["*"]
trusted_origins = [f"https://{h}" for h in args.hostnames] if args.hostnames else []

app = Django(
    SQLITE_DATABASE=SQLITE_DATABASE,
    LOGIN_REDIRECT_URL="/",
    LOGIN_URL="/login",
    DEBUG=args.debug,
    MIDDLEWARE=setting_middleware,
    TEMPLATES=setting_templates,
    ALLOWED_HOSTS=allowed_hosts,
    CSRF_TRUSTED_ORIGINS=trusted_origins,
    SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
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
    original_filename = models.CharField(max_length=255, null=True, blank=True)
    require_sender_auth = models.BooleanField(default=False)
    self_destruct = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

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
    original_filename = forms.CharField(required=False, widget=forms.HiddenInput())


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
        print(f"Host: {request.get_host()}, Origin: {request.META.get('HTTP_ORIGIN')}")
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
    # Just generate hash and redirect to pod view
    hash = secrets.token_urlsafe(32)
    return redirect(reverse("pod_view", kwargs={"hash": hash}))


@app.route("/pod/<str:hash>/", name="pod_view")
def pod_view(request, hash):
    try:
        pod = Pod.objects.get(hash=hash)
    except Pod.DoesNotExist:
        # Pod doesn't exist yet - show create form if user is authenticated
        if not request.user.is_authenticated:
            return redirect(
                f"{reverse('login')}?next={reverse('pod_view', kwargs={'hash': hash})}"
            )

        if request.method == "POST":
            # Create the pod
            form = PodCreateForm(request.POST)
            if form.is_valid():
                pod = form.save(commit=False)
                pod.owner = request.user
                pod.hash = hash
                pod.save()
                return redirect(reverse("pod_view", kwargs={"hash": hash}))
        else:
            form = PodCreateForm()

        return app.render(
            request,
            "pod_create.html",
            {"title": "Create a Pod", "form": form, "hash": hash},
        )

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
                context["error"] = (
                    f"Encrypted data exceeds maximum size of {MAX_SIZE_MB}MB"
                )
                return app.render(request, "pod_view.html", context)

            # Store encrypted secret
            pod.encrypted_secret = encrypted_data.encode("utf-8")
            pod.secret_type = send_form.cleaned_data["secret_type"]
            pod.original_filename = send_form.cleaned_data.get("original_filename", "")
            pod.status = Pod.Status.SENT
            pod.save()

            return redirect(reverse("pod_view", kwargs={"hash": hash}))

    return app.render(request, "pod_view.html", context)


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
    print(f"Storage mode: {f'disk ({SQLITE_DATABASE})' if args.store else 'in-memory'}")
    print(f"Max upload size: {MAX_SIZE_MB}MB")

    if args.debug:
        app.run(args.address)
        return

    # Create event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    loop.create_task(
        app.create_server(
            args.address,
            log_level="debug",
            is_prod=False,
        )
    )
    loop.create_task(cleanup_expired_pods())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")


# Templates
app.templates["app.html"] = """{% extends "base.html" %}

{% block extra_head %}
<style>
    :root {
        --colour-primary: #2c3e50;
    }
    .message { padding: 15px; margin: 15px 0; border-radius: 4px; }
    .message.info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
    .message.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    .message.warning { background: #fff3cd; color: #856404; border: 1px solid #f5c6cb; }
    .message.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    .loading { opacity: 0.6; pointer-events: none; }

    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
    }
    th, td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #ddd;
    }
    th { background: #ecf0f1; font-weight: 600; }

    .pod-url {
        background: #ecf0f1;
        padding: 15px;
        border-radius: 4px;
        margin: 15px 0;
        font-family: monospace;
        word-break: break-all;
    }
    .secret-display {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 4px;
        margin: 15px 0;
        border: 1px solid #dee2e6;
    }
</style>

<script>
const PrivipodCrypto = {
    async generateKeyPair() {
        return await crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Export any CryptoKey to JWK object
    async exportKey(key) {
        return await crypto.subtle.exportKey("jwk", key);
    },

    async importPublicKey(jwk) {
        return await crypto.subtle.importKey(
            "jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
        );
    },

    async importPrivateKey(jwk) {
        return await crypto.subtle.importKey(
            "jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]
        );
    },

    base64ToBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    },

    bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    },

    async encrypt(data, publicKey) {
        const aesKey = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 }, true, ["encrypt"]
        );
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const dataBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const encryptedData = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, dataBuffer);
        const aesKeyData = await crypto.subtle.exportKey("raw", aesKey);
        const encryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, aesKeyData);
        return {
            encryptedKey: this.bufferToBase64(encryptedKey),
            encryptedData: this.bufferToBase64(encryptedData),
            iv: this.bufferToBase64(iv),
        };
    },

    async decrypt(encrypted, privateKey) {
        const aesKeyData = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" }, privateKey, this.base64ToBuffer(encrypted.encryptedKey)
        );
        const aesKey = await crypto.subtle.importKey(
            "raw", aesKeyData, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
        );
        return await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: this.base64ToBuffer(encrypted.iv) },
            aesKey,
            this.base64ToBuffer(encrypted.encryptedData)
        );
    },

    storeKey(hash, jwkObj) {
        localStorage.setItem(`privipod_key_${hash}`, JSON.stringify(jwkObj));
    },

    getStoredKey(hash) {
        const str = localStorage.getItem(`privipod_key_${hash}`);
        return str ? JSON.parse(str) : null;
    },

    removeKey(hash) {
        localStorage.removeItem(`privipod_key_${hash}`);
    },
};

function privipodCopyToClipboard(text, msg) {
    navigator.clipboard.writeText(text)
        .then(() => alert(msg || 'Copied!'))
        .catch(() => alert('Failed to copy to clipboard'));
}
</script>
{% endblock %}

{% block footer %}{% endblock %}
"""

app.templates["dashboard.html"] = """
{% extends "app.html" %}

{% block content %}

<p><a href="{% url 'pod_create' %}" class="button">Create New Pod</a></p>

{% if pods %}
<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Created</th>
            <th>Status</th>
            <th>Deadline</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        {% for pod in pods %}
        <tr>
            <td><a href="{% url 'pod_view' hash=pod.hash %}">{{ pod.name }}</a></td>
            <td>{{ pod.created_at }}</td>
            <td>{{ pod.get_status_display }}</td>
            <td>{{ pod.deadline|date:"Y-m-d H:i"|default:"No deadline" }}</td>
            <td>
                <a href="{% url 'pod_view' hash=pod.hash %}" class="button secondary">View</a>
                <button onclick="copyUrl('{{ request.scheme }}://{{ request.get_host }}{% url 'pod_view' hash=pod.hash %}')" class="button secondary">Copy URL</button>
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% else %}
<p class="message info">You haven't created any pods yet. <a href="{% url 'pod_create' %}">Create your first pod</a> to get started.</p>
{% endif %}

<script>
function copyUrl(url) {
    privipodCopyToClipboard(url, 'Pod URL copied to clipboard!');
}

// Clean up localStorage keys for pods no longer owned by this user
const activePodHashes = new Set([{% for pod in pods %}"{{ pod.hash }}"{% if not forloop.last %}, {% endif %}{% endfor %}]);
for (let i = localStorage.length - 1; i >= 0; i--) {
    const key = localStorage.key(i);
    if (key && key.startsWith('privipod_key_')) {
        const hash = key.slice('privipod_key_'.length);
        if (!activePodHashes.has(hash)) {
            localStorage.removeItem(key);
        }
    }
}
</script>
{% endblock %}
"""

app.templates["pod_create.html"] = """
{% extends "app.html" %}

{% block content %}
<form method="post" id="createPodForm">
    {% csrf_token %}

    {{ form.as_p }}

    <p style="margin-top: 20px;">
        <button type="submit">Create Pod</button>
    </p>
</form>

<script>
const podHash = "{{ hash }}";

let keyPair = null;
(async () => {
    keyPair = await PrivipodCrypto.generateKeyPair();
})();

document.getElementById('createPodForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!keyPair) {
        alert('Key generation not ready yet, please try again.');
        return;
    }
    try {
        const publicKeyJWK = await PrivipodCrypto.exportKey(keyPair.publicKey);
        document.querySelector('input[name="public_key"]').value = JSON.stringify(publicKeyJWK);
        PrivipodCrypto.storeKey(podHash, await PrivipodCrypto.exportKey(keyPair.privateKey));
        e.target.submit();
    } catch (err) {
        alert(`Error preparing pod: ${err.message}`);
    }
});
</script>
{% endblock %}
"""

app.templates["registration/login.html"] = """
{% extends "app.html" %}

{% block content %}

{% if form.errors %}
<div class="message error">Invalid username or password. Please try again.</div>
{% endif %}

<form method="post">
    {% csrf_token %}
    {{ form.as_p }}
    <p style="margin-top: 20px;">
        <button type="submit">Login</button>
    </p>

    <input type="hidden" name="next" value="{{ next }}">
</form>
{% endblock %}
"""

app.templates["pod_view.html"] = """
{% extends "app.html" %}

{% block content %}

<p>Created by {{ pod.owner }}</p>

{% if is_owner %}
    {% if pod.status == "pending" %}
        {% if not show_send_form %}
        <div class="message info">
            <strong>Waiting for secret</strong>
        </div>

        {% if pod.deadline %}
            <div class="message warning">
                This pod will close at {{ pod.deadline }}
            </div>
        {% endif %}

        <p>Share this URL with the sender:</p>
        <div class="pod-url">{{ request.scheme }}://{{ request.get_host }}{% url 'pod_view' hash=pod.hash %}</div>
        <p>
            <button onclick="copyUrl()">Copy URL</button>
            <button onclick="location.reload()" class="button secondary">Refresh</button>
            <a href="?send" class="button secondary">Send to myself</a>
            <button onclick="exportKey()" class="button secondary">Download Key</button>
        </p>

        <meta http-equiv="refresh" content="30">
        {% endif %}

    {% elif pod.status == "sent" %}
        <div class="message success">Secret received</div>

        {% if pod.self_destruct %}
            <div class="message warning">
                This message is set to self destruct, and will be gone when you close this page.
            </div>
        {% elif pod.deadline %}
            <div class="message warning">
                You have until {{ pod.deadline }} to see the secret.
            </div>
        {% endif %}

        {{ encrypted_secret_json|json_script:"encrypted-secret-data" }}

        <div id="secretDisplay" class="secret-display">
            <p>Decrypting...</p>
        </div>

        <div id="keyRecovery" style="display:none;">
            <div class="message warning">
                Private key not found in this browser. Import your key file to decrypt.
            </div>
            <p>
                <label for="importKeyFile">Key file:</label>
                <input type="file" id="importKeyFile" accept=".json">
            </p>
        </div>

        <div id="keyActions" style="display:none;">
            <p>
                <button onclick="exportKey()" class="button secondary">Download Key</button>
            </p>
        </div>

        <script>
        (async () => {
            const podHash = "{{ pod.hash }}";
            const secretType = "{{ pod.secret_type }}";
            const originalFilename = "{{ pod.original_filename|escapejs }}";
            const selfDestruct = {{ pod.self_destruct|yesno:"true,false" }};
            const encryptedSecret = JSON.parse(document.getElementById('encrypted-secret-data').textContent);
            const display = document.getElementById('secretDisplay');

            function showError(msg) {
                display.innerHTML = '';
                const p = document.createElement('p');
                p.className = 'message error';
                p.textContent = msg;
                display.appendChild(p);
            }

            // Renders decrypted content; throws on failure so callers can handle errors
            async function decryptAndDisplay(privateKey) {
                const decrypted = await PrivipodCrypto.decrypt(encryptedSecret, privateKey);
                display.innerHTML = '';

                if (secretType === "text") {
                    const text = new TextDecoder().decode(decrypted);
                    const ta = document.createElement('textarea');
                    ta.readOnly = true;
                    ta.style.cssText = 'width:100%; min-height:150px; margin-top:10px;';
                    ta.value = text;
                    display.appendChild(ta);
                    const btn = document.createElement('button');
                    btn.style.marginTop = '10px';
                    btn.textContent = 'Copy to Clipboard';
                    btn.onclick = () => privipodCopyToClipboard(text, 'Copied to clipboard!');
                    display.appendChild(btn);
                } else {
                    const blob = new Blob([decrypted]);
                    const url = URL.createObjectURL(blob);
                    const p = document.createElement('p');
                    const strong = document.createElement('strong');
                    strong.textContent = 'File: ';
                    p.appendChild(strong);
                    p.appendChild(document.createTextNode(originalFilename));
                    display.appendChild(p);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = originalFilename;
                    a.className = 'button';
                    a.textContent = 'Download File';
                    display.appendChild(a);
                }

                document.getElementById('keyRecovery').style.display = 'none';
                if (selfDestruct) {
                    PrivipodCrypto.removeKey(podHash);
                } else {
                    document.getElementById('keyActions').style.display = 'block';
                }
            }

            // Try key from localStorage
            const storedJwk = PrivipodCrypto.getStoredKey(podHash);
            if (storedJwk) {
                try {
                    await decryptAndDisplay(await PrivipodCrypto.importPrivateKey(storedJwk));
                } catch (err) {
                    display.innerHTML = '';
                    document.getElementById('keyRecovery').style.display = 'block';
                }
            } else {
                display.innerHTML = '';
                document.getElementById('keyRecovery').style.display = 'block';
            }

            // Key recovery via file import — only store key after decryption succeeds
            document.getElementById('importKeyFile').addEventListener('change', async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                try {
                    const jwkObj = JSON.parse(await file.text());
                    const privateKey = await PrivipodCrypto.importPrivateKey(jwkObj);
                    await decryptAndDisplay(privateKey);
                    PrivipodCrypto.storeKey(podHash, jwkObj);
                } catch (err) {
                    showError(`Decryption failed: ${err.message}`);
                }
            });
        })();
        </script>
    {% endif %}

    <script>
    function copyUrl() {
        privipodCopyToClipboard(
            "{{ request.scheme }}://{{ request.get_host }}{% url 'pod_view' hash=pod.hash %}",
            'Pod URL copied to clipboard!'
        );
    }

    function exportKey() {
        const hash = "{{ pod.hash }}";
        const jwkObj = PrivipodCrypto.getStoredKey(hash);
        if (!jwkObj) { alert('No key found in this browser.'); return; }
        const blob = new Blob([JSON.stringify(jwkObj)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `privipod-key-${hash}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }
    </script>
{% endif %}

{# Sender view (non-owner or owner sending to self) #}
{% if show_send_form or not is_owner %}
    {% if pod.status == "pending" and not pod.is_expired %}
        <noscript>
            <div class="message error">You must enable JavaScript to send a secret.</div>
        </noscript>

        <div class="message info">
            Your data will be encrypted in your browser, and can only be read by the recipient.
            {% if pod.self_destruct %}It will be deleted once they have seen it.{% endif %}
        </div>

        {% if pod.deadline %}
            <div class="message warning">
                The recipient has until {{ pod.deadline }} to see your secret.
            </div>
        {% endif %}

        <form method="post" id="sendForm">
            {% csrf_token %}

            {{ send_form.as_p }}

            <p>
                <label for="input_type-text">Text secret</label>
                <input type="radio" id="input_type-text" name="input_type" value="text" checked>
            </p>
            <p>
                <label for="input_type-file">File</label>
                <input type="radio" id="input_type-file" name="input_type" value="file">
            </p>

            <p id="textInput">
                <label for="secretText">Enter your secret:</label>
                <textarea id="secretText" placeholder="Enter secret text here..."></textarea>
            </p>

            <p id="fileInput" style="display: none;">
                <label for="secretFile">Select file:</label>
                <input type="file" id="secretFile">
            </p>

            <p style="margin-top: 20px;">
                <button type="submit">Send Secret</button>
            </p>
        </form>

        {{ public_key_json|json_script:"public-key-data" }}

        <script>
        // Import public key once on load rather than on every submit
        let cachedPublicKey = null;
        (async () => {
            const jwk = JSON.parse(document.getElementById('public-key-data').textContent);
            cachedPublicKey = await PrivipodCrypto.importPublicKey(jwk);
        })();

        // Toggle text/file input visibility
        document.querySelectorAll('input[name="input_type"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                document.getElementById('textInput').style.display = e.target.value === 'text' ? 'block' : 'none';
                document.getElementById('fileInput').style.display = e.target.value === 'file' ? 'block' : 'none';
            });
        });

        document.getElementById('sendForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!cachedPublicKey) {
                alert('Encryption key not ready yet, please try again.');
                return;
            }

            const inputType = document.querySelector('input[name="input_type"]:checked').value;
            let data;

            if (inputType === 'text') {
                data = document.getElementById('secretText').value;
                if (!data) { alert('Please enter some text'); return; }
                document.querySelector('input[name="secret_type"]').value = 'text';
            } else {
                const fileInput = document.getElementById('secretFile');
                if (!fileInput.files.length) { alert('Please select a file'); return; }
                const file = fileInput.files[0];
                data = await file.arrayBuffer();
                document.querySelector('input[name="secret_type"]').value = 'file';
                document.querySelector('input[name="original_filename"]').value = file.name;
            }

            try {
                e.target.classList.add('loading');
                const encrypted = await PrivipodCrypto.encrypt(data, cachedPublicKey);
                document.querySelector('input[name="encrypted_data"]').value = JSON.stringify(encrypted);
                e.target.submit();
            } catch (err) {
                e.target.classList.remove('loading');
                alert(`Encryption failed: ${err.message}`);
            }
        });
        </script>

    {% elif pod.status == "sent" %}
        <div class="message success">
            <strong>Pod has been sent!</strong><br>
            The secret has been delivered.
        </div>

    {% else %}
        <div class="message error">This pod has expired or never existed.</div>
    {% endif %}
{% endif %}

{% endblock %}
"""

# Main
if __name__ == "__main__":
    main()
