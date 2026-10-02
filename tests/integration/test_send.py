"""
End-to-end tests for send pods: the pod owner sends a secret to someone else.
"""

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from playwright.sync_api import expect

from .utils import (
    create_send_pod,
    goto,
    lock_with_wrong_codes,
    log_table,
    message,
    pod_hash,
    secret_display,
    unlock_with_access_code,
    wait_for_send_pod,
    wait_until,
)

CODE = "correct horse battery staple"


class TestAnonymousAccessCode:
    def test_recipient_decrypts_and_owner_page_updates(self, server, alice, anon):
        url = create_send_pod(alice.page, text="anon-secret", access_code=CODE)
        hash = pod_hash(url)
        expect(message(alice.page, "Waiting to be decrypted")).to_be_visible()

        goto(anon.page, url)
        # The secret is only released by the access code check
        expect(anon.page.locator("#encrypted-secret-data")).to_have_count(0)
        unlock_with_access_code(anon.page, "wrong")
        expect(anon.page.locator("#accessCodeError")).to_contain_text(
            "4 attempt(s) remaining"
        )
        unlock_with_access_code(anon.page, CODE)
        expect(secret_display(anon.page)).to_have_value("anon-secret")

        # Owner page is still open - polling notices and reloads
        expect(
            message(alice.page, "The recipient has decrypted the secret")
        ).to_be_visible()
        expect(log_table(alice.page)).to_have_text(
            ["Secret decrypted", "Secret accessed", "Failed access attempt"]
        )
        assert server.log_events("send", hash) == [
            ("attempt_failed", "attempt 1", None),
            ("accessed", "", None),
            ("decrypted", "", None),
        ]
        assert server.pod("send", hash)["status"] == "read"

    def test_plaintext_never_reaches_server(self, server, alice):
        plaintext = "send-plaintext-do-not-store"
        requests_seen = []
        alice.page.on("request", lambda r: requests_seen.append(r.post_data or ""))
        url = create_send_pod(alice.page, text=plaintext, access_code=CODE)

        assert not any(plaintext in body for body in requests_seen)
        assert not any(CODE in body for body in requests_seen)
        pod = server.pod("send", pod_hash(url))
        assert plaintext.encode() not in pod["encrypted_secret"]
        assert CODE.encode() not in pod["encrypted_private_key"]

    def test_recipient_can_decrypt_again(self, server, alice, anon):
        url = create_send_pod(alice.page, text="read-twice", access_code=CODE)
        for _ in range(2):
            goto(anon.page, url)
            unlock_with_access_code(anon.page, CODE)
            expect(secret_display(anon.page)).to_have_value("read-twice")

        hash = pod_hash(url)
        events = wait_until(
            lambda: len(e := server.log_events("send", hash)) == 4 and e
        )
        assert [event for event, _, _ in events] == [
            "accessed",
            "decrypted",
            "accessed",
            "decrypted",
        ]

    def test_lockout_and_unlock(self, alice, anon):
        url = create_send_pod(alice.page, text="locked-secret", access_code=CODE)
        goto(anon.page, url)
        lock_with_wrong_codes(anon.page)

        # Owner page updates to show the pod is locked, and the owner unlocks it
        expect(message(alice.page, "the pod is locked")).to_be_visible()
        alice.page.click("text=Unlock Pod")
        expect(alice.page.locator("#pp-messages")).to_contain_text("Pod unlocked")
        expect(message(alice.page, "Waiting to be decrypted")).to_be_visible()

        goto(anon.page, url)
        unlock_with_access_code(anon.page, CODE)
        expect(secret_display(anon.page)).to_have_value("locked-secret")

    def test_self_destruct(self, server, alice, anon):
        url = create_send_pod(
            alice.page, text="burn-after-reading", access_code=CODE, self_destruct=True
        )
        goto(anon.page, url)
        unlock_with_access_code(anon.page, CODE)
        expect(secret_display(anon.page)).to_have_value("burn-after-reading")

        expect(message(alice.page, "This pod has been destroyed")).to_be_visible()
        pod = server.pod("send", pod_hash(url))
        assert pod["encrypted_secret"] is None
        assert pod["encrypted_private_key"] is None
        assert server.log_events("send", pod_hash(url))[-1][:2] == (
            "destroyed",
            "self-destruct",
        )

        goto(anon.page, url)
        expect(anon.page.locator(".message.warning")).to_contain_text("destroyed")
        expect(anon.page.locator("#accessCode")).to_have_count(0)

    def test_file_secret(self, alice, anon, tmp_path):
        test_file = tmp_path / "launch-codes.txt"
        test_file.write_bytes(b"0000")
        url = create_send_pod(alice.page, file=test_file, access_code=CODE)

        goto(anon.page, url)
        unlock_with_access_code(anon.page, CODE)
        link = anon.page.locator("#secretDisplay a[download]")
        expect(link).to_have_attribute("download", "launch-codes.txt")
        with anon.page.expect_download() as download:
            link.click()
        assert Path(download.value.path()).read_bytes() == b"0000"


class TestNamedRecipient:
    def test_recipient_decrypts_with_identity_key(self, server, alice, bob):
        # Logging in on the dashboard generates each user's identity key
        url = create_send_pod(alice.page, text="for-bob", recipient=bob.user)

        goto(bob.page, url)
        expect(secret_display(bob.page)).to_have_value("for-bob")

        expect(
            message(alice.page, "The recipient has decrypted the secret")
        ).to_be_visible()
        assert server.log_events("send", pod_hash(url)) == [
            ("accessed", "", bob.user.username),
            ("decrypted", "", bob.user.username),
        ]

    def test_other_users_cannot_open_pod(self, actor, alice, bob, anon):
        url = create_send_pod(alice.page, text="for-bob-only", recipient=bob.user)

        carol = actor("carol")
        goto(carol.page, url)
        expect(carol.page.locator(".message.error")).to_contain_text("doesn't exist")

        anon.page.goto(url)
        expect(anon.page).to_have_url(re.compile(r"/login/"))

    def test_recipient_without_identity_key_cannot_be_chosen(self, server, alice):
        # Never logged in, so no identity key has been generated
        dave = server.create_user("dave")
        goto(alice.page, "/create/send/")
        alice.page.select_option("#id_recipient_username", dave.username)
        expect(alice.page.locator("#recipientKeyStatus")).to_contain_text("Cannot send")

    def test_new_device_with_server_stored_identity_key(self, actor, alice, bob):
        goto(bob.page, "/keys/")
        actions = bob.page.locator("#identity-server-key-actions")
        actions.locator("input").fill(CODE)
        actions.locator("button", has_text="Save to server").click()
        expect(bob.page.locator("#identity-server-key-actions")).to_contain_text(
            "Remove from server"
        )

        url = create_send_pod(alice.page, text="bob-on-laptop", recipient=bob.user)

        laptop = actor(user=bob.user)
        goto(laptop.page, url)
        expect(laptop.page.locator("#identityKeyCodePrompt")).to_be_visible()
        laptop.page.fill("#identityAccessCode", CODE)
        laptop.page.click("#identityAccessCodeSubmit")
        expect(secret_display(laptop.page)).to_have_value("bob-on-laptop")

    def test_regeneration_warns_rather_than_fails_if_server_removal_fails(self, bob):
        # Store a key on the server first
        goto(bob.page, "/keys/")
        actions = bob.page.locator("#identity-server-key-actions")
        actions.locator("input").fill(CODE)
        actions.locator("button", has_text="Save to server").click()
        expect(bob.page.locator("#identity-server-key-actions")).to_contain_text(
            "Remove from server"
        )
        goto(bob.page, "/keys/")  # reload so the page knows a server key now exists

        bob.page.route(
            "**/identity/remove-private-key/", lambda route: route.fulfill(status=500)
        )
        bob.page.click(".key-danger-zone summary")
        bob.page.once("dialog", lambda d: d.accept())
        with bob.page.expect_navigation():
            bob.page.click("#regenerateIdentityKeyBtn")

        # Regeneration itself (new public key + new local private key) still
        # succeeded - the user is warned about the stale server-side key rather than
        # told the whole thing failed
        expect(
            bob.page.locator(".toast.warning", has_text="could not be removed")
        ).to_be_visible()
        expect(bob.page.locator("#identity-browser-status")).to_have_text(
            "✓ In browser"
        )

    def test_new_device_with_identity_key_file(self, actor, alice, bob, tmp_path):
        goto(bob.page, "/keys/")
        with bob.page.expect_download() as download:
            bob.page.click("text=Download key file")
        key_file = tmp_path / "identity.json"
        download.value.save_as(key_file)

        url = create_send_pod(alice.page, text="bob-from-file", recipient=bob.user)

        laptop = actor(user=bob.user)
        goto(laptop.page, url)
        expect(laptop.page.locator("#identityKeyImportPrompt")).to_be_visible()
        laptop.page.set_input_files("#importIdentityKeyFile", str(key_file))
        expect(secret_display(laptop.page)).to_have_value("bob-from-file")


class TestAnonymousKeyFile:
    """Anonymous pods on a server without server-stored keys"""

    def create_pod(self, page, text, tmp_path) -> tuple[str, Path]:
        create_send_pod(page, text=text, submit=False)
        with page.expect_download() as download:
            page.click("#sendPodSubmit")
        url = wait_for_send_pod(page)
        key_file = tmp_path / download.value.suggested_filename
        download.value.save_as(key_file)
        assert key_file.name == f"privipod-key-{pod_hash(url)}.json"
        return url, key_file

    def test_recipient_decrypts_with_key_file(self, actor, keyfile_server, tmp_path):
        carol = actor("carol", on=keyfile_server)
        url, key_file = self.create_pod(carol.page, "keyfile-secret", tmp_path)
        expect(carol.page.locator("#storeKeySection")).to_have_count(0)

        recipient = actor(on=keyfile_server)
        goto(recipient.page, url)
        recipient.page.set_input_files("#importKeyFile", str(key_file))
        expect(secret_display(recipient.page)).to_have_value("keyfile-secret")

        expect(
            message(carol.page, "The recipient has decrypted the secret")
        ).to_be_visible()
        assert keyfile_server.log_events("send", pod_hash(url)) == [
            ("accessed", "", None),
            ("decrypted", "", None),
        ]

    def test_wrong_key_file_does_not_decrypt(self, actor, keyfile_server, tmp_path):
        carol = actor("carol", on=keyfile_server)
        url, _ = self.create_pod(carol.page, "right-secret", tmp_path / "a")
        _, other_key_file = self.create_pod(carol.page, "other-secret", tmp_path / "b")

        recipient = actor(on=keyfile_server)
        goto(recipient.page, url)
        recipient.page.set_input_files("#importKeyFile", str(other_key_file))
        expect(recipient.page.locator(".toast.error")).to_contain_text(
            "Decryption failed"
        )
        expect(secret_display(recipient.page)).to_have_count(0)
        pod = keyfile_server.pod("send", pod_hash(url))
        assert pod["status"] == "pending"
        events = keyfile_server.log_events("send", pod_hash(url))
        assert [event for event, _, _ in events] == ["accessed"]


class TestDeadlineAndExpiry:
    @pytest.mark.timezone("Asia/Kolkata")
    def test_deadline_entered_in_local_time_is_stored_as_utc(self, server, alice):
        deadline = (datetime.now(timezone.utc) + timedelta(days=1)).replace(
            second=0, microsecond=0
        )
        url = create_send_pod(
            alice.page, text="deadline", access_code=CODE, deadline=deadline
        )
        stored = server.pod("send", pod_hash(url))["deadline"]
        assert stored == deadline.strftime("%Y-%m-%d %H:%M:%S")

    def test_expired_pod_cannot_be_opened(self, server, alice, anon):
        url = create_send_pod(alice.page, text="too-late", access_code=CODE)
        hash = pod_hash(url)
        server.expire("send", hash)

        goto(anon.page, url)
        expect(anon.page.locator(".message.warning")).to_contain_text("destroyed")
        expect(anon.page.locator("#accessCode")).to_have_count(0)

        # Owner page polling picks up the change
        expect(message(alice.page, "This pod has been destroyed")).to_be_visible()
        expect(log_table(alice.page).first).to_have_text("Destroyed")
        assert server.log_events("send", hash) == [("destroyed", "expired", None)]
        pod = server.pod("send", hash)
        assert pod["encrypted_secret"] is None
        assert pod["encrypted_private_key"] is None

    def test_expired_locked_pod_is_destroyed(self, server, alice, anon):
        url = create_send_pod(alice.page, text="locked-then-expired", access_code=CODE)
        hash = pod_hash(url)
        goto(anon.page, url)
        lock_with_wrong_codes(anon.page)

        server.expire("send", hash)
        goto(alice.page, url)
        expect(message(alice.page, "This pod has been destroyed")).to_be_visible()
        expect(alice.page.locator("text=Unlock Pod")).to_have_count(0)
        assert server.pod("send", hash)["encrypted_secret"] is None


class TestDashboard:
    def test_dashboard_lists_both_kinds_of_pod(self, alice, anon):
        create_send_pod(alice.page, text="x", access_code=CODE, name="Outgoing")
        goto(alice.page, "/create/receive/")
        alice.page.fill("#id_name", "Incoming")
        alice.page.click('#createPodForm button[type="submit"]')
        alice.page.wait_for_url("**/pod/r-*/")

        goto(alice.page, "/")
        cards = alice.page.locator(".pod-card")
        expect(cards.filter(has_text="Incoming")).to_contain_text("Waiting for secret")
        expect(cards.filter(has_text="Outgoing")).to_contain_text(
            "Waiting to be decrypted"
        )
