"""
End-to-end tests for receive pods: someone sends a secret to the pod owner.
"""

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from playwright.sync_api import expect

from .utils import (
    create_receive_pod,
    goto,
    local_input_value,
    log_table,
    pod_hash,
    secret_display,
    send_to_receive_pod,
    wait_ready,
    wait_until,
)


class TestTextSecret:
    def test_owner_page_updates_and_decrypts_when_secret_arrives(self, alice, anon):
        url = create_receive_pod(alice.page, name="Text pod")
        expect(alice.page.locator(".message.info")).to_contain_text(
            "Waiting for secret"
        )

        send_to_receive_pod(anon.page, url, text="my-secret-value-12345")
        expect(anon.page.locator(".message.success")).to_contain_text(
            "Pod has been sent"
        )

        # Owner page is still open - polling notices and reloads
        expect(secret_display(alice.page)).to_have_value("my-secret-value-12345")

    def test_secret_shown_with_copy_and_delete_buttons(self, alice, anon):
        url = create_receive_pod(alice.page)
        send_to_receive_pod(anon.page, url, text="copy-me")
        expect(secret_display(alice.page)).to_have_value("copy-me")

        buttons = alice.page.locator("#secretActions button")
        expect(buttons).to_have_text(["Copy to Clipboard", "Delete Pod"])
        alice.context.grant_permissions(["clipboard-read", "clipboard-write"])
        buttons.first.click()
        expect(alice.page.locator(".toast")).to_contain_text("Copied")
        assert alice.page.evaluate("navigator.clipboard.readText()") == "copy-me"

    def test_status_and_log_after_decrypt(self, server, alice, anon):
        url = create_receive_pod(alice.page)
        send_to_receive_pod(anon.page, url, text="logged")
        expect(secret_display(alice.page)).to_have_value("logged")

        hash = pod_hash(url)
        user = alice.user.username
        wait_until(lambda: len(server.log_events("receive", hash)) == 2)
        assert server.log_events("receive", hash) == [
            ("accessed", "", user),
            ("decrypted", "", user),
        ]

        # Reload: the page is accessed again before rendering, and decrypted after
        goto(alice.page, url)
        expect(secret_display(alice.page)).to_have_value("logged")
        expect(log_table(alice.page)).to_have_text(
            ["Secret accessed", "Secret decrypted", "Secret accessed"]
        )
        assert server.pod("receive", pod_hash(url))["status"] == "received"

    def test_sender_cannot_send_twice(self, alice, anon):
        url = create_receive_pod(alice.page)
        send_to_receive_pod(anon.page, url, text="first")
        goto(anon.page, url)
        expect(anon.page.locator("#sendForm")).to_have_count(0)
        expect(secret_display(alice.page)).to_have_value("first")

    def test_send_to_self(self, alice):
        url = create_receive_pod(alice.page)
        alice.page.click('a[href="?send"]')
        wait_ready(alice.page)
        alice.page.fill("#secretText", "self-secret-value")
        alice.page.click('#sendForm button[type="submit"]')
        alice.page.wait_for_url(url)
        expect(secret_display(alice.page)).to_have_value("self-secret-value")

    def test_plaintext_never_reaches_server(self, server, alice, anon):
        url = create_receive_pod(alice.page)
        plaintext = "super-secret-plaintext-do-not-store"
        requests_seen = []
        anon.page.on("request", lambda r: requests_seen.append(r.post_data or ""))
        send_to_receive_pod(anon.page, url, text=plaintext)

        assert not any(plaintext in body for body in requests_seen)
        stored = server.pod("receive", pod_hash(url))["encrypted_secret"]
        assert plaintext.encode() not in stored
        expect(secret_display(alice.page)).to_have_value(plaintext)


class TestFileSecret:
    def test_file_round_trip(self, server, alice, anon, tmp_path):
        filename = "confidential-report-2026.txt"
        test_file = tmp_path / filename
        test_file.write_bytes(b"the quick brown fox")
        url = create_receive_pod(alice.page)
        send_to_receive_pod(anon.page, url, file=test_file)

        link = alice.page.locator("#secretActions a[download]")
        expect(link).to_have_attribute("download", filename)
        with alice.page.expect_download() as download:
            link.click()
        assert Path(download.value.path()).read_bytes() == b"the quick brown fox"

        # Filename is encrypted too
        pod = server.pod("receive", pod_hash(url))
        assert filename.encode() not in pod["encrypted_filename"]

    def test_oversized_file_rejected(self, alice, anon, tmp_path):
        big_file = tmp_path / "big.bin"
        big_file.write_bytes(b"x" * (11 * 1024 * 1024))  # server limit is 10MB
        url = create_receive_pod(alice.page)
        send_to_receive_pod(anon.page, url, file=big_file)
        expect(anon.page.locator("#pp-messages li[data-type='error']")).to_contain_text(
            "size"
        )
        expect(anon.page.locator("#sendForm")).to_be_visible()


class TestSelfDestruct:
    def test_secret_destroyed_after_owner_decrypts(self, server, alice, anon):
        url = create_receive_pod(alice.page, self_destruct=True)
        hash = pod_hash(url)
        send_to_receive_pod(anon.page, url, text="self-destruct-secret")

        expect(secret_display(alice.page)).to_have_value("self-destruct-secret")

        pod = wait_until(
            lambda: (p := server.pod("receive", hash))["status"] == "destroyed" and p
        )
        assert pod["encrypted_secret"] is None
        assert server.log_events("receive", hash)[-1][:2] == (
            "destroyed",
            "self-destruct",
        )
        # Private key is removed from the browser
        assert (
            alice.page.evaluate(f"localStorage.getItem('privipod_key_{hash}')") is None
        )

        goto(alice.page, url)
        expect(alice.page.locator(".message.warning")).to_contain_text("destroyed")
        expect(log_table(alice.page).first).to_have_text("Destroyed")


class TestSenderAuth:
    def test_anonymous_sender_redirected_to_login(self, alice, anon):
        url = create_receive_pod(alice.page, require_sender_auth=True)
        anon.page.goto(url)
        expect(anon.page).to_have_url(re.compile(r"/login/"))

    def test_logged_in_sender_can_send(self, alice, bob):
        url = create_receive_pod(alice.page, require_sender_auth=True)
        send_to_receive_pod(bob.page, url, text="from bob")
        expect(secret_display(alice.page)).to_have_value("from bob")


class TestDeadline:
    @pytest.mark.timezone("Europe/Berlin")
    def test_deadline_entered_in_local_time_is_stored_as_utc(self, server, alice):
        deadline = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(
            second=0, microsecond=0
        )
        url = create_receive_pod(alice.page, deadline=deadline)
        stored = server.pod("receive", pod_hash(url))["deadline"]
        assert stored == deadline.strftime("%Y-%m-%d %H:%M:%S")

    @pytest.mark.timezone("America/New_York")
    def test_past_deadline_rejected_and_value_kept(self, alice):
        page = alice.page
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(
            second=0, microsecond=0
        )
        goto(page, "/create/receive/")
        typed = local_input_value(page, past)
        page.fill("#id_deadline", typed)
        page.click('#createPodForm button[type="submit"]')
        page.wait_for_load_state()
        wait_ready(page)

        expect(page.locator(".errorlist")).to_contain_text("must be in the future")
        # Converted back to the local time the user typed
        expect(page.locator("#id_deadline")).to_have_value(typed)


class TestExpiry:
    def test_expired_pod_rejects_sender(self, server, alice, anon):
        url = create_receive_pod(alice.page)
        server.expire("receive", pod_hash(url))
        goto(anon.page, url)
        expect(anon.page.locator(".message.error")).to_contain_text("expired")
        expect(anon.page.locator("#sendForm")).to_have_count(0)

    def test_expired_received_pod_is_destroyed(self, server, alice, anon):
        url = create_receive_pod(alice.page)
        hash = pod_hash(url)
        send_to_receive_pod(anon.page, url, text="expiring")
        expect(secret_display(alice.page)).to_have_value("expiring")

        server.expire("receive", hash)
        goto(alice.page, url)
        expect(alice.page.locator(".message.warning")).to_contain_text("destroyed")
        expect(log_table(alice.page).first).to_have_text("Destroyed")
        assert server.log_events("receive", hash)[-1] == ("destroyed", "expired", None)
        assert server.pod("receive", hash)["encrypted_secret"] is None

    def test_pending_owner_page_updates_on_expiry(self, server, alice):
        url = create_receive_pod(alice.page)
        server.expire("receive", pod_hash(url))
        # Status polling expires the pod and the page reloads to show it
        expect(alice.page.locator(".message.warning")).to_contain_text("destroyed")


class TestPolling:
    def test_polling_backs_off_to_every_10_seconds(self, alice):
        url = create_receive_pod(alice.page)
        page = alice.page
        page.clock.install()
        polls = []
        page.on("request", lambda r: "/status/" in r.url and polls.append(r.url))
        goto(page, url)

        windows = []
        for _ in range(12):  # 6 minutes in 30 second windows
            before = len(polls)
            for _ in range(30):
                page.clock.run_for(1000)
                page.wait_for_timeout(15)  # let each poll's fetch resolve
            windows.append(len(polls) - before)

        assert windows[0] >= 28  # every 1s
        assert 13 <= windows[1] <= 16  # every 2s
        assert windows[-2:] == [3, 3]  # every 10s, and still polling

    def test_reloads_rather_than_looping_forever_if_session_expires(self, alice):
        # login_required redirects an expired session's status poll to /login/; the
        # page should reload to show that rather than fail to parse HTML as JSON and
        # silently keep polling forever
        url = create_receive_pod(alice.page)
        hash = pod_hash(url)
        alice.page.route(
            f"**/pod/r-{hash}/status/",
            lambda route: route.fulfill(status=302, headers={"Location": "/login/"}),
        )
        with alice.page.expect_navigation(url=url, timeout=15000):
            pass


class TestKeys:
    def test_key_stored_in_local_storage(self, alice):
        url = create_receive_pod(alice.page)
        key = alice.page.evaluate(
            f"localStorage.getItem('privipod_key_{pod_hash(url)}')"
        )
        assert '"kty"' in key

    def test_key_file_recovers_secret_on_new_device(self, actor, alice, anon, tmp_path):
        url = create_receive_pod(alice.page)
        alice.page.click("#keyManage summary")
        with alice.page.expect_download() as download:
            alice.page.click("button[data-export-key]")
        key_file = tmp_path / download.value.suggested_filename
        download.value.save_as(key_file)
        assert key_file.name == f"privipod-key-{pod_hash(url)}.json"

        send_to_receive_pod(anon.page, url, text="recovered-by-file")

        laptop = actor(user=alice.user)
        goto(laptop.page, url)
        expect(laptop.page.locator("#keyRecovery")).to_be_visible()
        laptop.page.set_input_files("#importKeyFile", str(key_file))
        expect(secret_display(laptop.page)).to_have_value("recovered-by-file")

    def test_server_stored_key_recovers_secret_on_new_device(self, actor, alice, anon):
        url = create_receive_pod(alice.page)
        alice.page.click("#keyManage summary")
        alice.page.fill("#storeKeyCode", "correct horse battery")
        alice.page.click("#storeKeyBtn")
        expect(alice.page.locator("#storeKeySection")).to_contain_text(
            "Key stored on server"
        )

        send_to_receive_pod(anon.page, url, text="recovered-from-server")

        laptop = actor(user=alice.user)
        goto(laptop.page, url)
        laptop.page.fill("#retrieveKeyCode", "wrong code")
        laptop.page.click("#retrieveKeyBtn")
        expect(laptop.page.locator("#retrieveKeyError")).to_be_visible()
        laptop.page.fill("#retrieveKeyCode", "correct horse battery")
        laptop.page.click("#retrieveKeyBtn")
        expect(secret_display(laptop.page)).to_have_value("recovered-from-server")

    def test_manage_key_box_kept_after_secret_received(self, server, alice, anon):
        url = create_receive_pod(alice.page)
        expect(alice.page.locator("#keyManage")).to_be_visible()

        send_to_receive_pod(anon.page, url, text="still-manageable")
        expect(secret_display(alice.page)).to_have_value("still-manageable")
        box = alice.page.locator("#keyManage")
        expect(box).to_be_visible()

        # Its actions still work once the secret has arrived
        box.locator("summary").click()
        with alice.page.expect_download() as download:
            box.locator("button[data-export-key]").click()
        assert download.value.suggested_filename == f"privipod-key-{pod_hash(url)}.json"
        alice.page.fill("#storeKeyCode", "stored after receipt")
        alice.page.click("#storeKeyBtn")
        expect(alice.page.locator("#storeKeySuccess")).to_be_visible()
        expect(alice.page.locator("#storeKeyForm")).to_have_count(0)
        assert server.pod("receive", pod_hash(url))["encrypted_private_key"]

        # And it knows the key is stored when the page is next loaded
        goto(alice.page, url)
        expect(secret_display(alice.page)).to_have_value("still-manageable")
        expect(alice.page.locator("#storeKeySuccess")).to_be_attached()
        expect(alice.page.locator("#storeKeyForm")).to_have_count(0)

    def test_manage_key_box_needs_key_in_browser(self, actor, alice, anon, tmp_path):
        url = create_receive_pod(alice.page)
        alice.page.click("#keyManage summary")
        with alice.page.expect_download() as download:
            alice.page.click("button[data-export-key]")
        key_file = tmp_path / "key.json"
        download.value.save_as(key_file)
        send_to_receive_pod(anon.page, url, text="elsewhere")

        # Hidden until the key has been imported into this browser
        laptop = actor(user=alice.user)
        goto(laptop.page, url)
        expect(laptop.page.locator("#keyManage")).to_be_hidden()
        laptop.page.set_input_files("#importKeyFile", str(key_file))
        expect(secret_display(laptop.page)).to_have_value("elsewhere")
        expect(laptop.page.locator("#keyManage")).to_be_visible()

    def test_manage_key_box_not_shown_for_self_destruct(self, alice, anon):
        url = create_receive_pod(alice.page, self_destruct=True)
        expect(alice.page.locator("#keyManage")).to_be_visible()
        send_to_receive_pod(anon.page, url, text="gone")
        expect(secret_display(alice.page)).to_have_value("gone")
        expect(alice.page.locator("#keyManage")).to_have_count(0)

    def test_no_server_key_option_when_disabled(self, actor, keyfile_server):
        carol = actor("carol", on=keyfile_server)
        create_receive_pod(carol.page)
        expect(carol.page.locator("#storeKeySection")).to_have_count(0)

    def test_dashboard_removes_stale_keys(self, alice):
        alice.page.evaluate("localStorage.setItem('privipod_key_stale-hash', '{}')")
        goto(alice.page, "/")
        assert (
            alice.page.evaluate("localStorage.getItem('privipod_key_stale-hash')")
            is None
        )
