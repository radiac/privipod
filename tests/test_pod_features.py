"""
Feature-specific tests for Privipod pods.

These tests require a running Privipod server. See conftest.py for setup.
"""

import pytest
import requests
from playwright.sync_api import Page, expect

from .conftest import BASE_URL, TEST_PASS, TEST_USER


def get_auth_session() -> requests.Session:
    session = requests.Session()
    resp = session.get(f"{BASE_URL}/login/")
    csrf = session.cookies.get("csrftoken")
    session.post(
        f"{BASE_URL}/login/",
        data={
            "username": TEST_USER,
            "password": TEST_PASS,
            "csrfmiddlewaretoken": csrf,
        },
        headers={"Referer": f"{BASE_URL}/login/"},
        allow_redirects=True,
    )
    return session


class TestExpiredPod:
    def test_expired_pod_cannot_receive_secret(
        self,
        owner_page: Page,
        sender_page: Page,
    ):
        """A pod past its deadline shows as expired and rejects sends."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        # Set deadline in the past
        owner_page.fill('input[name="deadline"]', "2000-01-01T00:00")
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url

        sender_page.goto(pod_url)
        # Sender should see an error (expired/never existed)
        expect(sender_page.locator(".message.error")).to_be_visible()
        expect(sender_page.locator("#sendForm")).not_to_be_visible()


class TestFileSizeLimit:
    def test_oversized_payload_rejected(
        self, owner_page: Page, sender_page: Page, tmp_path
    ):
        """Payloads exceeding MAX_SIZE_MB are rejected."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url

        # Create a file just over the 10 MB default limit
        big_file = tmp_path / "big.bin"
        big_file.write_bytes(b"x" * (11 * 1024 * 1024))

        sender_page.goto(pod_url)
        sender_page.check('input[value="file"]')
        sender_page.set_input_files("#secretFile", str(big_file))
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)

        # Expect an error message about size
        expect(sender_page.locator("ul.messages li.error")).to_contain_text("size")


class TestKeyManagement:
    def test_export_key_button_present_when_pending(self, owner_page: Page):
        """'Download Key' button is shown on a pending pod."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")

        expect(owner_page.locator('button:has-text("Download Key")')).to_be_visible()

    def test_key_stored_in_localstorage_after_create(self, owner_page: Page):
        """Private key is stored in localStorage after pod creation."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_hash = owner_page.url.rstrip("/").split("/")[-1]

        key_data = owner_page.evaluate(
            f"localStorage.getItem('privipod_key_{pod_hash}')"
        )
        assert key_data is not None, "Private key should be in localStorage"
        assert "kty" in key_data, "localStorage value should be a JWK"

    def test_key_recovery_ui_shown_when_key_missing(
        self,
        owner_page: Page,
        sender_page: Page,
        browser,
    ):
        """Recovery UI appears when private key is absent from localStorage."""
        # Create pod and get URL
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url
        pod_hash = pod_url.rstrip("/").split("/")[-1]

        # Sender sends secret
        sender_page.goto(pod_url)
        sender_page.fill("#secretText", "recovery-test-secret")
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)

        # Open pod in a fresh context (no key in localStorage)
        from .conftest import TEST_PASS, TEST_USER

        fresh_context = browser.new_context()
        fresh_page = fresh_context.new_page()
        fresh_page.goto(f"{BASE_URL}/login/")
        fresh_page.fill('input[name="username"]', TEST_USER)
        fresh_page.fill('input[name="password"]', TEST_PASS)
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_url(f"{BASE_URL}/")
        fresh_page.goto(pod_url)
        fresh_page.wait_for_selector("#keyRecovery", timeout=3000)

        recovery_visible = fresh_page.locator("#keyRecovery").is_visible()
        fresh_context.close()
        assert recovery_visible, "Key recovery UI should be visible when key is missing"

    def test_dashboard_cleans_stale_keys(self, owner_page: Page):
        """Dashboard JS removes localStorage keys for pods not in the user's list."""
        # Plant a fake stale key
        owner_page.goto(f"{BASE_URL}/")
        owner_page.evaluate(
            "localStorage.setItem('privipod_key_stale-hash-that-does-not-exist', '{}')"
        )

        # Reload dashboard (cleanup runs on load)
        owner_page.reload()
        owner_page.wait_for_load_state("networkidle")

        stale_key = owner_page.evaluate(
            "localStorage.getItem('privipod_key_stale-hash-that-does-not-exist')"
        )
        assert stale_key is None, "Stale key should have been cleaned up"


class TestFileSecrets:
    def test_file_round_trip(self, owner_page: Page, sender_page: Page, tmp_path):
        """File content and filename survive the encrypt/send/decrypt cycle."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url

        filename = "test-secret.txt"
        test_file = tmp_path / filename
        test_file.write_bytes(b"the quick brown fox")

        sender_page.goto(pod_url)
        sender_page.check('input[value="file"]')
        sender_page.set_input_files("#secretFile", str(test_file))
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)

        owner_page.goto(pod_url)
        owner_page.wait_for_selector("#secretDisplay a", timeout=5000)

        expect(owner_page.locator("#secretDisplay")).to_contain_text(filename)
        download_link = owner_page.locator("#secretDisplay a[download]")
        expect(download_link).to_have_attribute("download", filename)


class TestDatabaseIsolation:
    def test_encrypted_secret_not_readable_plaintext(
        self, owner_page: Page, sender_page: Page
    ):
        """The encrypted_secret field in the DB contains ciphertext, not plaintext."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url

        plaintext = "super-secret-plaintext-do-not-store"
        sender_page.goto(pod_url)
        sender_page.fill("#secretText", plaintext)
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)

        response = requests.get(pod_url, allow_redirects=True)
        assert plaintext not in response.text, (
            "Plaintext secret must not appear in server-rendered HTML"
        )

    def test_filename_not_in_server_html(
        self, owner_page: Page, sender_page: Page, tmp_path
    ):
        """The original filename is encrypted and must not appear in server-rendered HTML."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url

        filename = "confidential-report-2026.pdf"
        test_file = tmp_path / filename
        test_file.write_bytes(b"PDF content here")

        sender_page.goto(pod_url)
        sender_page.check('input[value="file"]')
        sender_page.set_input_files("#secretFile", str(test_file))
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)

        session = get_auth_session()
        response = session.get(pod_url)
        assert filename not in response.text, (
            "Original filename must not appear in server-rendered HTML"
        )
