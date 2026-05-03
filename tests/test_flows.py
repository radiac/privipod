"""
End-to-end flow tests for Privipod.

These tests require a running Privipod server. See conftest.py for setup.
"""

import re

from playwright.sync_api import BrowserContext, Page, expect

from .conftest import BASE_URL


def create_pod(owner_page: Page) -> str:
    """Create a new pod and return its URL."""
    owner_page.goto(f"{BASE_URL}/pod/create/")
    owner_page.wait_for_selector("#createPodForm")
    # Form generates keypair on load; wait for it
    owner_page.wait_for_timeout(500)
    owner_page.click('button[type="submit"]')
    owner_page.wait_for_url(f"{BASE_URL}/pod/**")
    return owner_page.url


class TestTextSecretFlow:
    def test_full_text_flow(
        self,
        owner_page: Page,
        sender_page: Page,
    ):
        """Owner creates pod → sender sends text → owner decrypts."""
        pod_url = create_pod(owner_page)

        # Owner sees "Waiting for secret"
        expect(owner_page.locator(".message.info")).to_contain_text(
            "Waiting for secret"
        )

        # Sender visits pod URL and sends a secret
        sender_page.goto(pod_url)
        expect(sender_page.locator(".message.info")).to_contain_text(
            "encrypted in your browser"
        )
        sender_page.fill("#secretText", "my-secret-value-12345")
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)
        expect(sender_page.locator(".message.success")).to_contain_text(
            "Pod has been sent"
        )

        # Owner reloads and sees decrypted secret
        owner_page.goto(pod_url)
        owner_page.wait_for_selector("#secretDisplay textarea", timeout=5000)
        secret_text = owner_page.locator("#secretDisplay textarea").input_value()
        assert secret_text == "my-secret-value-12345"


class TestFileSecretFlow:
    def test_full_file_flow(
        self,
        owner_page: Page,
        sender_page: Page,
        tmp_path,
    ):
        """Owner creates pod → sender uploads file → owner downloads."""
        pod_url = create_pod(owner_page)

        # Create a temporary test file
        test_file = tmp_path / "secret.txt"
        test_file.write_text("file-contents-xyz")

        # Sender sends file
        sender_page.goto(pod_url)
        sender_page.check('input[value="file"]')
        sender_page.set_input_files("#secretFile", str(test_file))
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)

        # Owner sees download link with correct filename
        owner_page.goto(pod_url)
        owner_page.wait_for_selector("#secretDisplay a", timeout=5000)
        download_link = owner_page.locator("#secretDisplay a")
        expect(download_link).to_have_attribute("download", "secret.txt")


class TestSelfDestructFlow:
    def test_pod_deleted_after_owner_views(
        self,
        owner_page: Page,
        sender_page: Page,
    ):
        """Self-destruct pod is deleted after owner views the secret."""
        # Create pod with self-destruct
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.check('input[name="self_destruct"]')
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url

        # Sender sends secret
        sender_page.goto(pod_url)
        sender_page.fill("#secretText", "self-destruct-secret")
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)

        # Owner views secret (triggers deletion)
        owner_page.goto(pod_url)
        owner_page.wait_for_selector("#secretDisplay textarea", timeout=5000)

        # Pod should now be gone
        owner_page.goto(pod_url)
        expect(owner_page.locator(".message.error")).to_be_visible()

    def test_localStorage_key_cleared_after_self_destruct(
        self,
        owner_page: Page,
        sender_page: Page,
    ):
        """LocalStorage key is removed after owner decrypts a self-destruct pod."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.check('input[name="self_destruct"]')
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url
        pod_hash = pod_url.rstrip("/").split("/")[-1]

        sender_page.goto(pod_url)
        sender_page.fill("#secretText", "gone-after-view")
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)

        # Owner views; key should be removed from localStorage
        owner_page.goto(pod_url)
        owner_page.wait_for_selector("#secretDisplay textarea", timeout=5000)

        key_in_storage = owner_page.evaluate(
            f"localStorage.getItem('privipod_key_{pod_hash}')"
        )
        assert key_in_storage is None


class TestSendToSelfFlow:
    def test_owner_can_send_to_self(self, owner_page: Page):
        """Owner uses 'Send to myself' to encrypt and then decrypt their own secret."""
        pod_url = create_pod(owner_page)

        # Click "Send to myself"
        owner_page.click('a[href="?send"]')
        owner_page.wait_for_selector("#secretText")
        owner_page.fill("#secretText", "self-secret-value")
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(pod_url)

        # Owner should now see the decrypted secret
        owner_page.wait_for_selector("#secretDisplay textarea", timeout=5000)
        secret_text = owner_page.locator("#secretDisplay textarea").input_value()
        assert secret_text == "self-secret-value"


class TestSenderAuthFlow:
    def test_unauthenticated_sender_blocked(
        self,
        owner_page: Page,
        sender_page: Page,
    ):
        """Pod with require_sender_auth blocks unauthenticated senders."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.check('input[name="require_sender_auth"]')
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url

        # Unauthenticated sender is redirected to login
        sender_page.goto(pod_url)
        expect(sender_page).to_have_url(re.compile(rf"{re.escape(BASE_URL)}/login/"))
