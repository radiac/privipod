"""
Security header and XSS tests for Privipod.

These tests require a running Privipod server. See conftest.py for setup.
"""

import pytest
import requests
from playwright.sync_api import Page, expect

from .conftest import BASE_URL, TEST_PASS, TEST_USER

# ---------------------------------------------------------------------------
# HTTP header tests (using requests, no browser needed)
# ---------------------------------------------------------------------------

CHECKED_PATHS = ["/login/", "/"]


def get_session() -> requests.Session:
    """Return an authenticated requests session."""
    session = requests.Session()
    # Fetch login page to get CSRF token
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


@pytest.fixture(scope="module")
def auth_session():
    return get_session()


class TestSecurityHeaders:
    @pytest.mark.parametrize("path", CHECKED_PATHS)
    def test_csp_header_present(self, path):
        resp = requests.get(f"{BASE_URL}{path}", allow_redirects=False)
        # May redirect to login - follow to get the actual response
        resp = requests.get(f"{BASE_URL}{path}", allow_redirects=True)
        assert "Content-Security-Policy" in resp.headers

    @pytest.mark.parametrize("path", CHECKED_PATHS)
    def test_x_frame_options_deny(self, path):
        # Set by Django's XFrameOptionsMiddleware (X_FRAME_OPTIONS = "DENY" default)
        resp = requests.get(f"{BASE_URL}{path}", allow_redirects=True)
        assert resp.headers.get("X-Frame-Options") == "DENY"

    @pytest.mark.parametrize("path", CHECKED_PATHS)
    def test_x_content_type_options(self, path):
        # Set by Django's SecurityMiddleware (SECURE_CONTENT_TYPE_NOSNIFF = True default)
        resp = requests.get(f"{BASE_URL}{path}", allow_redirects=True)
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    @pytest.mark.parametrize("path", CHECKED_PATHS)
    def test_referrer_policy(self, path):
        # Set by Django's SecurityMiddleware (SECURE_REFERRER_POLICY = "same-origin" default)
        resp = requests.get(f"{BASE_URL}{path}", allow_redirects=True)
        assert resp.headers.get("Referrer-Policy") == "same-origin"

    def test_csp_on_pod_view(self, auth_session: requests.Session):
        """CSP header is present on authenticated pod pages."""
        resp = auth_session.get(f"{BASE_URL}/pod/create/", allow_redirects=True)
        # Follows redirect to the new pod hash URL
        assert "Content-Security-Policy" in resp.headers


class TestCSRF:
    def test_post_without_token_returns_403(self):
        """POST without CSRF token is rejected."""
        session = requests.Session()
        # Get cookies but skip the CSRF token
        session.get(f"{BASE_URL}/login/")
        resp = session.post(
            f"{BASE_URL}/login/",
            data={"username": TEST_USER, "password": TEST_PASS},
        )
        assert resp.status_code == 403


class TestXSS:
    def test_malicious_filename_not_executed(
        self,
        owner_page: Page,
        sender_page: Page,
        tmp_path,
    ):
        """A filename containing script injection is not executed."""
        # Create pod
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url

        # Create file with XSS name
        xss_name = '"><img src=x onerror=alert(1)>.txt'
        test_file = tmp_path / xss_name
        test_file.write_text("content")

        # Send file
        sender_page.goto(pod_url)
        sender_page.check('input[value="file"]')
        sender_page.set_input_files("#secretFile", str(test_file))

        # Intercept any dialog (alert) - none should fire
        dialog_fired = []
        sender_page.on(
            "dialog", lambda d: dialog_fired.append(d.message) or d.dismiss()
        )
        sender_page.click('button[type="submit"]')
        sender_page.wait_for_url(pod_url)

        # Owner views
        owner_page.goto(pod_url)
        owner_page.wait_for_selector("#secretDisplay a", timeout=5000)

        # No alert should have fired
        assert not dialog_fired, f"XSS alert fired: {dialog_fired}"

    def test_public_key_xss_not_executed(self, owner_page: Page, sender_page: Page):
        """Public key JSON is safely embedded (json_script) and not executed."""
        owner_page.goto(f"{BASE_URL}/pod/create/")
        owner_page.wait_for_selector("#createPodForm")
        owner_page.wait_for_timeout(500)
        owner_page.click('button[type="submit"]')
        owner_page.wait_for_url(f"{BASE_URL}/pod/**")
        pod_url = owner_page.url

        dialog_fired = []
        sender_page.on(
            "dialog", lambda d: dialog_fired.append(d.message) or d.dismiss()
        )
        sender_page.goto(pod_url)
        sender_page.wait_for_selector("#sendForm")

        assert not dialog_fired, f"XSS alert fired: {dialog_fired}"

        # Verify public key is inside a json_script element, not raw in a script tag
        pk_elem = sender_page.locator("#public-key-data")
        expect(pk_elem).to_be_attached()
        assert pk_elem.get_attribute("type") == "application/json"
