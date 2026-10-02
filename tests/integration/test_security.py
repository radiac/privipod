"""
End-to-end security tests: headers, CSRF and XSS.
"""

import pytest
import requests
from playwright.sync_api import expect

from .utils import create_receive_pod, create_send_pod, goto, send_to_receive_pod

CHECKED_PATHS = ["/login/", "/"]


@pytest.fixture
def auth_session(server) -> requests.Session:
    """An authenticated requests session for a new user"""
    user = server.create_user("session")
    session = requests.Session()
    session.get(f"{server.url}/login/")
    session.post(
        f"{server.url}/login/",
        data={
            "username": user.username,
            "password": user.password,
            "csrfmiddlewaretoken": session.cookies.get("csrftoken"),
        },
        headers={"Referer": f"{server.url}/login/"},
    )
    return session


class TestSecurityHeaders:
    @pytest.mark.parametrize("path", CHECKED_PATHS)
    def test_csp_header(self, server, path):
        resp = requests.get(f"{server.url}{path}")
        assert "script-src 'self'" in resp.headers["Content-Security-Policy"]

    @pytest.mark.parametrize("path", CHECKED_PATHS)
    def test_x_frame_options_deny(self, server, path):
        resp = requests.get(f"{server.url}{path}")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    @pytest.mark.parametrize("path", CHECKED_PATHS)
    def test_x_content_type_options(self, server, path):
        resp = requests.get(f"{server.url}{path}")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    @pytest.mark.parametrize("path", CHECKED_PATHS)
    def test_referrer_policy(self, server, path):
        resp = requests.get(f"{server.url}{path}")
        assert resp.headers.get("Referrer-Policy") == "same-origin"

    @pytest.mark.parametrize("path", ["/create/receive/", "/create/send/", "/keys/"])
    def test_csp_on_authenticated_pages(self, server, auth_session, path):
        resp = auth_session.get(f"{server.url}{path}")
        assert resp.ok
        assert "Content-Security-Policy" in resp.headers


class TestCSRF:
    def test_post_without_token_returns_403(self, server):
        session = requests.Session()
        session.get(f"{server.url}/login/")
        resp = session.post(
            f"{server.url}/login/", data={"username": "x", "password": "y"}
        )
        assert resp.status_code == 403


class TestXSS:
    XSS = '"><img src=x onerror=alert(1)>'

    def watch_dialogs(self, *pages) -> list[str]:
        fired = []
        for page in pages:
            page.on("dialog", lambda d: fired.append(d.message) or d.dismiss())
        return fired

    def test_malicious_filename_not_executed(self, alice, anon, tmp_path):
        fired = self.watch_dialogs(alice.page, anon.page)
        test_file = tmp_path / f"{self.XSS}.txt"
        test_file.write_text("content")
        url = create_receive_pod(alice.page)
        send_to_receive_pod(anon.page, url, file=test_file)

        link = alice.page.locator("#secretActions a[download]")
        expect(link).to_have_attribute("download", f"{self.XSS}.txt")
        assert not fired, f"XSS alert fired: {fired}"

    def test_malicious_pod_names_not_executed(self, alice, anon):
        fired = self.watch_dialogs(alice.page, anon.page)
        receive_url = create_receive_pod(alice.page, name=self.XSS)
        goto(anon.page, receive_url)
        send_url = create_send_pod(
            alice.page, text="x", access_code="code", name=self.XSS
        )
        goto(anon.page, send_url)
        goto(alice.page, "/")
        expect(alice.page.locator(".pod-card").first).to_contain_text(self.XSS)
        assert not fired, f"XSS alert fired: {fired}"

    def test_public_key_embedded_as_json_data(self, alice, anon):
        url = create_receive_pod(alice.page)
        goto(anon.page, url)
        public_key = anon.page.locator("#public-key-data")
        expect(public_key).to_have_attribute("type", "application/json")
