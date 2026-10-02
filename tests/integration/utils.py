"""
Helpers for driving Privipod pages in end-to-end tests.

Page JS sets ``<html data-pp-ready>`` once it has finished setting up, so helpers wait
for that rather than sleeping. Pages have a strict CSP, which blocks the string form of
``page.wait_for_function()``; use locators and ``expect()`` instead.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from playwright.sync_api import Page, expect

if TYPE_CHECKING:
    from .conftest import User


def wait_ready(page: Page):
    page.wait_for_selector("html[data-pp-ready]", state="attached")


def goto(page: Page, url: str):
    page.goto(url)
    wait_ready(page)


def login(page: Page, user: User):
    page.goto("/login/")
    page.fill('input[name="username"]', user.username)
    page.fill('input[name="password"]', user.password)
    page.click('button[type="submit"]')
    page.wait_for_url(lambda url: urlparse(url).path == "/")
    wait_ready(page)


def wait_until(check, timeout: float = 10):
    """Wait until ``check()`` returns a truthy value, and return it"""
    deadline = time.monotonic() + timeout
    while True:
        result = check()
        if result or time.monotonic() > deadline:
            assert result, "Timed out waiting for condition"
            return result
        time.sleep(0.1)


def pod_hash(url: str) -> str:
    """Return the hash from a /pod/r-<hash>/ or /pod/s-<hash>/ URL"""
    return re.search(r"/pod/[rs]-([^/]+)/", url).group(1)


def local_input_value(page: Page, when: datetime) -> str:
    """Format a datetime as a datetime-local input value in the browser's timezone"""
    return page.evaluate(
        """iso => {
            const d = new Date(iso);
            const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
            return local.toISOString().slice(0, 16);
        }""",
        when.isoformat(),
    )


def secret_display(page: Page):
    """The decrypted text secret shown on a pod page"""
    return page.locator("#secretDisplay textarea")


def message(page: Page, text: str):
    """A message box on the page containing ``text``"""
    return page.locator(".message", has_text=text)


def log_table(page: Page):
    """The access log table's event column"""
    return page.locator("table tbody tr td:nth-child(2)")


# ---------------------------------------------------------------------------
# Receive pods
# ---------------------------------------------------------------------------


def create_receive_pod(
    page: Page,
    name: str = "",
    deadline: datetime | None = None,
    self_destruct: bool = False,
    require_sender_auth: bool = False,
) -> str:
    """Create a receive pod and return its URL, leaving the page on it"""
    goto(page, "/create/receive/")
    if name:
        page.fill("#id_name", name)
    if deadline:
        page.fill("#id_deadline", local_input_value(page, deadline))
    if self_destruct:
        page.check("#id_self_destruct")
    if require_sender_auth:
        page.check("#id_require_sender_auth")
    page.click('#createPodForm button[type="submit"]')
    page.wait_for_url("**/pod/r-*/")
    wait_ready(page)
    return page.url


def send_to_receive_pod(
    page: Page, url: str, text: str | None = None, file: Path | None = None
):
    """Send a text or file secret to a receive pod"""
    goto(page, url)
    if file:
        page.check("#input_type-file")
        page.set_input_files("#secretFile", str(file))
    else:
        page.fill("#secretText", text)
    page.click('#sendForm button[type="submit"]')
    page.wait_for_url(url)
    wait_ready(page)


# ---------------------------------------------------------------------------
# Send pods
# ---------------------------------------------------------------------------


def create_send_pod(
    page: Page,
    text: str | None = None,
    file: Path | None = None,
    recipient: User | None = None,
    access_code: str | None = None,
    name: str = "",
    deadline: datetime | None = None,
    self_destruct: bool = False,
    submit: bool = True,
) -> str | None:
    """
    Create a send pod and return its URL, leaving the page on it

    Pass ``submit=False`` to fill the form without submitting it, eg to catch the key
    file download on a server without server-stored keys.
    """
    goto(page, "/create/send/")
    if name:
        page.fill("#id_name", name)
    if recipient:
        page.select_option("#id_recipient_username", recipient.username)
        expect(page.locator("#recipientKeyStatus")).to_contain_text("Ready")
    if access_code:
        page.fill("#sendCreateAccessCode", access_code)
    if deadline:
        page.fill("#id_deadline", local_input_value(page, deadline))
    if self_destruct:
        page.check("#id_self_destruct")
    if file:
        page.check("#input_type-file")
        page.set_input_files("#secretFile", str(file))
    else:
        page.fill("#secretText", text)
    if not submit:
        return None
    page.click("#sendPodSubmit")
    return wait_for_send_pod(page)


def wait_for_send_pod(page: Page) -> str:
    page.wait_for_url("**/pod/s-*/")
    wait_ready(page)
    return page.url


def unlock_with_access_code(page: Page, code: str):
    page.fill("#accessCode", code)
    page.click("#accessCodeSubmit")


def lock_with_wrong_codes(page: Page, attempts: int = 5):
    """Enter wrong access codes until an anonymous send pod locks"""
    for attempt in range(attempts):
        unlock_with_access_code(page, f"wrong {attempt}")
        remaining = attempts - attempt - 1
        if remaining:
            expect(page.locator("#accessCodeError")).to_contain_text(
                f"{remaining} attempt(s) remaining"
            )
    expect(page.locator("#accessCodeSection")).to_contain_text("Pod locked")
