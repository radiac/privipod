"""
Pytest configuration and fixtures for Privipod tests.

Requires a running Privipod instance. The BASE_URL environment variable
controls which server to test against (default: http://localhost:8765).

Start the server before running tests:
    uv run privipod.py 0:8765 --user testuser --pass testpass
"""

import os

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, Playwright

BASE_URL = os.environ.get("PRIVIPOD_URL", "http://localhost:8765")
TEST_USER = os.environ.get("PRIVIPOD_USER", "testuser")
TEST_PASS = os.environ.get("PRIVIPOD_PASS", "testpass")


@pytest.fixture(scope="session")
def base_url() -> str:
    return BASE_URL


@pytest.fixture(scope="session")
def browser_type_launch_args():
    return {"headless": True}


@pytest.fixture(scope="session")
def playwright_instance(playwright: Playwright):
    return playwright


@pytest.fixture(scope="session")
def browser(playwright: Playwright) -> Browser:
    browser = playwright.chromium.launch(headless=True)
    yield browser
    browser.close()


@pytest.fixture
def owner_context(browser: Browser) -> BrowserContext:
    """A browser context logged in as the test owner."""
    context = browser.new_context()
    page = context.new_page()
    page.goto(f"{BASE_URL}/login/")
    page.fill('input[name="username"]', TEST_USER)
    page.fill('input[name="password"]', TEST_PASS)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE_URL}/")
    yield context
    context.close()


@pytest.fixture
def owner_page(owner_context: BrowserContext) -> Page:
    page = owner_context.new_page()
    yield page
    page.close()


@pytest.fixture
def sender_context(browser: Browser) -> BrowserContext:
    """A fresh browser context with no login (anonymous sender)."""
    context = browser.new_context()
    yield context
    context.close()


@pytest.fixture
def sender_page(sender_context: BrowserContext) -> Page:
    page = sender_context.new_page()
    yield page
    page.close()
