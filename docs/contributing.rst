============
Contributing
============

Contributions are welcome, preferably via pull request. Check the GitHub issues to see
what needs work, or raise an issue to discuss a new feature before building it.


Installing
==========

Fork the project on GitHub, then clone your fork:

.. code-block:: bash

    git clone https://github.com/radiac/privipod.git
    cd privipod
    uv sync --group dev


Testing
=======

There are two test suites:

* Unit tests in ``tests/``, which test the Django views and models directly.
* End-to-end tests in ``tests/integration/``, which use Playwright to test functionality
  with a browser.

To run the tests:

.. code-block:: bash

    # Install browsers (first time only)
    uv run playwright install chromium

    # Run everything
    uv run pytest

    # Run only the unit tests, or only the end-to-end tests
    uv run pytest tests/ --ignore=tests/integration
    uv run pytest tests/integration

To see what the end-to-end tests are doing, run them in a visible browser, or keep a
Playwright trace of failures to open with ``uv run playwright show-trace``:

.. code-block:: bash

    uv run pytest tests/integration --headed --slowmo 500
    uv run pytest tests/integration --tracing retain-on-failure


Running with Docker
-------------------

To run the full test suite in an isolated container (no local browser install needed):

.. code-block:: bash

    docker compose -f tests/docker-compose.yml up --build
