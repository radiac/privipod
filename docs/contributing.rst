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

The test suite is Playwright end-to-end - it drives a real browser against a running
Privipod instance. You need to start the server before running pytest.

.. code-block:: bash

    # Terminal 1 - start the server
    uv run python -m privipod 0:8765 --user=testuser --pass=testpass

    # Terminal 2 - install browsers (first time only), then run tests
    uv run playwright install chromium
    uv run pytest

The default test server URL is ``http://localhost:8765``. Override it with environment
variables if you want to test against a different instance:

.. code-block:: bash

    PRIVIPOD_URL=http://localhost:9000 \
    PRIVIPOD_USER=admin \
    PRIVIPOD_PASS=secret \
    uv run pytest tests/ -v


Running with Docker
-------------------

To run the full test suite in an isolated container (no local server or browser
install needed):

.. code-block:: bash

    docker compose -f tests/docker-compose.yml up --build
