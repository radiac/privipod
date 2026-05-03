=====================
Deploying to a server
=====================

These options assume you have a Linux server with a domain name pointed at it.


Run with Docker
===============

The easiest way to deploy. Download the three config files from GitHub, edit the
domain in the ``Caddyfile``, and start:

.. code-block:: bash

    curl -O https://raw.githubusercontent.com/radiac/privipod/main/docker-compose.yml
    mkdir -p docker
    curl -O --output-dir docker https://raw.githubusercontent.com/radiac/privipod/main/docker/Dockerfile
    curl -O --output-dir docker https://raw.githubusercontent.com/radiac/privipod/main/docker/Caddyfile

Then edit the three required values in ``docker-compose.yml``:

- ``PRIVIPOD_HOSTNAME`` - your domain name (e.g. ``privipod.example.com``). This
  enables deployed mode: strict ``ALLOWED_HOSTS`` checking, HSTS headers, and
  correct share link generation.
- ``PRIVIPOD_SECRET_KEY`` - a random secret key for Django session signing. You can
  generate a strong one with:

  .. code-block:: bash

      uv run --with django python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

- ``PRIVIPOD_PASS`` - password for the admin user. Set it here for an initial password,
  then change it once logged in.

Also replace ``privipod.example.com`` in ``docker/Caddyfile`` with your domain:

.. code-block:: bash

    $EDITOR docker/Caddyfile
    $EDITOR docker-compose.yml

    docker compose up -d

Caddy handles TLS automatically via Let's Encrypt. Check logs for confirmation
that the service started in deployed mode:

.. code-block:: bash

    docker compose logs -f

You can change the admin password after logging in via the Django admin at ``/admin/``.


Systemd service
===============

It's more complicated than docker, but if you prefer to run it directly on your server,
you can run it with systemd, and then use a web server such as nginx or caddy to handle
HTTPS and route traffic to the service.

Create ``/etc/systemd/system/privipod.service`` with something like this:

.. code-block:: ini

    [Unit]
    Description=Privipod
    After=network.target

    [Service]
    Type=simple
    User=privipod
    WorkingDirectory=/opt/privipod
    ExecStart=uvx privipod \
        --store /opt/privipod/privipod.db \
        localhost:8000
    Restart=on-failure
    RestartSec=5

    [Install]
    WantedBy=multi-user.target


Run privipod once to create a user (see :ref:`command-line-options` for ways to do
this):

.. code-block:: bash

   uvx privipod --store /opt/privipod/privipod.db


Enable and start it:

.. code-block:: bash

    sudo useradd -r -s /sbin/nologin privipod
    sudo mkdir -p /opt/privipod
    sudo chown -R privipod:privipod /opt/privipod

    sudo systemctl daemon-reload
    sudo systemctl enable --now privipod

    # Check logs
    sudo journalctl -u privipod -f


You will now need to configure a web server to forward to privipod on
``localhost:8000``.
