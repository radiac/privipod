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

    # Edit docker/Caddyfile - replace privipod.example.com with your domain
    $EDITOR docker/Caddyfile

    docker compose up -d

Caddy handles TLS automatically via Let's Encrypt. Check logs for the auto-generated
admin user credentials with:

.. code-block:: bash

    docker compose logs -f

Don't forget to change the password once you've logged in.


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
