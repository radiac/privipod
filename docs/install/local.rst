==================================
Running locally with remote access
==================================

These options let you run Privipod on your own machine and share it with others over
the internet without a server.

This is only practical in the short-term; you will need to keep it running until you
have transferred the secret.


ngrok
=====

`ngrok <https://ngrok.com>`_ creates a temporary public HTTPS tunnel to your local
machine. Free accounts get a random subdomain; paid accounts get a fixed domain.

.. code-block:: bash

    # Install ngrok, then:
    uv run privipod.py 0:8000

    # In a second terminal:
    ngrok http 0:8000

ngrok prints a URL like ``https://abc123.ngrok-free.app`` - share that with your
sender.

Once the transfer is complete, shut down privipod and ngrok to close the tunnel.


Cloudflare Tunnel
=================

`Cloudflare Tunnel <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/>`_
(``cloudflared``) creates a persistent tunnel from Cloudflare's edge to your machine
with no inbound firewall rules required.

.. code-block:: bash

    # Install cloudflared, authenticate once:
    cloudflared login

    # Start Privipod:
    uv run privipod.py 0:8000

    # Start the tunnel (one-off, for quick sharing):
    cloudflared tunnel --url http://localhost:8000

Cloudflare prints a public HTTPS URL. For a stable named tunnel (survives restarts),
follow the `Named Tunnels guide <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/>`_.
