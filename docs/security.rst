========
Security
========

Encryption
==========

All encryption and decryption happens in the browser using the
`Web Crypto API <https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API>`_.

Key generation uses RSA-OAEP 2048-bit key pairs. Encryption is hybrid: AES-256-GCM
encrypts the data, and RSA-OAEP encrypts the AES key.


Key storage
===========

There are three types of keys:

Identity keys
-------------

Each authenticated user creates a public/private identity key. The private key is stored
in the ``localstorage`` of the user's browser, and the public key is stored on the
server.

Users can either download their private key, or opt to store an encrypted copy on the
server (see :ref:`server-stored-keys` below).

Identity keys are used when one user creates a send pod to send a secret to another
user - the secret is encrypted with the recipient's public key before storing it on the
server.


Receive pod keys
----------------

Each receive pod gets its own public/private key pair when it is created.

Receive pod private keys are stored in the ``localstorage`` of the owner's browser, and
the public key is stored on the server, ready to encrypt the sender's secret.


Anonymous send pod keys
-----------------------

Send pods sent to an anonymous user get their own public/private key pair.

The private key can then either be downloaded and sent to the sender separately using a
secure method (eg by USB key). Alternatively, the sender can set an access code (a
secure password) to encrypt it with and store it on the server, and then they can share
the access code with the recipient separately (eg by SMS or DM),


.. _server-stored-keys:

Server-stored keys
==================

As mentioned above, Privipod can optionally store an encrypted copy of a private key on
the server. This lets you decrypt a secret from a different device without transferring
a key file out-of-band, and in the case of anonymous pods, share the private key .

The key is encrypted in the browser before being sent to the server.

.. warning::

    Storing a key on the server weakens its security in the event of a database breach.
    Your encrypted secret is protected by a 256-bit AES key; the server-stored private key
    is protected only by your access code. Use a strong, randomly generated access code -
    not a memorable word or number.

    Each pod uses a distinct access code, so compromising one
    access code does not expose keys on other pods.

Paranoid server administrators can disable this feature entirely:

.. code-block:: bash

    uv run python -m privipod --no-server-keys
    # or
    PRIVIPOD_NO_SERVER_KEYS=1 uv run python -m privipod


Expiry and destruction
======================

When a pod's deadline passes or it self-destructs, the server wipes the encrypted
secret, encrypted filename, and any server-stored key and access-code verifier for the
pod. The pod record and its access log are kept until the owner deletes it.

Expired pods are destroyed as soon as they are next used, and by a background task
every 5 minutes - except in ``--debug`` mode, where the background task does not run.

The access log records who fetched and decrypted a secret, and when. Decryption
happens in the browser, so "Secret decrypted" entries are reported by the browser
rather than observed by the server - see :ref:`access-log`.


Secret key
==========

Privipod uses a secret key to sign sessions and CSRF tokens. If you do not set one,
a random key is generated on every startup - this logs a warning and means all users
are logged out whenever the process restarts.

Set a persistent key via the ``PRIVIPOD_SECRET_KEY`` environment variable:

.. code-block:: bash

    export PRIVIPOD_SECRET_KEY="your-long-random-string"

The key should be at least 50 characters long, contain a mix of letters, digits, and
symbols, and be generated randomly - never use a memorable phrase or reuse a key from
another project.

In the Docker deployment, add it to ``docker-compose.yml``::

    environment:
      - PRIVIPOD_SECRET_KEY=your-long-random-string-here

For systemd, set it in the ``[Service]`` section::

    Environment=PRIVIPOD_SECRET_KEY=your-long-random-string-here


HTTPS requirement
=================

Privipod must be served over HTTPS in production. The Web Crypto API requires a
`secure context <https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts>`_,
and without HTTPS the private key stored in ``localStorage`` is accessible to any
script on the same origin. See :doc:`install/index` for configuration examples.
