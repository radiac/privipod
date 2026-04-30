========
Security
========

Encryption
==========

All encryption and decryption happens in the browser using the
`Web Crypto API <https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API>`_.

Key generation uses RSA-OAEP 2048-bit key pairs. Encryption is hybrid: AES-256-GCM
encrypts the data, and RSA-OAEP encrypts the AES key. The payload sent to the server
is a Base64-encoded JSON object containing ``encryptedKey``, ``encryptedData``, and
``iv``.


Key storage
===========

Each pod gets its own private/public key pair.

Private keys are stored in ``localStorage`` under ``privipod_key_<hash>``.

They persist until:

- The pod is set to self-destruct (the key is removed after the owner decrypts the
  secret); or
- You clear your browser storage manually; or
- The key expires and you visit the dashboard for it to be pruned.

.. note::

    For the truly paranoid, use a dedicated private browsing session and clear storage
    afterwards, or download the key to a secure location and delete it from the browser.


HTTPS requirement
=================

Privipod must be served over HTTPS in production. The Web Crypto API requires a
`secure context <https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts>`_,
and without HTTPS the private key stored in ``localStorage`` is accessible to any
script on the same origin. See :doc:`install` for configuration examples.
