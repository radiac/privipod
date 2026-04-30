=====
Usage
=====

Basic workflow
==============

1. Log in and click **Create New Pod**.
2. Configure the pod options (see below), then click **Create Pod**.

   - The browser generates a keypair and saves the private key to ``localStorage``.

3. Copy the pod URL and send it to whoever will share a secret with you.
4. The sender visits the URL, enters text or selects a file, and clicks **Send Secret**.
5. Return to your pod page - the secret is automatically decrypted and displayed.

A pod accepts exactly one secret. Once a secret has been sent, the send form is hidden
and the pod status changes to "sent".


Pod options
===========

Name
----

An optional label shown on the pod page and dashboard, shown to you and the other user.
Useful when you have several pods in flight.

It is kept in plain text in the database, so keep it vague if the context is sensitive.


Deadline
--------

An optional expiry date and time.

Once the deadline passes:

- The sender can no longer submit a secret.
- The pod is automatically deleted within 5 minutes by a background cleanup task -
  whether or not a secret was sent.

Use a deadline when you want the pod and any secret it holds to disappear automatically,
or to signal urgency to the sender.

Make sure to retrieve your secret before the deadline.


Require sender authentication
-----------------------------

When checked, the sender must be logged in to your Privipod instance before they can
see the send form.

This adds a layer of security, ensuring an attacker cannot intercept a pod URL and
send their own response without also having valid login credentials for a user.

Without this option, anyone who has the pod URL can submit a secret.


Self-destruct
-------------

When enabled, the pod record is permanently deleted from the server the moment you view
the decrypted secret. The private key is also removed from ``localStorage``. After that
point the secret is gone from all storage - server and browser.

Use self-destruct for the highest-sensitivity secrets where you want no trace left
after retrieval.


Sending secrets
===============

Text
----

Type or paste the secret directly into the text area and click **Send Secret**. The
browser encrypts it in place before it leaves your machine.


Files
-----

Select a file using the file picker. Both the file content and the original filename
are encrypted in the browser before upload - the server never sees the unencrypted
versions of either.

The maximum upload size defaults to 10 MB and can be changed with the ``--max-size``
option (see :ref:`command-line-options`).


Key backup
==========

Use the **Download Key** button on the pod page to export your private key as a JSON
file (``privipod-key-<hash>.json``). Keep it safe - without it you cannot decrypt the
secret.

If you open a pod in a different browser (or after clearing storage), the **key
recovery** area appears. Import your ``.json`` key file or paste the JWK text to
decrypt without a page reload.

See :doc:`security` for details on how keys are stored and when they are removed.
