=====
Usage
=====

Privipod has two kinds of pod:

* A **receive pod** collects a secret from someone else - you create it, send them the
  link, and they send you a secret through it.
* A **send pod** delivers a secret to someone else - you create it with the secret
  inside, and send them the link so they can decrypt it.

Your pods are listed on the **Your Pods** dashboard.


Receiving a secret
==================

1. Log in and click **Receive Secret**.
2. Configure the pod options (see below), then click **Create Pod**.

   - The browser generates a key pair and saves the private key to ``localStorage``.

3. Copy the pod URL and send it to whoever will share a secret with you.
4. The sender visits the URL, enters text or selects a file, and clicks **Send Secret**.
5. Your pod page updates when the secret arrives, and the secret is decrypted and
   displayed.

A receive pod accepts exactly one secret. Once a secret has been sent, the send form is
hidden and the pod status changes to "Secret received".


Sending a secret
================

1. Log in and click **Send Secret**.
2. Choose a recipient:

   - **Another user** of this Privipod instance. The secret is encrypted with their
     identity key (see :ref:`identity-keys`), so they must have set one up. They will
     need to log in to see it.
   - **Anonymous** - anyone with the link and the key. Privipod generates a one-off key
     pair for the pod. If server-stored keys are enabled, you choose an access code, and
     the private key is stored on the server encrypted with it. Otherwise the private
     key downloads as a file, which you send to the recipient yourself.

3. Enter the secret, configure the pod options, and click **Send secret**.
4. Copy the pod URL and send it to the recipient. For anonymous pods, send the access
   code or key file separately, using a different channel to the URL.
5. The recipient visits the URL, unlocks their key, and the secret is decrypted in their
   browser. Your pod page updates when they have decrypted it.

Anonymous pods allow 5 wrong access codes before they lock. The owner can unlock a
locked pod from its page to let the recipient try again.

If an anonymous pod was created with a key file, the owner can later store the key on
the server with an access code, by uploading the key file on the pod page.


Pod options
===========

Name
----

An optional label shown on the pod page and dashboard, shown to you and the other user.
Useful when you have several pods in flight.

It is kept in plain text in the database, so keep it vague if the context is sensitive.


Deadline
--------

An optional expiry date and time, entered in your browser's local time zone. It must be
in the future.

Once the deadline passes:

- A receive pod no longer accepts a secret, and a send pod can no longer be decrypted.
- The secret is destroyed as soon as the pod is next used, or within 5 minutes by a
  background cleanup task - whatever state the pod is in, including locked.
- The pod itself remains, with a log entry recording that it expired, until you delete
  it.

Use a deadline when you want the pod and any secret it holds to disappear automatically,
or to signal urgency to the other person.

For receive pods, make sure to retrieve your secret before the deadline.


Require sender authentication
-----------------------------

Receive pods only.

When checked, the sender must be logged in to your Privipod instance before they can
see the send form.

This adds a layer of security, ensuring an attacker cannot intercept a pod URL and
send their own response without also having valid login credentials for a user.

Without this option, anyone who has the pod URL can submit a secret.


Self-destruct
-------------

When enabled, the secret is destroyed on the server as soon as it has been decrypted.

The decrypted secret stays on screen until the page is closed, so save it first if you
need to keep it. After that it cannot be retrieved again.

The pod record and its access log remain until you delete it.

Use self-destruct for the highest-sensitivity secrets where you want no copy left on
the server after retrieval.


.. _access-log:

Access log
==========

Each pod keeps a log of what has happened to it, shown to the owner on the pod page:

Secret accessed
    The server sent the encrypted secret to a browser. For a receive pod this is when
    you open the pod page after the secret has arrived; for a send pod it is when the
    recipient opens the pod page, or enters the right access code for an anonymous pod
    with a server-stored key.

Secret decrypted
    A browser reported that it decrypted the secret successfully.

Failed access attempt
    Someone entered the wrong access code for an anonymous send pod.

Pod locked
    Too many failed access attempts.

Destroyed
    The secret was destroyed, with the reason (``self-destruct`` or ``expired``).

Bear in mind:

* **Secret accessed** is logged on every page load that includes the encrypted secret,
  so reloads add entries. Link previews in chat or email apps which fetch the page will
  also add entries. The encrypted secret is useless without the private key, but these
  entries tell you the link has been opened.
* **Secret decrypted** is reported by the recipient's browser, because the server
  cannot see the decryption happen. A modified client could decrypt the secret without
  reporting it, so treat this as a record of normal use rather than proof - the absence
  of a decrypted entry does not prove the secret has not been read. It cannot be
  faked by someone without the key: named recipients must be logged in, and anonymous
  pods require proof of the key.
* **Secret decryption is async** - opening the page of a receive pod will show the
  access log with "Secret accessed", but the "Secret decrypted" will happen after the
  page has been shown to you, and because the access log does not automatically reload,
  the decryption event will not appear until you refresh the page.


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


Keys
====

Key backup
----------

Use the **Download Key** button on a receive pod page to export its private key as a
JSON file (``privipod-key-<hash>.json``). Keep it safe - without it you cannot decrypt
the secret.

If you open a pod in a different browser (or after clearing storage), the **key
recovery** area appears. Import your ``.json`` key file, or load the key from the server
if you stored it there, to decrypt the secret.


.. _identity-keys:

Identity keys
-------------

Other users can only send you secrets directly once you have an identity key. Privipod
offers to generate one on your dashboard, and you can manage it from **Manage Keys** -
download a backup, or store it on the server protected by an access code so you can
decrypt secrets on other devices.

See :doc:`security` for details on how keys are stored and when they are removed.
