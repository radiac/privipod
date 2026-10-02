# Privipod

[![PyPI](https://img.shields.io/pypi/v/privipod.svg)](https://pypi.org/project/privipod/)
[![Documentation](https://readthedocs.org/projects/privipod/badge/?version=latest)](https://privipod.readthedocs.io/en/latest/)
[![Tests](https://github.com/radiac/privipod/actions/workflows/ci.yml/badge.svg)](https://github.com/radiac/privipod/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/radiac/privipod/branch/main/graph/badge.svg)](https://codecov.io/gh/radiac/privipod)

Privipod is a lightweight self-hosted service for sharing secrets and files.

It uses end-to-end encryption - all encryption and decryption happens entirely in your
browser, so the server never sees your unencrypted data.

Read the [full documentation](https://privipod.readthedocs.io/en/latest/).


## Receive a secret

1. Run Privipod somewhere both of you can access - for example, remotely on a VPS, or
   locally using ngrok.
2. Create a "pod" - the browser generates a key pair, stores your private key locally,
   and sends the public key to the server.
3. Share the pod URL with the sender.
4. The sender visits the URL and their browser uses your public key to encrypt their
   secret, then sends it to the Privipod server.
5. You collect the secret, and the browser uses your private key to decrypt it.


## Send a secret

1. Create a send pod with your secret, for another registered user or an anonymous
   recipient.
2. The browser encrypts the secret with the recipient's public key - their identity
   key, or a one-off key pair for an anonymous recipient - and sends it to the server.
3. Share the pod URL with the recipient, and for anonymous recipients, send the access
   code or key file separately.
4. The recipient visits the URL, and their browser decrypts the secret.


## Quick start

It's easiest to run with [uv](https://docs.astral.sh/uv/) and
[ngrok](https://ngrok.com/docs/guides/share-localhost/quickstart):

```bash
# Start with a temporary database (data lost on shutdown)
uvx privipod

# Use ngrok to share with people outside your network
ngrok http 127.0.0.1:8000
```

Open `http://localhost:8000` in your browser. See the
[installation docs](https://privipod.readthedocs.io/en/latest/install/) for
more deployment options.

Or you can install it and run it directly:

```bash
pip install privipod
privipod
ngrok http 127.0.0.1:8000
```

And it takes several arguments to customise it:

```bash
# Start with a permanent database and specify a username and password
uvx privipod --store=privipod.db --user=admin --pass=changeme 0:7000
```
