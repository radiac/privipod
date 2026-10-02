===
FAQ
===

**What happens if I lose my private key?**

The secret cannot be recovered. This is by design - the server cannot help because it
never had the private key or unencrypted data. Always download a key backup for
important pods.


**Can I use Privipod from a different browser or device?**

Yes. You have two options:

1. Export the key from the original browser using **Download Key**, then import it on
   the new device using the key recovery area on the pod page.

2. If server-stored keys are enabled, you can store the key on the server, protected by
   an access code, and load it on the other device with that code.


**Is the database encrypted?**

The database only ever stores secrets in an encrypted format without the private keys.
However, the SQLite file itself is not encrypted at rest.


**What does the the other person see?**

For a receive pod, the sender sees the pod name, whether a deadline is set, and whether
self-destruct is enabled. They cannot see any previously submitted secrets or the
recipient's private key.

For a send pod, the recipient either logs in and has the secret decrypted for them
using their identity key, or anonymous users are given a password field used to
decrypt the secret.


**Can I tell whether someone has read my secret?**

The owner of a pod can see its access log on the pod page, which records when the
encrypted secret was fetched and when a browser reported decrypting it. See
:ref:`access-log` for what these entries can and cannot tell you.


**Can multiple people send to the same receive pod?**,
or **I sent the wrong secret to a receive pod, can I send it again?**

No - a receive pod accepts one secret. Once sent, the send form is no longer shown and
the pod status is marked "Secret received". This is a security measure to prevent
attackers changing a secret after data has been sent, or to show the sender that their
form has been compromised, so they can notify the recipient directly.
