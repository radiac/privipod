===
FAQ
===

**What happens if I lose my private key?**

The secret cannot be recovered. This is by design - the server cannot help because it
never had the private key or unencrypted data. Always download a key backup for
important pods.


**Can I use Privipod from a different browser or device?**

Yes. Export the key from the original browser using **Download Key**, then import it on
the new device using the key recovery area on the pod page.


**Which browsers are supported?**

Any modern browser with Web Crypto API support.


**Is the database encrypted?**

The database only ever stores secrets in an encrypted format without the private keys.
However, the SQLite file itself is not encrypted at rest.


**What does the sender see?**

The sender sees the pod name, whether a deadline is set, and whether self-destruct is
enabled. They cannot see any previously submitted secrets or the recipient's private
key.


**Can multiple people send to the same pod?**,
or **I sent the wrong secret, can I send it again?**

No - a pod accepts one secret. Once sent, the send form is no longer shown and the pod
status is marked "sent". This is a security measure to prevent attackers changing a
secret after genuine data has been sent.
