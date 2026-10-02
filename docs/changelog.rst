=========
Changelog
=========

0.3.0, 2026-10-03
-----------------

Features:

* Send pods to other users
* Send pods to anonymous users
* Secure storage for private keys on the server (optional)
* Pod access logs
* Improved pod polling for owners

Changes:

* Pod urls have changed
* Expired and self-destructed pods destroy the secret, but aren't deleted automatically
  so the logs are retained

Bugfixes:

* Deadlines now use local times instead of UTC


0.2.0, 2026-05-03
-----------------

Features:

* Refactor into deployable project
* UX improvements, improved mobile support
* Security improvements


0.1.0, 2026-04-30
-----------------

Initial release
