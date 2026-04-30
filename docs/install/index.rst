============
Installation
============

.. toctree::
    :hidden:

    local
    deploy


Privipod can either be run locally on your machine and configured with remote access,
or run remotely on a server.

.. note::

   Privipod **must** be served over HTTPS - the Web Crypto API requires a secure
   connection.


The quickest way to run Privipod is with `uvx <https://docs.astral.sh/uv/>`_:

.. code-block:: bash

    uvx privipod --store privipod.db --user admin --pass changeme

This runs Privipod on port 8000. Open ``http://localhost:8000`` in your browser.

Next steps:

* :doc:`local` - expose your local instance over the internet
* :doc:`deploy` - run on a remote server



.. _command-line-options:

Command-line options
====================

``host:port``:
  ``0:8000``
  Address to listen on, e.g. ``0:8000`` or ``127.0.0.1:5000``

``--store PATH``:
  Path to SQLite database file for disk persistence.

  Default is in-memory (ephemeral), all data lost on shutdown.

``--max-size N``:
  Maximum file size in MB.

  Note that due to encryption and storage the bandwidth and storage will be larger than
  the original size of the file.

``--user NAME``:
  Specify the username for the admin user created on first run.

  Default is the current system username.

``--pass PASS``
  Specify the password for the admin user created on first run.

  Because this password may be stored in your command line history, you should change
  your password in Privipod.

  If left blank, a password will be generated.

``--debug``
  Enable Django debug mode.

  In debug mode, expired pods will not be automatically removed.

  Default is off

.. code-block:: bash

    # In-memory, default port
    uvx privipod

    # Persistent storage, port 8080
    uvx privipod --store privipod.db 0:8080

    # Create an admin user on first run
    uvx privipod --store privipod.db --user=admin --pass=changeme

    # All options
    uvx privipod --store privipod.db --max-size 50 --debug --user admin --pass test
