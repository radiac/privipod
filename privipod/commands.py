import logging

import click

from . import config


@click.command()
@click.argument(
    "address",
    required=False,
    default=None,
)
@click.option(
    "--store",
    metavar="PATH",
    envvar="PRIVIPOD_STORE",
    default=None,
    help="Path to SQLite database file for disk persistence",
)
@click.option(
    "--max-size",
    type=int,
    default=10,
    show_default=True,
    envvar="PRIVIPOD_MAX_SIZE",
    help="Max upload size in MB",
)
@click.option(
    "--user",
    default=None,
    envvar="PRIVIPOD_USER",
    help="Username for login",
)
@click.option(
    "--pass",
    "password",
    default=None,
    envvar="PRIVIPOD_PASS",
    help="Password for user",
)
@click.option(
    "--secret-key",
    "secret_key",
    default=None,
    envvar="PRIVIPOD_SECRET_KEY",
    help="Django secret key; generated if not set (see docs)",
)
@click.option(
    "--no-server-keys",
    "no_server_keys",
    is_flag=True,
    default=False,
    envvar="PRIVIPOD_NO_SERVER_KEYS",
    help="Disable server-side encrypted key storage",
)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Debug mode, for devs",
)
@click.option(
    "--hostname",
    "hostnames",
    multiple=True,
    metavar="HOST",
    envvar="PRIVIPOD_HOSTNAME",
    help="Allowed hostname (eg, example.com); enables deployed mode. Can be repeated.",
)
def cli(address, store, max_size, user, password, secret_key, no_server_keys, debug, hostnames):
    """Privipod - Lightweight encrypted secret transfer service."""
    config.address = address
    config.hostnames = list(hostnames)
    config.store = store
    config.max_size_mb = max_size
    config.debug = debug
    config.user = user
    config.password = password
    config.secret_key = secret_key
    config.allow_server_keys = not no_server_keys

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    from . import server

    server.main()


def invoke():
    cli()
