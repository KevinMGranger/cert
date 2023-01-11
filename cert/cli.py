import threading
import typing
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CERTIFICATE_PRIVATE_KEY_TYPES,
)

from cert.certs import (
    CertBuilderArgs,
    make_private_key,
    sign_builder,
    simple_common_name,
)
from cert.certs.ser import serialize_private, serialize_public_cert
from cert.serve import make_context, make_server

from .cli_types import X509_GENERAL_NAME, X509Certificate, X509PrivateKey


@click.group()
def cli():
    pass


# TODO: password option
@cli.command(help="make a private key")
@click.argument("file", type=click.File(mode="xb", lazy=False))
def mkpriv(file: typing.BinaryIO):
    key = make_private_key()
    bytes_ = serialize_private(key)
    file.write(bytes_)


@cli.command(help="create a CA cert")
@click.option("-p", "--privkey", required=True, type=X509PrivateKey())
@click.option("-o", "--out", required=True, type=click.File("xb", lazy=False))
@click.option(
    "--commonname",
    "--name",
    required=True,
    type=str,
    default=datetime.now() + timedelta(days=40),
)
# @click.option("--exp", type=click.DateTime)
def mkca(
    privkey: CERTIFICATE_PRIVATE_KEY_TYPES,
    out: typing.BinaryIO,
    commonname: str,
    # expiration: datetime | None,
):
    # TODO: restrictions
    cn = simple_common_name(commonname)
    # TODO: this is wrong, and this is why we rely on typing
    pubkey = privkey.public_key()

    constraint_ext = x509.BasicConstraints(True, 2)
    # TODO: figure out what these are and what chrome/macos needs
    key_usage = x509.KeyUsage(True, True, True, True, True, True, True, False, False)

    builder = CertBuilderArgs(
        subject=cn,
        issuer=cn,
        public_key=pubkey,
        extensions=(
            x509.Extension(constraint_ext.oid, True, constraint_ext),
            x509.Extension(key_usage.oid, True, key_usage),
        ),
    ).make_builder()
    cacert = sign_builder(builder, privkey)
    out.write(serialize_public_cert(cacert))


@cli.command(help="create a ca-signed leaf cert")
@click.option(
    "-p",
    "--privkey",
    required=True,
    type=X509PrivateKey(),
    help="The leaf cert private key",
)
@click.option(
    "--cakey",
    required=True,
    type=X509PrivateKey(),
    help="The CA cert private key",
)
@click.option("--cacert", required=True, type=X509Certificate(), help="The CA cert")
@click.option("-o", "--out", required=True, type=click.File("xb", lazy=False))
@click.option(
    "--commonname",
    "--name",
    required=True,
    type=str,
    default=datetime.now() + timedelta(days=40),
)
# @click.option("--exp", type=click.DateTime)
@click.argument("sans", required=True, nargs=-1, type=X509_GENERAL_NAME)
def mkcert(
    privkey: CERTIFICATE_PRIVATE_KEY_TYPES,
    cakey: CERTIFICATE_PRIVATE_KEY_TYPES,
    cacert: x509.Certificate,
    out: typing.BinaryIO,
    commonname: str,
    # expiration: datetime | None,
    sans: list[x509.GeneralName],
):
    # TODO: restrictions
    cn = simple_common_name(commonname)

    constraint_ext = x509.BasicConstraints(True, 2)
    # TODO: figure out what these are and what chrome/macos needs
    key_usage = x509.KeyUsage(True, True, True, True, True, True, True, False, False)

    pubkey = privkey.public_key()

    builder = CertBuilderArgs(
        subject=cn,
        issuer=cacert.subject,
        public_key=pubkey,
        # not_valid_after=expiration,
        subject_alternative_name=x509.SubjectAlternativeName(sans),
        extensions=(
            x509.Extension(constraint_ext.oid, True, constraint_ext),
            x509.Extension(key_usage.oid, True, key_usage),
        ),
    ).make_builder()
    leafcert = sign_builder(builder, cakey)
    out.write(serialize_public_cert(leafcert))


@cli.command(help="simple https server for testing cert")
@click.option(
    "-p",
    "--privkey",
    required=True,
    type=click.Path(exists=True, readable=True),
    help="The leaf cert private key",
)
@click.option(
    "--cert",
    required=True,
    type=click.Path(exists=True, readable=True),
    help="The leaf cert",
)
@click.option(
    "--browser",
    default=False,
    is_flag=True,
    show_default=True,
    help="Launch a browser pointed at the running server",
)
def serve(
    privkey: str,
    cert: str,
    browser: bool,
):
    ctx = make_context(Path(cert), Path(privkey))
    server = make_server(ctx)
    port = server.server_port

    ip_url = f"https://127.0.0.1:{port}/"

    print("Serving on:")
    print(ip_url)
    print(f"https://localhost:{port}/")

    with server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()

        if browser:
            webbrowser.open(ip_url)

        thread.join()
