from datetime import datetime, timedelta
from cryptography import x509
from pathlib import Path
from typing import cast
import typing
import click
from cert.cert import (
    make_private_key,
    serialize_private,
    simple_common_name,
    CertBuilderArgs,
    serialize_public_cert,
)
from cert.serve import make_server, make_context
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from .types import X509_GENERAL_NAME, X509Certificate, X509PrivateKey
from cryptography.hazmat.primitives.asymmetric.types import (
    CERTIFICATE_PRIVATE_KEY_TYPES,
)


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
@click.argument("sans", required=True, nargs=-1, type=X509_GENERAL_NAME)
def mkca(
    privkey: CERTIFICATE_PRIVATE_KEY_TYPES,
    out: typing.BinaryIO,
    commonname: str,
    # expiration: datetime | None,
    sans: list[x509.GeneralName],
):
    # TODO: restrictions
    cn = simple_common_name(commonname)
    # TODO: this is wrong, and this is why we rely on typing
    pubkey = privkey.public_key()
    builder = CertBuilderArgs(
        subject=cn,
        issuer=cn,
        public_key=pubkey,
        # not_valid_after=expiration,
        subject_alternative_name=x509.SubjectAlternativeName(sans),
    )
    cacert = builder.make_and_sign(privkey)
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
    leafcert: x509.Certificate,
    out: typing.BinaryIO,
    commonname: str,
    # expiration: datetime | None,
    sans: list[x509.GeneralName],
):
    # TODO: restrictions
    cn = simple_common_name(commonname)
    pubkey = privkey.public_key()
    builder = CertBuilderArgs(
        subject=cn,
        issuer=leafcert.subject,
        public_key=pubkey,
        # not_valid_after=expiration,
        subject_alternative_name=x509.SubjectAlternativeName(sans),
    )
    leafcert = builder.make_and_sign(cakey)
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
def serve(
    privkey: str,
    cert: str,
):
    ctx = make_context(Path(cert), Path(privkey))
    server = make_server(ctx)
    print(f"Serving on {server.server_port}")
    server.serve_forever()
