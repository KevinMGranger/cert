import threading
import shlex
import subprocess
import tempfile
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from typing import BinaryIO

import click
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)

from cert.certs import (
    CertBuilderArgs,
    _openssl_view,
    make_private_key,
    sign_builder,
    simple_common_name,
)
from cert.certs.ser import serialize_private, serialize_public_cert
from cert.serve import make_context, make_server

from .cli_types import (
    X509_GENERAL_NAME,
    X509Certificate,
    X509Certificates,
    X509PrivateKey,
)


@click.group()
def cli():
    pass


# TODO: because cryptography doesn't have sufficient support for it yet,
# we'll have to generate and inform of the steps for cross-signing.
# @click.option("--cakey", required=True, type=X509PrivateKey())
# @click.option("--cacert", required=True, type=X509Certificate())
# @click.option("--")
# def xsign(
#     cakey: CertificateIssuerPrivateKeyTypes,
#     cacert: x509.Certificate,
#     target_cert: x509.Certificate
#     constraint: str,
# ):


def request_config(name: str, constraint: str) -> str:
    # TODO: do we still need dist_name if not constraining? yes, no?
    _templated = f"""[req]
prompt=no
distinguished_name=dist_name
req_extensions=extensions

[dist_name]
CN={name}

[extensions]
# basicConstraints=critical,CA:true,pathlen:0
nameConstraints=critical,permitted;DNS:{constraint}
"""
    return _templated


@cli.command()
@click.option(
    "--cakey",
    required=True,
    type=X509PrivateKey(),
    help="The CA cert private key",
)
@click.option("--cacert", required=True, type=X509Certificate(), help="The CA cert")
@click.option(
    "--target", required=True, type=X509Certificate(), help="the target CA to constrain"
)
@click.option("-o", "--out", required=True, type=click.File("xb", lazy=False))
@click.argument("constraint", required=True)
def try_xsign(
    cakey: CertificateIssuerPrivateKeyTypes,
    cacert: x509.Certificate,
    target: x509.Certificate,
    constraint: str,
    out: BinaryIO,
):
    ba = CertBuilderArgs.cross_sign_with_constraint(target, cacert.subject, constraint)
    builder = ba.make_builder()
    signed = sign_builder(builder, cakey)
    out.write(serialize_public_cert(signed))


@cli.command()
@click.option("--cakey", required=True)
@click.option("--cacert", required=True)
@click.option("--target", required=True)
@click.option("-o", "--out", required=True)
@click.argument("constraint", required=True)
def xsign(
    cakey: str,
    cacert: str,
    target: str,
    out: str,
    constraint: str,
):
    "cross-sign a CA cert"
    print("NOTE: until support lands in `cryptography`, we will shell out to openssl.")
    with tempfile.TemporaryDirectory() as d:
        config_path = f"{d}/constraint.cfg"
        print("writing following config to", d)
        # todo: ask for name?
        # todo: does the subject name need to be the same?
        config = request_config(f"constraint to {constraint}", constraint)
        print(config)
        with open(config_path, "x") as f:
            f.write(config)
        print("cross-signing...")
        cmd = "openssl x509 -in".split() + [
            target,
            "-CA",
            cacert,
            "-CAkey",
            cakey,
            "-set_serial",
            str(x509.random_serial_number()),
            "-sha256",
            "-extensions",
            "extensions",
            "-extfile",
            config_path,
            "-out",
            out,
        ]
        print(shlex.join(cmd))
        # TODO
        _result = subprocess.run(cmd, check=True)


# TODO: password option
@cli.command()
@click.argument("file", type=click.File(mode="xb", lazy=False))
def mkpriv(file: BinaryIO):
    "Make a private key."
    key = make_private_key()
    bytes_ = serialize_private(key)
    file.write(bytes_)


@cli.command()
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
    privkey: CertificateIssuerPrivateKeyTypes,
    out: BinaryIO,
    commonname: str,
    # expiration: datetime | None,
):
    "create a CA cert"
    # TODO: restrictions
    cn = simple_common_name(commonname)
    # TODO: this is wrong, and this is why we rely on typing
    pubkey = privkey.public_key()

    # TODO: was 2 to account for roots. should be configurable.
    # wait should it have been 1 the whole time? does "0" mean one more?
    constraint_ext = x509.BasicConstraints(True, 1)
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


@cli.command()
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
    privkey: CertificateIssuerPrivateKeyTypes,
    cakey: CertificateIssuerPrivateKeyTypes,
    cacert: x509.Certificate,
    out: BinaryIO,
    commonname: str,
    # expiration: datetime | None,
    sans: list[x509.GeneralName],
):
    "create a ca-signed leaf cert"
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


@cli.command()
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
    "Serve a test page over TLS using the given cert bundle."
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


@cli.command()
@click.argument("certs", type=X509Certificates(), required=True)
def view(certs: list[x509.Certificate]):
    "View a cert a-la OpenSSL's -text output."
    for cert in certs:
        _openssl_view.view(cert)
