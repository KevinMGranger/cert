from datetime import datetime, timedelta
from cryptography import x509
from pathlib import Path
from typing import cast
import typing
import click
from cert import cert
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.types import (
    CERTIFICATE_PRIVATE_KEY_TYPES,
    PRIVATE_KEY_TYPES,
)


class X509GeneralNameParamType(click.ParamType):
    name = "x509 General Name"

    def convert(self, value: str, param, ctx):
        return cert.parse_name(value)


X509_GENERAL_NAME = X509GeneralNameParamType()


class X509Certificate(click.File):
    name = "x509 Certificate"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, mode="rb", lazy=False)

    def convert(self, value: str, param, ctx) -> x509.Certificate:
        file = super().convert(value, param, ctx)
        return x509.load_pem_x509_certificate(file.read())


class X509PrivateKey(click.File):
    name = "x509 Private Key"
    MSG = "Private key was not compatible with a certificate key type"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, mode="rb", lazy=False)

    def convert(self, value: str, param, ctx) -> CERTIFICATE_PRIVATE_KEY_TYPES:
        file = super().convert(value, param, ctx)
        privkey = load_pem_private_key(file.read(), password=None)
        if not isinstance(privkey, CERTIFICATE_PRIVATE_KEY_TYPES):  # type: ignore # works in 3.10, why does it complain?
            if ctx is not None:
                ctx.fail(self.MSG)
            else:
                raise ValueError(self.MSG)
        else:
            return privkey  # type: ignore
