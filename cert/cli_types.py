import click
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CERTIFICATE_PRIVATE_KEY_TYPES,
)

from cert.certs.ser import InvalidPrivateKeyType, load_cert_private_key
from cert.certs.utils import parse_name as parse_x509_name


class X509GeneralNameParamType(click.ParamType):
    name = "x509 General Name"

    def convert(self, value: str, param, ctx):
        return parse_x509_name(value)


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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, mode="rb", lazy=False)

    def convert(self, value: str, param, ctx) -> CERTIFICATE_PRIVATE_KEY_TYPES:
        file = super().convert(value, param, ctx)
        try:
            return load_cert_private_key(file.read())
        except InvalidPrivateKeyType as e:
            if ctx is not None:
                ctx.fail(e.message)
            else:
                raise
