from pathlib import Path
from typing import TypeVar, Generic

import click
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)

from cert.certs.ser import InvalidPrivateKeyType, load_cert_private_key
from cert.certs.utils import parse_name as parse_x509_name

T = TypeVar("T", bound=click.ParamType)


class WithPath(Generic[T]):
    def __init__(self, path: Path | str, value: T):
        self.path = Path(path)
        self.value = value


class ParamWithPath(Generic[T], click.ParamType):
    def __init__(self, wrapped: T, *args, **kwargs):
        self.name = wrapped.name
        self.wrapped = wrapped
        super().__init__(*args, **kwargs, mode="rb", lazy=False)

    def convert(self, value: str, param, ctx) -> WithPath[T]:
        converted = self.wrapped.convert(value, param, ctx)
        return WithPath(value, converted)


class X509GeneralNameParamType(click.ParamType):
    name = "x509 General Name"

    def convert(self, value: str, param, ctx):
        return parse_x509_name(value)


class X509Name(click.ParamType):
    name = "x509 Name"

    def convert(self, value: str, param, ctx):
        return x509.Name.from_rfc4514_string(value)


X509_GENERAL_NAME = X509GeneralNameParamType()


class X509Certificate(click.File):
    name = "x509 Certificate"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, mode="rb", lazy=False)

    def convert(self, value: str, param, ctx) -> x509.Certificate:
        file = super().convert(value, param, ctx)
        return x509.load_pem_x509_certificate(file.read())


class X509Certificates(click.File):
    name = "x509 Certificates"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, mode="rb", lazy=False)

    def convert(self, value: str, param, ctx) -> list[x509.Certificate]:
        file = super().convert(value, param, ctx)
        return x509.load_pem_x509_certificates(file.read())


class X509PrivateKey(click.File):
    name = "x509 Private Key"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, mode="rb", lazy=False)

    def convert(self, value: str, param, ctx) -> CertificateIssuerPrivateKeyTypes:
        file = super().convert(value, param, ctx)
        try:
            return load_cert_private_key(file.read())
        except InvalidPrivateKeyType as e:
            if ctx is not None:
                ctx.fail(e.message)
            else:
                raise
