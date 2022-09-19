import ipaddress
from attrs.converters import default_if_none
from typing import Iterable
from attrs import frozen, field
from functools import partial
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric.types import (
    CERTIFICATE_PRIVATE_KEY_TYPES,
    CERTIFICATE_PUBLIC_KEY_TYPES,
)

make_private_key = partial(
    rsa.generate_private_key,
    public_exponent=65537,
    key_size=4096,
)


serialize_private = partial(
    rsa.RSAPrivateKey.private_bytes,
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
)

serialize_public_cert = partial(
    x509.Certificate.public_bytes,
    encoding=serialization.Encoding.PEM,
)


def _san_converter(
    sans: Iterable[x509.GeneralName] | x509.SubjectAlternativeName,
) -> x509.SubjectAlternativeName:
    if isinstance(sans, x509.SubjectAlternativeName):
        return sans
    return x509.SubjectAlternativeName(sans)


# TODO: url constraints for CA, supporting cross-signing and whatnot
@frozen(kw_only=True)
class CertBuilderArgs:
    subject: x509.Name
    issuer: x509.Name
    # public_key: rsa.RSAPublicKey
    public_key: CERTIFICATE_PUBLIC_KEY_TYPES
    not_valid_before: datetime = field(
        default=None, converter=default_if_none(factory=datetime.now)  # type: ignore
    )
    not_valid_after: datetime = field(
        default=None,
        converter=default_if_none(factory=lambda: datetime.now() + timedelta(days=30)),  # type: ignore
    )

    subject_alternative_name: x509.SubjectAlternativeName | None = field(
        default=None, converter=_san_converter
    )
    extensions: tuple[x509.Extension, ...] = field(default=tuple(), converter=tuple)

    serial_number: int = field(factory=x509.random_serial_number)

    def make_builder(self) -> x509.CertificateBuilder:
        builder = (
            x509.CertificateBuilder()
            .subject_name(self.subject)
            .issuer_name(self.issuer)
            .public_key(self.public_key)
            .serial_number(self.serial_number)
            .not_valid_before(self.not_valid_before)
            .not_valid_after(self.not_valid_after)
        )
        if self.subject_alternative_name is not None:
            # TODO: should this be critical?
            builder = builder.add_extension(
                self.subject_alternative_name, critical=False
            )
        for extension in self.extensions:
            builder = builder.add_extension(extension.value, extension.critical)

        return builder

    def make_and_sign(
        self,
        private_key: CERTIFICATE_PRIVATE_KEY_TYPES,
        algorithm: hashes.HashAlgorithm = hashes.SHA256(),
    ) -> x509.Certificate:
        builder = self.make_builder()
        return builder.sign(private_key, algorithm)


def parse_name(name: str) -> x509.IPAddress | x509.DNSName:
    try:
        ipaddr = ipaddress.ip_address(name)
        return x509.IPAddress(ipaddr)
    except ValueError:
        return x509.DNSName(name)


def simple_common_name(name: str) -> x509.Name:
    return x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, name),))
