from datetime import datetime, timedelta
from typing import Callable, Self

import attrs.converters
from attrs import field, frozen
from attrs.converters import default_if_none
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CERTIFICATE_PRIVATE_KEY_TYPES,
    CERTIFICATE_PUBLIC_KEY_TYPES,
)
from .utils import wrapext
from cryptography.x509.oid import NameOID
from kmg.kitchen.attrs import type_passthrough


def make_private_key(
    # todo: callable protocol for positional and kwargs, although is that really necessary?
    keygenfunc: Callable[
        [int, int], CERTIFICATE_PRIVATE_KEY_TYPES
    ] = rsa.generate_private_key,
    /,
    *,
    public_exponent=65537,
    key_size=4096,
):
    return keygenfunc(public_exponent, key_size)


def _thirty_days_from_now():
    return datetime.now() + timedelta(days=30)


# TODO: url constraints for CA, supporting cross-signing and whatnot
@frozen(kw_only=True)
class CertBuilderArgs:
    "Standard arguments for a certificate builder."

    subject: x509.Name
    issuer: x509.Name
    public_key: CERTIFICATE_PUBLIC_KEY_TYPES
    not_valid_before: datetime = field(
        default=None,
        converter=default_if_none(factory=datetime.now),  # type: ignore
    )
    not_valid_after: datetime = field(
        default=None,
        converter=default_if_none(factory=_thirty_days_from_now),  # type: ignore
    )

    subject_alternative_name: x509.SubjectAlternativeName | None = field(
        default=None,
        converter=attrs.converters.optional(
            type_passthrough(x509.SubjectAlternativeName, x509.SubjectAlternativeName)
        ),
    )
    extensions: tuple[x509.Extension, ...] = field(default=tuple(), converter=tuple)

    serial_number: int = field(factory=x509.random_serial_number)

    @classmethod
    def cross_sign_with_constraint(
        cls, other: x509.Certificate, issuer: x509.Name, constraint: str
    ) -> Self:
        constraint_ext = wrapext(
            x509.NameConstraints([x509.DNSName(constraint)], None), True
        )

        all_extensions = (*other.extensions, constraint_ext)

        return cls(
            subject=other.subject,
            issuer=issuer,
            public_key=other.public_key(),
            not_valid_before=other.not_valid_before,
            not_valid_after=other.not_valid_after,
            extensions=all_extensions,
        )

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


def sign_builder(
    builder: x509.CertificateBuilder,
    private_key: CERTIFICATE_PRIVATE_KEY_TYPES,
    algorithm: hashes.HashAlgorithm = hashes.SHA256(),
):
    return builder.sign(private_key, algorithm)


# TODO: is this necessary for the browser?
ORG = x509.NameAttribute(NameOID.ORGANIZATION_NAME, "cert python cli")


def simple_common_name(name: str) -> x509.Name:
    return x509.Name(
        (
            ORG,
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, name),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        )
    )
