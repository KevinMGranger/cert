"""
(De)serialization tools.
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def serialize_private(
    privkey: CertificateIssuerPrivateKeyTypes,
    *,
    encryption_algorithm: serialization.KeySerializationEncryption = serialization.NoEncryption(),
) -> bytes:
    "Serialize a private key."
    return privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm,
    )


class InvalidPrivateKeyType(ValueError):
    def __init__(self, key_type: str, *args, **kwargs):
        message = (
            f"Private key was not compatible with a certificate key type ({key_type})"
        )
        super().__init__(message, *args, **kwargs)
        self.message = message


def serialize_public_cert(cert: x509.Certificate):
    "Serialize a public key in PEM format."
    # TODO: function not really necessary
    return cert.public_bytes(serialization.Encoding.PEM)


def load_cert_private_key(data: bytes) -> CertificateIssuerPrivateKeyTypes:
    privkey = load_pem_private_key(data, password=None)
    if not isinstance(privkey, CertificateIssuerPrivateKeyTypes):
        # todo: this started working?  # type: ignore # works in 3.10, why does it complain?
        raise InvalidPrivateKeyType(type(privkey).__name__)
    else:
        return privkey


__all__ = [
    "serialize_private",
    "InvalidPrivateKeyType",
    "serialize_public_cert",
    "load_cert_private_key",
]
