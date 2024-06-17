from functools import partial
import sys
import re
from datetime import datetime
from inspect import cleandoc
from textwrap import wrap
from typing import Iterable, NamedTuple, TextIO

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import Encoding


def _format_datetime(d: datetime) -> str:
    """
    There's some complexities with padding here, unfortunately.
    That's why we can't just do a single strftime.
    """

    d = d.astimezone()
    month = d.strftime("%b")
    day = f"{d.day:2}"

    rest = d.strftime("%H:%M:%S %Y %Z")

    return f"{month} {day} {rest}"


def _pubkey_alg_name(pk: CertificateIssuerPublicKeyTypes) -> str:
    # TODO: the rest, I guess.
    # I can script creating these and asking openssl to say it
    match pk:
        case rsa.RSAPublicKey():
            return "rsaEncryption"
        case _:
            raise ValueError("unsupported public key type... for now")


# def _pubkey_bitsize()
# def _pubkey_alg_name(pk: CERTIFICATE_PUBLIC_KEY_TYPES) -> str:
#     # TODO: the rest, I guess.
#     # I can script creating these and asking openssl to say it
#     match pk:
#         case rsa.RSAPublicKey():
#             return "rsaEncryption"
#         case _:
#             raise ValueError("unsupported public key type... for now")

# def _pubkey_bitsize()




_MOD_WIDTH = 45


# TODO: unified indentation strategy,
# verbosity
class PubKeyRepr(NamedTuple):
    key: rsa.RSAPublicKey  # TODO: support for other key types

    @property
    def nums(self):
        return self.key.public_numbers()

    @property
    def short(self):
        return f"Public-Key: ({self.key.key_size} bit)"

    def _lines(self) -> Iterable[str]:
        yield f"Public-Key: ({self.key.key_size} bit)"

        # TODO: where do the 00's come from?
        mod = _intersperse_colons(f"00{self.nums.n:x}")
        # mod width + 4 cuz of indentation
        yield "Modulus:"
        yield from wrap(
            mod,
            width=_MOD_WIDTH + 4,
            initial_indent=4 * " ",
            subsequent_indent=4 * " ",
        )
        exp = self.nums.e
        yield f"Exponent: {exp} ({exp:#x})"

    def __str__(self):
        # leading indentation from top `Certificate:` line is 4 levels (4 each)
        line_indentation = 4 * 4 * " "
        return ("\n" + line_indentation).join(self._lines())




def _general_name(name: x509.GeneralName) -> str:
    # TODO: the rest
    match name:
        case x509.DNSName():
            return f"DNS:{name.value}"
        case x509.IPAddress():
            return f"IP Address:{name.value}"
        case _:
            raise NotImplementedError(f"No support for {name}")




def _extension_value(ext: x509.ExtensionType) -> str:
    match ext:
        case x509.KeyUsage():
            return ", ".join(_key_usages(ext))
        case x509.ExtendedKeyUsage():
            # TODO: either map better names ourselves or contribute to cryptography
            return ", ".join(usage._name for usage in ext)
        case x509.SubjectKeyIdentifier():
            return _intersperse_colons(ext.digest.hex().upper())
        case x509.AuthorityKeyIdentifier():
            kid = ext.key_identifier
            assert kid is not None  # todo: what does this mean?
            # TODO: unclear if this blank line is because of AKI or because of SAN
            return f"keyid:{_intersperse_colons(kid.hex().upper())}\n"
        case x509.SubjectAlternativeName():
            return ", ".join(_general_name(name) for name in ext)
        case x509.BasicConstraints():
            return "CA:TRUE" if ext.ca else ""
        # case x509.AuthorityInformationAccess():
        #     return
        case x509.NameConstraints():
            s = []
            if ext.permitted_subtrees:
                s.append(', '.join(_general_name(x) for x in ext.permitted_subtrees))
            if ext.excluded_subtrees:
                s.append(', '.join(_general_name(x) for x in ext.excluded_subtrees))
            return "\n".join(s)
        case _:
            return f"extension value for {ext.__class__.__name__} not yet implemented but it looks like this: {ext}"
            # raise NotImplementedError(
            #     f"extension value for {ext.__class__.__name__} not yet implemented"
            # )


def view(cert: x509.Certificate, file: TextIO = sys.stdout):
    """
    View the certificate in a similar manner to openssl's `-text` output.
    """

    p = partial(print, file=file)

    # TODO: file issue about sig alg name being sunder
    version = cert.version.value
    version_human = version + 1

    serial_num_hex = _intersperse_colons(f"{cert.serial_number:x}")

    pubkey = cert.public_key()
    assert isinstance(pubkey, rsa.RSAPublicKey), "only rsa keys are supported for now"

    # why the extra space? the world may never know.
    signature = ("\n" + (9 * " ")).join(
        wrap(_intersperse_colons(cert.signature.hex()), width=54)
    )

    # TODO: these won't necessarily all be v3, will they?
    extensions = "\n".join(
        f"""{(3*4*' ')}X509v3 {_extension_name(extension)}
{(4*4*' ')}{_extension_value(extension.value)}"""
        for extension in cert.extensions
    )

    templated = cleandoc(
        f"""
Certificate:
    Data:
        Version: {version_human} ({version:#x})
        Serial Number:
            {serial_num_hex}
    Signature Algorithm: {cert.signature_algorithm_oid._name}
        Issuer: {cert.issuer.rfc4514_string()}
        Validity
            Not Before: {_format_datetime(cert.not_valid_before_utc)}
            Not After : {_format_datetime(cert.not_valid_after_utc)}
        Subject: {cert.subject.rfc4514_string()}
        Subject Public Key Info:
            Public Key Algorithm: {_pubkey_alg_name(pubkey)}
                {PubKeyRepr(pubkey).short}
        X509v3 extensions:
{extensions}
    Signature Algorithm: {cert.signature_algorithm_oid._name}
"""
        #  {signature}
        # {cert.public_bytes(Encoding.PEM).decode("ascii")}"""
    )

    print(templated, file=file)
