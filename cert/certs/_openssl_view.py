import sys
import re
from datetime import datetime
from inspect import cleandoc
from textwrap import wrap
from typing import Iterable, NamedTuple, TextIO

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CERTIFICATE_PUBLIC_KEY_TYPES
from cryptography.hazmat.primitives.serialization import Encoding


def _format_datetime(d: datetime) -> str:
    """
    There's some complexities with padding here, unfortunately.
    That's why we can't just do a single strftime.
    """
    month = d.strftime("%b")
    day = f"{d.day:2}"

    # WARNING: assuming naive but UTC, since that's what cryptography gives us.
    # otherwise, a naive datetime will be assumed to be localtime, if you use `.astimezone`!
    rest = d.strftime("%H:%M:%S %Y GMT")

    return f"{month} {day} {rest}"


def _pubkey_alg_name(pk: CERTIFICATE_PUBLIC_KEY_TYPES) -> str:
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


def _intersperse_colons(s: str) -> str:
    return ":".join(wrap(s, width=2))


_MOD_WIDTH = 45


class PubKeyRepr(NamedTuple):
    key: rsa.RSAPublicKey  # TODO: support for other key types

    @property
    def nums(self):
        return self.key.public_numbers()

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


def _break_pascal_case_name(s: str) -> list[str]:
    return re.findall(r"[A-Z][a-z]+", s)


_KEY_USAGE_ATTR_NAMES = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)

_KEY_USAGE_MAPPING = {
    attr: attr.replace("_", " ").title() for attr in _KEY_USAGE_ATTR_NAMES
}


def _extension_name(ext: x509.Extension) -> str:
    name = " ".join(_break_pascal_case_name(type(ext.value).__name__))
    criticality = "critical" if ext.critical else ""
    return f"{name}: {criticality}"


def _extension_value(ext: x509.ExtensionType) -> str:
    match ext:
        case x509.KeyUsage():
            return ", ".join(
                name for attr, name in _KEY_USAGE_MAPPING.items() if getattr(ext, attr)
            )
        case x509.ExtendedKeyUsage():
            # TODO: either map better names ourselves or contribute to cryptography
            return ", ".join(usage._name for usage in ext)
        case _:
            raise NotImplementedError


def view(cert: x509.Certificate, file: TextIO = sys.stdout):
    """
    View the certificate in a similar manner to openssl's `-text` output.
    """
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

    extensions = "\n".join(
        f"""{(3*4*' ')}X509v3 {_extension_name(extension)}
{(4*4*' ')}{_extension_value(extension.value)}"""
        for extension in cert.extensions[0:2]
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
            Not Before: {_format_datetime(cert.not_valid_before)}
            Not After : {_format_datetime(cert.not_valid_after)}
        Subject: {cert.subject.rfc4514_string()}
        Subject Public Key Info:
            Public Key Algorithm: {_pubkey_alg_name(pubkey)}
                {PubKeyRepr(pubkey)}
        X509v3 extensions:
{extensions}
            X509v3 Subject Key Identifier: 
                1C:1F:60:A6:4C:0D:17:10:E4:19:51:5D:17:7E:11:13:1A:52:4A:7F
            X509v3 Authority Key Identifier: 
                keyid:61:D9:BD:D4:FB:86:5B:96:80:AE:E9:43:63:63:B3:9E:EC:00:EA:18

            X509v3 Subject Alternative Name: 
                DNS:test.i.kmg.fyi
    Signature Algorithm: {cert.signature_algorithm_oid._name}
         {signature}
{cert.public_bytes(Encoding.PEM).decode("ascii")}"""
    )

    print(templated, file=file)
