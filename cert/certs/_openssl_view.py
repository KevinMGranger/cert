import sys
from datetime import datetime
from inspect import cleandoc
from textwrap import wrap
from typing import Iterable, NamedTuple, TextIO

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CERTIFICATE_PUBLIC_KEY_TYPES


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
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Key Agreement
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                1C:1F:60:A6:4C:0D:17:10:E4:19:51:5D:17:7E:11:13:1A:52:4A:7F
            X509v3 Authority Key Identifier: 
                keyid:61:D9:BD:D4:FB:86:5B:96:80:AE:E9:43:63:63:B3:9E:EC:00:EA:18

            X509v3 Subject Alternative Name: 
                DNS:test.i.kmg.fyi
    Signature Algorithm: sha256WithRSAEncryption
         6f:8d:92:28:51:53:d9:76:d7:65:70:07:eb:75:1e:85:47:e6:
         e7:cb:0b:5e:3a:65:53:91:74:6f:c7:b1:0f:97:8b:3d:a6:a1:
         0c:72:d2:9c:40:79:0e:7c:b1:02:7f:f6:4f:d6:b4:27:be:da:
         df:7b:0b:b6:50:cb:1d:2d:4a:55:fd:81:01:f9:71:c6:28:34:
         17:da:29:61:6d:b3:95:43:19:a9:eb:9b:9d:00:a5:bf:01:bd:
         5d:29:92:16:1e:a9:e1:09:7b:e7:ec:52:25:58:97:b4:19:7a:
         59:94:8c:54:6e:7e:d5:cc:08:7f:a8:af:79:fe:3d:4c:dc:b4:
         21:20:00:83:02:c6:97:dc:ba:88:7e:72:2a:3e:8d:aa:c7:5d:
         ee:c5:ef:e9:b5:9d:50:ce:dd:33:42:c1:84:6e:49:c7:78:e6:
         ed:59:e3:85:dd:fa:c7:75:46:83:e1:be:d5:d5:a2:b3:f4:db:
         46:0e:33:d0:b4:dc:c5:62:9e:9e:8d:f0:22:44:a4:69:95:68:
         f1:61:66:8e:01:be:9d:ee:9f:fd:c4:1a:f7:38:60:a2:2d:59:
         c1:73:a7:6f:f5:4f:c9:09:90:21:d9:04:42:3a:57:98:8c:4f:
         e4:8b:2f:35:54:d5:f8:2a:1b:a7:5e:da:22:0c:52:55:8f:46:
         bc:66:86:ea
-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUSUS+dEkNMwioA7WFF5R/ucnakxAwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAxMJaS5rbWcuZnlpMB4XDTIzMDEwOTIyNDkzNloXDTIzMDEx
MDIyNTAwNVowGTEXMBUGA1UEAxMOdGVzdC5pLmttZy5meWkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCiHHBVbybrG8OD57gghlV7cS+Z2FpYOwF2ml9f
0bX0o5ZJK5xUk3pi5YmeqKJWeUddQSjpp91xRP0Mh3PALGfqmg2202JcqpVqYHon
dd/6/OLzgI+qfCpL7Wcpkd9Wf0yWl1QvIMcEEAhaoQyrm3qlo+0VXlH/jFRW+/Ys
y2S7HNTZ5M847N+pUqtCVb2t1bSfgdEkunH7QamF5+ZHsFOoDeHQvJrAGcLyvq3m
sj8BW8Ui6wXvJcBoan3ngJmFDhyVMwIgAYAq472xmCDGOCbR0LZYzuEeDyBK3ocm
7T1xU81RXm4aVEnI8CBphY1QC/dAeXmhxLP8eGP7ORnLv/WdAgMBAAGjgY0wgYow
DgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAd
BgNVHQ4EFgQUHB9gpkwNFxDkGVFdF34RExpSSn8wHwYDVR0jBBgwFoAUYdm91PuG
W5aArulDY2OznuwA6hgwGQYDVR0RBBIwEIIOdGVzdC5pLmttZy5meWkwDQYJKoZI
hvcNAQELBQADggEBAG+NkihRU9l212VwB+t1HoVH5ufLC146ZVORdG/HsQ+Xiz2m
oQxy0pxAeQ58sQJ/9k/WtCe+2t97C7ZQyx0tSlX9gQH5ccYoNBfaKWFts5VDGanr
m50Apb8BvV0pkhYeqeEJe+fsUiVYl7QZelmUjFRuftXMCH+or3n+PUzctCEgAIMC
xpfcuoh+cio+jarHXe7F7+m1nVDO3TNCwYRuScd45u1Z44Xd+sd1RoPhvtXVorP0
20YOM9C03MVinp6N8CJEpGmVaPFhZo4Bvp3un/3EGvc4YKItWcFzp2/1T8kJkCHZ
BEI6V5iMT+SLLzVU1fgqG6de2iIMUlWPRrxmhuo=
-----END CERTIFICATE-----
"""
    )

    print(templated, file=file)
