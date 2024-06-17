"""
Various ways to view certificates,
including Openssl-like, friendly, json and yaml formats.
"""

from __future__ import annotations
import re
from textwrap import wrap
import yaml
from cryptography import x509
from typing import Iterable, NamedTuple

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


def _intersperse_colons(s: str) -> str:
    return ":".join(wrap(s, width=2))


def _key_usages(ku: x509.KeyUsage) -> Iterable[str]:
    for attr, name in _KEY_USAGE_MAPPING.items():
        try:
            if getattr(ku, attr):
                yield name
        except ValueError:
            return "UNKNOWN"


CRIT = "!critical"


def _general_name(name: x509.GeneralName) -> str:
    # TODO: the rest
    match name:
        case x509.DNSName():
            return name.value
        case x509.IPAddress():
            return str(name.value)
        case _:
            raise NotImplementedError(f"No support for {name}")


class ExtensionType(NamedTuple):
    critical: bool
    ext: x509.ExtensionType


def repr_type(d: yaml.BaseDumper, extype: ExtensionType):
    critical = extype.critical
    ext = extype.ext
    match ext:
        case x509.KeyUsage():
            if critical:
                return d.represent_sequence(CRIT, _key_usages(ext))
            else:
                return d.represent_data([*_key_usages(ext)])
        # case x509.ExtendedKeyUsage():
        #     # TODO: either map better names ourselves or contribute to cryptography
        #     return ", ".join(usage._name for usage in ext)
        case x509.SubjectKeyIdentifier():
            if critical:
                return d.represent_scalar(
                    CRIT, _intersperse_colons(ext.digest.hex().upper())
                )
            else:
                return d.represent_data(_intersperse_colons(ext.digest.hex().upper()))
        case x509.AuthorityKeyIdentifier():
            kid = ext.key_identifier
            assert kid is not None  # todo: what does this mean?
            if critical:
                return d.represent_scalar(
                    CRIT, f"keyid:{_intersperse_colons(kid.hex().upper())}"
                )
            else:
                return d.represent_data(
                    f"keyid:{_intersperse_colons(kid.hex().upper())}"
                )
        case x509.SubjectAlternativeName():
            if critical:
                return d.represent_sequence(CRIT, map(_general_name, ext))
            else:
                return d.represent_data([_general_name(name) for name in ext])
        case x509.BasicConstraints():
            # should be handled at higher level
            return None
            # return "CA:TRUE" if ext.ca else ""
        # case x509.AuthorityInformationAccess():
        #     return
        case x509.NameConstraints():
            if ext.permitted_subtrees is None:
                permitted = None
            else:
                permitted = [_general_name(x) for x in ext.permitted_subtrees]
            if ext.excluded_subtrees is None:
                excluded = None
            else:
                excluded = [_general_name(x) for x in ext.excluded_subtrees]
            dict_ = dict(permitted=permitted, excluded=excluded)
            if critical:
                return d.represent_mapping(CRIT, dict_)
            else:
                return d.represent_data(dict_)
        case _:
            return d.represent_data(
                f"extension value for {ext.__class__.__name__} not yet implemented but it looks like this: {ext}"
            )
            # raise NotImplementedError(
            #     f"extension value for {ext.__class__.__name__} not yet implemented"
            # )


yaml.add_representer(ExtensionType, repr_type)


def _break_pascal_case_name(s: str) -> list[str]:
    return re.findall(r"[A-Z][a-z]+", s)


def _extension_name(ext: x509.Extension) -> str:
    return " ".join(_break_pascal_case_name(type(ext.value).__name__))


class Extensions(NamedTuple):
    exts: x509.Extensions


def repr_exts(d: yaml.Dumper, exts: Extensions):
    return d.represent_data(
        [
            {_extension_name(ext): ExtensionType(ext.critical, ext.value)}
            for ext in exts.exts
            # TODO: cleaner way for this
            if not isinstance(ext.value, x509.BasicConstraints)
        ]
    )


yaml.add_representer(Extensions, repr_exts)


class IsCa(NamedTuple):
    critial: bool
    is_ca: bool


def repr_isca(d: yaml.Dumper, self: IsCa):
    if self.critial:
        # TODO: pyyaml broken :(
        # return d.represent_scalar(CRIT, self.is_ca)
        return d.represent_bool(self.is_ca)
    else:
        return d.represent_bool(self.is_ca)


yaml.add_representer(IsCa, repr_isca)


def destructure(cert: x509.Certificate):
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = IsCa(bc.critical, bc.value.ca)
    except x509.ExtensionNotFound:
        is_ca = None

    return (
        dict(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
        )
        | ({"ca": is_ca} if is_ca is not None else {})
        | dict(
            valid={
                "start": cert.not_valid_after_utc.astimezone(),
                "until": cert.not_valid_after_utc.astimezone(),
            },
            extensions=Extensions(cert.extensions),
            serial=_intersperse_colons(f"{cert.serial_number:x}"),
            sig_algo=cert.signature_algorithm_oid._name,
            version=cert.version.value + 1,
        )
    )


# def repr_cert(d: yaml.BaseDumper, cert: x509.Certificate):
#     d.represent(f"{cert.serial_number:x}")

# yaml.add_representer(x509.Certificate, repr_cert)
