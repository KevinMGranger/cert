import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Self

from attrs import field, frozen
from cryptography import x509
from kmg.kitchen.attrs import simple_validator
from kmg.kitchen.datetime import must_be_positive_timedelta, must_be_tz_aware

# cryptography.x509's type hierarchy for extensions can be confusing,
# so here's an explanation for these helpers:

# extension classes inherit from an ExtensionType.
# Their instances are just instances of those types.

# `Extension`s are those instances with the added context of criticality.


def wrapext(ext: x509.ExtensionType, critical: bool) -> x509.Extension:
    return x509.Extension(ext.oid, critical, ext)


def unwrapext(ext: x509.Extension) -> tuple[x509.ExtensionType, bool]:
    return ext.value, ext.critical


def parse_name(name: str) -> x509.IPAddress | x509.DNSName:
    """
    Determine if the name is an IP address or a DNS name,
    and wrap it in those types accordingly.

    Note that it technically assumes any non-IP address
    is a valid DNS name-- it does no validation at that layer.
    """
    try:
        ipaddr = ipaddress.ip_address(name)
        return x509.IPAddress(ipaddr)
    except ValueError:
        return x509.DNSName(name)


# time specification:
# some APIs accept certificate lifespans as either a time-to-live
# or a "not after" date.
# These wrapper types allow us to represent it as either,
# and avoid giving inconsistent data.

_TTL_CHAR_TO_KW = dict(d="days", h="hours", m="minutes", s="seconds")


def _simple_ttl_parse(ttl: str) -> timedelta:
    try:
        ttl_seconds = int(ttl)
        return timedelta(seconds=ttl_seconds)
    except ValueError:
        pass

    unit_char = ttl[-1]

    try:
        unit_arg_name = _TTL_CHAR_TO_KW[unit_char]
        value = int(ttl[:-1])
    except KeyError:
        raise ValueError(f"Unknown TTL unit {unit_char} for TTL {ttl}")
    except ValueError:
        raise ValueError(f"Invalid value for ttl {ttl}")

    return timedelta(**{unit_arg_name: value})


@frozen
class Ttl:
    _VAULT_FIELD_NAME = "ttl"

    td: timedelta = field(
        validator=simple_validator(must_be_positive_timedelta),
    )

    @classmethod
    def from_str(cls, s: str) -> Self:
        return cls(_simple_ttl_parse(s))

    def __str__(self):
        return f"{int(self.td.total_seconds())}s"


class NotAfter:
    _VAULT_FIELD_NAME = "not_after"

    dt: datetime = field(validator=simple_validator(must_be_tz_aware))

    def __str__(self):
        return self.dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


End = Ttl | NotAfter
