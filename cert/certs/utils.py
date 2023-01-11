import ipaddress

from cryptography import x509


def ext_type_to_ext(ext: x509.ExtensionType, critical: bool) -> x509.Extension:
    return x509.Extension(ext.oid, critical, ext)


def ext_to_ext_type(ext: x509.Extension) -> tuple[x509.ExtensionType, bool]:
    return ext.value, ext.critical


def parse_name(name: str) -> x509.IPAddress | x509.DNSName:
    try:
        ipaddr = ipaddress.ip_address(name)
        return x509.IPAddress(ipaddr)
    except ValueError:
        return x509.DNSName(name)
