from cryptography import x509
import ipaddress


def parse_name(name: str) -> x509.IPAddress | x509.DNSName:
    try:
        ipaddr = ipaddress.ip_address(name)
        return x509.IPAddress(ipaddr)
    except ValueError:
        return x509.DNSName(name)
