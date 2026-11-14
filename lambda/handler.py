import ipaddress


def parse_attacker_ip(raw):
    """Return a public IPv4 address, or raise ValueError."""
    if not isinstance(raw, str):
        raise ValueError("attacker_ip must be a string")
    ip = ipaddress.ip_address(raw.strip())
    if ip.version != 4:
        raise ValueError("only IPv4 is supported")
    if not ip.is_global:
        raise ValueError(f"{ip} is not a public address")
    return ip


def load_allowlist(value):
    """Turn '1.2.3.4,5.6.7.0/24' into a list of networks."""
    networks = []
    for item in value.split(","):
        item = item.strip()
        if item:
            networks.append(ipaddress.ip_network(item, strict=False))
    return networks


def is_allowlisted(ip, networks):
    return any(ip in network for network in networks)