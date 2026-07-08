import ipaddress

def cidr_calc(target: str) -> str:
    """
    CIDR / subnet calculator.
    Input: IP, CIDR block (10.0.0.0/24), or IP/mask (192.168.1.0/255.255.255.0).
    Outputs: network addr, broadcast, host range, usable hosts, mask, wildcard.
    Also generates the IP range for use in other tools.
    """
    if not target:
        return "Need an IP/CIDR (e.g. 192.168.1.0/24 or 10.0.0.1)."

    target = target.strip()

    # If no prefix length, assume /32
    if "/" not in target:
        target += "/32"

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        return f"[ERROR] Invalid CIDR: {e}"

    lines = [f"[CIDR CALC] {target}\n"]

    is_v6 = isinstance(network, ipaddress.IPv6Network)

    lines += [
        f"  Network      : {network.network_address}",
        f"  Broadcast    : {network.broadcast_address}" if not is_v6 else f"  Last Address : {network.broadcast_address}",
        f"  Prefix       : /{network.prefixlen}",
        f"  Netmask      : {network.netmask}",
        f"  Wildcard     : {network.hostmask}",
        f"  Version      : IPv{'6' if is_v6 else '4'}",
        f"  Num Addresses: {network.num_addresses:,}",
        f"  Usable Hosts : {max(0, network.num_addresses - 2):,}" if not is_v6 else f"  Usable Hosts : {network.num_addresses:,}",
        f"  Private      : {'Yes' if network.is_private else 'No'}",
        f"  Loopback     : {'Yes' if network.is_loopback else 'No'}",
        f"  Multicast    : {'Yes' if network.is_multicast else 'No'}",
        f"  Global       : {'Yes' if network.is_global else 'No'}",
    ]

    # First/last usable hosts
    hosts = list(network.hosts())
    if hosts:
        lines.append(f"\n  First Host   : {hosts[0]}")
        lines.append(f"  Last Host    : {hosts[-1]}")

    # Subnetting helper
    if network.prefixlen < 30 and not is_v6:
        lines.append(f"\n  Split into /25 subnets:")
        try:
            for sub in list(network.subnets(new_prefix=min(network.prefixlen + 1, 30)))[:8]:
                lines.append(f"    {sub}")
        except Exception:
            pass

    # Common subnets cheat sheet
    if network.prefixlen == 0:
        lines.append("\n  Common subnet sizes:")
        for prefix in [8, 16, 24, 25, 26, 27, 28, 29, 30]:
            n = ipaddress.ip_network(f"0.0.0.0/{prefix}")
            lines.append(f"    /{prefix:2d}  {n.num_addresses:>10,} addresses  ({max(0, n.num_addresses-2):>10,} hosts)")

    return "\n".join(lines)
