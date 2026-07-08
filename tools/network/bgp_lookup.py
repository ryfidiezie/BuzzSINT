import requests

def bgp_lookup(target: str) -> str:
    """
    Full BGP/routing table lookup via BGPView.
    Shows upstream providers, peering relationships, and announced prefixes.
    Great for mapping an org's full IP footprint from a single ASN.
    """
    if not target:
        return "Need an ASN (AS13335), IP, or domain."

    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    lines = [f"[BGP LOOKUP] {target}\n"]

    if target.upper().startswith("AS"):
        asn = target.upper().replace("AS", "")
        endpoints = {
            "prefixes": f"https://api.bgpview.io/asn/{asn}/prefixes",
            "upstreams": f"https://api.bgpview.io/asn/{asn}/upstreams",
            "peers": f"https://api.bgpview.io/asn/{asn}/peers",
            "ixs": f"https://api.bgpview.io/asn/{asn}/ixs",
        }

        for section, url in endpoints.items():
            try:
                resp = requests.get(url, timeout=10)
                data = resp.json()
                if data.get("status") != "ok":
                    continue
                result = data.get("data", {})
                lines.append(f"  === {section.upper()} ===")

                if section == "prefixes":
                    v4 = result.get("ipv4_prefixes", [])
                    v6 = result.get("ipv6_prefixes", [])
                    lines.append(f"  IPv4 ({len(v4)}):")
                    for p in v4[:20]:
                        lines.append(f"    {p.get('prefix'):20s}  {p.get('name', '')}")
                    if len(v4) > 20:
                        lines.append(f"    ... and {len(v4)-20} more")
                    lines.append(f"  IPv6 ({len(v6)}):")
                    for p in v6[:10]:
                        lines.append(f"    {p.get('prefix')}")

                elif section in ("upstreams", "peers"):
                    items = result.get("ipv4_" + ("upstreams" if section == "upstreams" else "peers"), [])
                    for item in items[:15]:
                        lines.append(f"    AS{item.get('asn','?'):8}  {item.get('name','?')} [{item.get('country_code','?')}]")

                elif section == "ixs":
                    for ix in result[:10]:
                        lines.append(f"    {ix.get('name','?')} — {ix.get('city','?')}, {ix.get('country_code','?')}")

                lines.append("")
            except Exception as e:
                lines.append(f"  Error fetching {section}: {e}\n")
    else:
        # IP lookup
        url = f"https://api.bgpview.io/ip/{target}"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            if data.get("status") == "ok":
                result = data.get("data", {})
                rir = result.get("rir_allocation", {})
                lines += [
                    f"  IP           : {target}",
                    f"  RIR          : {rir.get('rir_name', 'N/A')}",
                    f"  Allocation   : {rir.get('prefix', 'N/A')}",
                    f"  Date Alloc.  : {rir.get('date_allocated', 'N/A')}",
                    "",
                ]
                for prefix in result.get("prefixes", []):
                    for asn in prefix.get("asns", []):
                        lines += [
                            f"  ASN          : AS{asn.get('asn')}",
                            f"  Name         : {asn.get('name', 'N/A')}",
                            f"  Description  : {asn.get('description', 'N/A')}",
                            f"  Country      : {asn.get('country_code', 'N/A')}",
                        ]
        except Exception as e:
            lines.append(f"  Error: {e}")

    return "\n".join(lines)
