import requests

def asn_lookup(target: str) -> str:
    """
    Look up ASN, BGP prefix, and routing info for an IP or domain.
    BGPView API — free, no key. ASN = who owns the IP block.
    Useful for pivoting: find every IP block owned by the same org.
    """
    if not target:
        return "Need an IP or ASN (e.g. AS13335 or 1.1.1.1)."

    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]

    # If it's an ASN query
    if target.upper().startswith("AS"):
        asn_num = target.upper().replace("AS", "")
        url = f"https://api.bgpview.io/asn/{asn_num}"
    else:
        # IP or domain — resolve via BGPView IP endpoint
        url = f"https://api.bgpview.io/ip/{target}"

    try:
        resp = requests.get(url, timeout=15, headers={"Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return "[TIMEOUT] BGPView API took too long."
    except Exception as e:
        return f"[ERROR] {e}"

    if data.get("status") != "ok":
        return f"[FAIL] BGPView returned: {data.get('status_message', 'Unknown error')}"

    result_data = data.get("data", {})
    lines = [f"[ASN LOOKUP] {target}\n"]

    if target.upper().startswith("AS"):
        asn_info = result_data
        lines += [
            f"  ASN         : AS{asn_info.get('asn', 'N/A')}",
            f"  Name        : {asn_info.get('name', 'N/A')}",
            f"  Description : {asn_info.get('description_short', 'N/A')}",
            f"  Country     : {asn_info.get('country_code', 'N/A')}",
            f"  Website     : {asn_info.get('website', 'N/A')}",
            f"  Type        : {asn_info.get('type', 'N/A')}",
            f"  Abuse Email : {', '.join(asn_info.get('abuse_contacts', {}).get('emails', [])) or 'N/A'}",
        ]
        prefixes = asn_info.get("prefixes", [])
        if prefixes:
            lines.append(f"\n  IPv4 Prefixes ({len(prefixes)}):")
            for p in prefixes[:20]:
                lines.append(f"    {p.get('prefix', '?')}  [{p.get('name', '?')}]")
    else:
        # IP result
        prefixes = result_data.get("prefixes", [])
        rir = result_data.get("rir_allocation", {})
        lines += [
            f"  IP          : {result_data.get('ip', target)}",
            f"  RIR         : {rir.get('rir_name', 'N/A')}",
            f"  Allocation  : {rir.get('prefix', 'N/A')} (since {rir.get('date_allocated', 'N/A')[:10] if rir.get('date_allocated') else 'N/A'})",
        ]
        if prefixes:
            lines.append(f"\n  BGP Prefixes / ASNs:")
            for p in prefixes:
                asns = p.get("asns", [])
                for a in asns:
                    lines.append(f"    AS{a.get('asn', '?')}  {a.get('name', '?')}  [{a.get('country_code', '?')}]")
                lines.append(f"    Prefix: {p.get('prefix', '?')}")
                lines.append("")

    return "\n".join(lines)
