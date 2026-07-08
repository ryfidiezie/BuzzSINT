import requests

def geolocate_ip(target: str) -> str:
    """
    Geolocate an IP or domain via ip-api.com.
    Free, no key needed, returns the good stuff:
    country, city, ISP, ASN, org, lat/lon.
    """
    if not target:
        return "Need an IP or domain."

    url = f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return "[TIMEOUT] ip-api.com too slow."
    except Exception as e:
        return f"[ERROR] {e}"

    if data.get("status") != "success":
        return f"[FAIL] {data.get('message', 'Unknown error')} — Private IP, localhost, or invalid target."

    lines = [
        f"[GEO] Results for {data['query']}:\n",
        f"  Location   : {data.get('city', '?')}, {data.get('regionName', '?')}, {data.get('country', '?')} ({data.get('countryCode', '?')})",
        f"  ZIP        : {data.get('zip', 'N/A')}",
        f"  Coordinates: {data.get('lat', '?')}, {data.get('lon', '?')}",
        f"  Timezone   : {data.get('timezone', 'N/A')}",
        f"  ISP        : {data.get('isp', 'N/A')}",
        f"  Org        : {data.get('org', 'N/A')}",
        f"  ASN        : {data.get('as', 'N/A')}",
    ]

    # Flag VPNs / hosting providers / known bulletproof hosters
    isp_lower = data.get("isp", "").lower()
    org_lower = data.get("org", "").lower()
    combined = isp_lower + org_lower
    vpn_hints = ["digitalocean", "linode", "vultr", "ovh", "hetzner", "tor", "vpn", "proxy",
                 "cloud", "hosting", "datacenter", "data center", "servers", "as-choopa"]
    matches = [h for h in vpn_hints if h in combined]
    if matches:
        lines.append(f"\n  ⚠ Possible VPS/Hosting/VPN provider detected: {', '.join(matches)}")

    # Maps link
    lat, lon = data.get("lat"), data.get("lon")
    if lat and lon:
        lines.append(f"\n  Maps: https://www.google.com/maps?q={lat},{lon}")

    return "\n".join(lines)
