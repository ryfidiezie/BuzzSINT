import requests
import socket

# DNSBL (DNS-based Block Lists) — the standard blacklists
DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
    "dnsbl.dronebl.org",
    "combined.abuse.ch",
    "cbl.abuseat.org",
    "spam.dnsbl.sorbs.net",
    "http.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "misc.dnsbl.sorbs.net",
    "smtp.dnsbl.sorbs.net",
]


def _reverse_ip(ip: str) -> str:
    """Reverse an IPv4 for DNSBL lookup."""
    parts = ip.split(".")
    return ".".join(reversed(parts))


def check_blacklists(target: str) -> str:
    """
    Check an IP against major DNS blacklists (DNSBLs).
    If an IP is listed, it's flagged as spam source, open proxy,
    botnet C2, or otherwise malicious. Useful for threat context.
    """
    if not target:
        return "Need an IP address."

    # Resolve to IP if domain
    try:
        ip = socket.gethostbyname(target.strip())
    except Exception as e:
        return f"[ERROR] Can't resolve {target}: {e}"

    reversed_ip = _reverse_ip(ip)
    lines = [f"[BLACKLIST CHECK] {target} ({ip})\n"]
    lines.append(f"  Checking {len(DNSBL_SERVERS)} blacklists...\n")

    listed = []
    clean = []

    import concurrent.futures

    def _check_dnsbl(dnsbl: str):
        lookup = f"{reversed_ip}.{dnsbl}"
        try:
            socket.gethostbyname(lookup)
            return dnsbl, True
        except socket.gaierror:
            return dnsbl, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(_check_dnsbl, DNSBL_SERVERS))

    for dnsbl, is_listed in results:
        if is_listed:
            listed.append(dnsbl)
        else:
            clean.append(dnsbl)

    if listed:
        lines.append(f"  ⚠ LISTED on {len(listed)} blacklist(s):")
        for bl in listed:
            lines.append(f"    ✗ {bl}")
        lines.append(f"\n  → This IP is flagged. Possible: spam source, open proxy, botnet, VPN exit.")
        lines.append(f"  Delist: https://www.spamhaus.org/lookup/ and respective DNSBL sites")
    else:
        lines.append(f"  ✓ Clean — not listed on any of the {len(DNSBL_SERVERS)} checked blacklists.")

    lines.append(f"\n  {len(clean)} clean / {len(listed)} listed")
    lines.append(f"  AbuseIPDB: https://www.abuseipdb.com/check/{ip}")
    lines.append(f"  VirusTotal: https://www.virustotal.com/gui/ip-address/{ip}")

    return "\n".join(lines)


def cve_lookup(query: str) -> str:
    """
    Look up CVEs by ID or keyword via NIST NVD API.
    No API key required. Returns severity, CVSS score, description, and references.
    """
    if not query:
        return "Need a CVE ID (CVE-2021-44228) or keyword (log4j)."

    query = query.strip()
    lines = [f"[CVE LOOKUP] {query}\n"]

    # Direct CVE ID lookup
    if query.upper().startswith("CVE-"):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query.upper()}"
    else:
        # Keyword search
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={requests.utils.quote(query)}&resultsPerPage=10"

    try:
        resp = requests.get(url, timeout=20, headers={"Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return "[TIMEOUT] NVD API is slow. Try again."
    except Exception as e:
        return f"[ERROR] {e}"

    vulns = data.get("vulnerabilities", [])
    total = data.get("totalResults", 0)

    if not vulns:
        lines.append(f"  No CVEs found for '{query}'.")
        return "\n".join(lines)

    lines.append(f"  Total results: {total} (showing {len(vulns)})\n")

    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        published = cve.get("published", "N/A")[:10]
        modified = cve.get("lastModified", "N/A")[:10]

        # Description
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "No description")

        # CVSS scores
        metrics = cve.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        cvss_v2 = metrics.get("cvssMetricV2", [])

        lines.append(f"  ● {cve_id}  (Published: {published}  Modified: {modified})")

        if cvss_v3:
            score_data = cvss_v3[0].get("cvssData", {})
            score = score_data.get("baseScore", "N/A")
            severity = cvss_v3[0].get("baseSeverity", score_data.get("baseSeverity", "N/A"))
            vector = score_data.get("vectorString", "N/A")
            lines.append(f"    CVSSv3 Score : {score} ({severity})")
            lines.append(f"    Vector       : {vector}")
        elif cvss_v2:
            score_data = cvss_v2[0].get("cvssData", {})
            score = score_data.get("baseScore", "N/A")
            severity = cvss_v2[0].get("baseSeverity", "N/A")
            lines.append(f"    CVSSv2 Score : {score} ({severity})")

        lines.append(f"    Description  : {desc[:200]}{'...' if len(desc) > 200 else ''}")

        # References
        refs = cve.get("references", [])
        if refs:
            lines.append(f"    References ({len(refs)}):")
            for ref in refs[:3]:
                lines.append(f"      {ref.get('url', 'N/A')}")

        lines.append("")

    return "\n".join(lines)


def tor_exit_check(target: str) -> str:
    """
    Check if an IP is a known Tor exit node.
    Dan.me.uk maintains a real-time list of all Tor exit nodes.
    Useful for threat context — is this traffic coming from Tor?
    """
    if not target:
        return "Need an IP address."

    target = target.strip()
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target

    lines = [f"[TOR EXIT CHECK] {ip}\n"]

    # Method 1: DAN.ME.UK DNSBL
    reversed_ip = _reverse_ip(ip)
    dnsbl = f"{reversed_ip}.dnsel.torproject.org"
    try:
        socket.gethostbyname(dnsbl)
        lines.append(f"  ⚠ CONFIRMED TOR EXIT NODE — {ip} is in Tor's exit list.")
        lines.append("  Traffic from this IP is anonymized through the Tor network.")
    except socket.gaierror:
        lines.append(f"  Not a current Tor exit node (per Tor's DNSEL).")

    # Method 2: Check against Dan's list (plaintext)
    try:
        resp = requests.get(
            f"https://check.torproject.org/torbulkexitlist?ip=1.1.1.1",
            timeout=10
        )
        if ip in resp.text:
            lines.append(f"  ⚠ Also confirmed in Tor Project bulk exit list.")
    except Exception:
        pass

    lines.append(f"\n  Manual check: https://check.torproject.org/?ip={ip}")
    lines.append(f"  Full list: https://dan.me.uk/torlist/")

    return "\n".join(lines)
