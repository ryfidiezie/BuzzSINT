import requests

def wayback_lookup(domain: str, limit: int = 50) -> str:
    """
    Query the Wayback Machine CDX API for archived URLs of a domain.
    Old URLs are a goldmine: deleted pages, old admin panels, exposed backups,
    API endpoints that devs thought were gone, login portals, staging servers.
    """
    if not domain:
        return "Need a domain."

    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*"
        f"&output=json"
        f"&fl=original,statuscode,timestamp"
        f"&collapse=urlkey"
        f"&limit={limit}"
        f"&filter=statuscode:200"
    )

    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return "[TIMEOUT] Wayback Machine is being slow. Try again."
    except Exception as e:
        return f"[ERROR] {e}"

    if not data or len(data) <= 1:
        return f"No archived URLs found for {domain} — either it's new or Wayback has nothing."

    # First row is headers: ["original", "statuscode", "timestamp"]
    rows = data[1:]  # skip header row

    # Flag interesting patterns
    juicy_patterns = [
        "admin", "login", "backup", "config", ".sql", ".env", ".bak",
        "api", "debug", "test", "dev", "staging", "upload", "phpinfo",
        ".git", "passwd", "secret", "token", "key", "password"
    ]

    lines = [f"[WAYBACK MACHINE] Archived URLs for {domain} (top {limit}, status 200):\n"]
    
    flagged = []
    normal = []

    for row in rows:
        if len(row) < 3:
            continue
        original_url, status, timestamp = row[0], row[1], row[2]
        # Format timestamp: 20230415123045 -> 2023-04-15
        date = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}" if len(timestamp) >= 8 else timestamp
        is_juicy = any(p in original_url.lower() for p in juicy_patterns)
        entry = f"  [{date}] {original_url}"
        if is_juicy:
            flagged.append(entry + "  ⚠ INTERESTING")
        else:
            normal.append(entry)

    if flagged:
        lines.append(f"  === FLAGGED ({len(flagged)}) ===")
        lines.extend(flagged)
        lines.append("")

    lines.append(f"  === All URLs ({len(normal)}) ===")
    lines.extend(normal)

    lines.append(f"\n  Full archive: https://web.archive.org/web/*/{domain}")

    return "\n".join(lines)
