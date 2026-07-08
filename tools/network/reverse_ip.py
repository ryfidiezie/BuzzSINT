import requests

def reverse_ip(target: str) -> str:
    """
    Find all domains hosted on the same IP via HackerTarget.
    Shared hosting = one popped site can pivot to everything on that IP.
    """
    if not target:
        return "Need an IP or domain."

    target = target.replace("https://", "").replace("http://", "").split("/")[0]

    url = f"https://api.hackertarget.com/reverseiplookup/?q={target}"

    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        text = resp.text.strip()
    except requests.exceptions.Timeout:
        return "[TIMEOUT] HackerTarget took too long."
    except Exception as e:
        return f"[ERROR] {e}"

    if "error" in text.lower() or "API count" in text:
        return f"[LIMIT] HackerTarget rate limited: {text}"

    domains = [d.strip() for d in text.splitlines() if d.strip()]

    if not domains:
        return f"No reverse IP results for {target}."

    lines = [f"[REVERSE IP] Domains on same server as {target}:\n"]
    lines.append(f"  Found {len(domains)} domain(s):\n")
    for d in sorted(domains):
        lines.append(f"  {d}")

    if len(domains) > 10:
        lines.append(f"\n  ⚠ {len(domains)} domains on this IP — likely shared hosting.")
    elif len(domains) == 1:
        lines.append(f"\n  Dedicated IP or VPS. One tenant.")

    return "\n".join(lines)
