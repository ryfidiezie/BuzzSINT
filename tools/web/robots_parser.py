import requests

def parse_robots(url: str) -> str:
    """
    Fetch and parse robots.txt.
    Disallowed paths are a treasure map — devs use robots.txt to hide
    admin panels, internal tools, staging paths, and API endpoints
    from crawlers. They're not hidden from us.
    """
    if not url:
        return "Need a domain or URL."

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    robots_url = f"https://{domain}/robots.txt"

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    }

    try:
        resp = requests.get(robots_url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return f"[ROBOTS] No robots.txt at {robots_url} (404)."
        resp.raise_for_status()
        content = resp.text
    except requests.exceptions.Timeout:
        return f"[TIMEOUT] {robots_url} didn't respond."
    except Exception as e:
        return f"[ERROR] {e}"

    lines_raw = content.splitlines()
    lines = [f"[ROBOTS.TXT] {robots_url}\n"]

    disallowed = []
    allowed = []
    sitemaps = []
    other = []
    current_agent = "*"

    for line in lines_raw:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("user-agent:"):
            current_agent = line.split(":", 1)[1].strip()
        elif lower.startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append((current_agent, path))
        elif lower.startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                allowed.append((current_agent, path))
        elif lower.startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
        else:
            other.append(line)

    # Flag juicy disallowed paths
    juicy = ["admin", "login", "api", "backup", "config", "private", "internal",
             "dev", "test", "staging", "upload", "secret", "key", "token", "debug",
             "wp-admin", "phpmyadmin", "cpanel", "dashboard", "manage"]

    if disallowed:
        lines.append(f"  === Disallowed Paths ({len(disallowed)}) ===")
        for agent, path in disallowed:
            flag = "  ⚠ INTERESTING" if any(j in path.lower() for j in juicy) else ""
            agent_str = f"[{agent}] " if agent != "*" else ""
            lines.append(f"  {agent_str}{path}{flag}")
        lines.append("")

    if sitemaps:
        lines.append(f"  === Sitemaps ({len(sitemaps)}) ===")
        for s in sitemaps:
            lines.append(f"  {s}")
        lines.append("")

    if allowed:
        lines.append(f"  === Explicitly Allowed ({len(allowed)}) ===")
        for agent, path in allowed:
            lines.append(f"  [{agent}] {path}")
        lines.append("")

    lines.append(f"  === Raw Content ===")
    lines.append(content)

    return "\n".join(lines)
