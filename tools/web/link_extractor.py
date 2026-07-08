import requests
import re
from urllib.parse import urljoin, urlparse

def extract_links(url: str) -> str:
    """
    Crawl a page and extract all internal + external links.
    Maps the attack surface — external links can reveal third-party
    dependencies, internal links expose directory structure and hidden pages.
    """
    if not url:
        return "Need a URL."

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        resp.raise_for_status()
        html = resp.text
        base_url = resp.url
    except requests.exceptions.Timeout:
        return f"[TIMEOUT] {url}"
    except Exception as e:
        return f"[ERROR] {e}"

    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc

    # Extract href and src attributes
    href_pattern = re.compile(r'(?:href|src|action)=["\']([^"\'#\s]+)["\']', re.IGNORECASE)
    raw_links = href_pattern.findall(html)

    internal = set()
    external = set()
    juicy_internal = []

    juicy_patterns = ["admin", "login", "api", "backup", "config", "upload",
                      "private", "internal", "debug", "test", "dev", ".env",
                      ".sql", ".bak", ".log", "wp-admin", "dashboard", "secret"]

    for link in raw_links:
        # Skip junk
        if link.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        if link.startswith("//"):
            link = "https:" + link

        full = urljoin(base_url, link)
        parsed = urlparse(full)

        if not parsed.scheme.startswith("http"):
            continue

        if parsed.netloc == base_domain or parsed.netloc == "":
            internal.add(full)
            if any(p in full.lower() for p in juicy_patterns):
                juicy_internal.append(full)
        else:
            external.add(full)

    lines = [f"[LINK EXTRACTOR] {base_url}\n"]
    lines.append(f"  Internal: {len(internal)}  |  External: {len(external)}\n")

    if juicy_internal:
        lines.append(f"  === ⚠ FLAGGED Internal Links ({len(juicy_internal)}) ===")
        for link in sorted(juicy_internal):
            lines.append(f"  {link}")
        lines.append("")

    lines.append(f"  === Internal Links ({len(internal)}) ===")
    for link in sorted(internal)[:60]:  # cap at 60 to avoid log flood
        lines.append(f"  {link}")
    if len(internal) > 60:
        lines.append(f"  ... and {len(internal) - 60} more")
    lines.append("")

    lines.append(f"  === External Links ({len(external)}) ===")
    for link in sorted(external)[:40]:
        lines.append(f"  {link}")
    if len(external) > 40:
        lines.append(f"  ... and {len(external) - 40} more")

    return "\n".join(lines)
