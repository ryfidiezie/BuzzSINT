import requests
import re
from urllib.parse import urljoin

def analyze_js(url: str) -> str:
    """
    Find all JS files linked from a page, then scrape each one for:
    - API endpoints / URL patterns
    - Hardcoded secrets (API keys, tokens, passwords)
    - Internal domain references
    - S3 buckets, cloud storage URLs
    Devs forget JS is public. Rookie mistake, our gain.
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
        base_url = resp.url
        html = resp.text
    except Exception as e:
        return f"[ERROR] {e}"

    # Find all JS file references
    js_pattern = re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
    js_urls = set()
    for match in js_pattern.findall(html):
        full = urljoin(base_url, match)
        js_urls.add(full)

    lines = [f"[JS ANALYZER] {base_url}\n"]
    lines.append(f"  Found {len(js_urls)} JS files to analyze:\n")

    # Patterns for interesting content
    secret_patterns = [
        (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key"),
        (r'(?:secret|token)\s*[=:]\s*["\']([A-Za-z0-9_\-+/=]{16,})["\']', "Secret/Token"),
        (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "Password"),
        (r'(?:auth|bearer)\s*[=:]\s*["\']([A-Za-z0-9_\-+/=]{20,})["\']', "Auth Token"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'["\'](?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}["\']', "GitHub Token"),
        (r's3\.amazonaws\.com/[A-Za-z0-9_\-]+', "S3 Bucket"),
        (r'(?:mongodb|postgres|mysql|redis)://[^\s"\']+', "DB Connection String"),
    ]
    endpoint_patterns = [
        re.compile(r'["\`](/(?:api|v\d|rest|graphql)[/A-Za-z0-9_\-{}?=&]+)["\`]'),
        re.compile(r'(?:fetch|axios\.get|axios\.post|http\.get|http\.post)\(["\`](/[^"\'`\s]+)'),
        re.compile(r'(?:url|endpoint|baseUrl|apiUrl)\s*[=:]\s*["\`]([^"\'`\s]{5,})["\`]'),
    ]

    for js_url in sorted(js_urls):
        lines.append(f"  --- {js_url} ---")
        try:
            js_resp = requests.get(js_url, headers=headers, timeout=10)
            js_code = js_resp.text
            size = len(js_code)
            lines.append(f"  Size: {size:,} bytes")

            # Secret hunting
            for pattern, name in secret_patterns:
                matches = re.findall(pattern, js_code, re.IGNORECASE)
                for m in matches[:3]:
                    val = m if isinstance(m, str) else m[0]
                    lines.append(f"  ⚠ {name}: {val[:60]}{'...' if len(val) > 60 else ''}")

            # Endpoint hunting
            endpoints = set()
            for pat in endpoint_patterns:
                for m in pat.findall(js_code):
                    if len(m) > 3:
                        endpoints.add(m)
            if endpoints:
                lines.append(f"  Endpoints ({len(endpoints)}):")
                for ep in sorted(endpoints)[:20]:
                    lines.append(f"    {ep}")

        except Exception as e:
            lines.append(f"  Error: {e}")
        lines.append("")

    return "\n".join(lines)
