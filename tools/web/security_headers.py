import requests

# Header name -> (description, why it matters)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "HSTS", "Forces HTTPS. Missing = downgrade attacks possible."
    ),
    "Content-Security-Policy": (
        "CSP", "Restricts what scripts/resources can load. Missing = XSS open season."
    ),
    "X-Frame-Options": (
        "Clickjacking Protection", "Prevents iframe embedding. Missing = clickjacking possible."
    ),
    "X-Content-Type-Options": (
        "MIME Sniffing Protection", "Stops browsers guessing content type. Should be 'nosniff'."
    ),
    "Referrer-Policy": (
        "Referrer Policy", "Controls what referrer info leaks to other sites."
    ),
    "Permissions-Policy": (
        "Permissions Policy", "Controls access to browser APIs (camera, mic, GPS, etc.)."
    ),
    "X-XSS-Protection": (
        "XSS Filter (Legacy)", "Old IE XSS filter. Mostly irrelevant now but scored anyway."
    ),
    "Cross-Origin-Opener-Policy": (
        "COOP", "Isolates browsing context. Mitigates Spectre-style attacks."
    ),
    "Cross-Origin-Embedder-Policy": (
        "COEP", "Required for SharedArrayBuffer. Part of origin isolation."
    ),
    "Cross-Origin-Resource-Policy": (
        "CORP", "Restricts cross-origin resource loading."
    ),
}

# Headers that leak info (bad to have, or worth noting)
LEAKY_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via"
]


def grade_security_headers(url: str) -> str:
    """
    Fetch HTTP headers and grade the target's security posture.
    Scores each security header present/missing, flags leaky headers
    that disclose tech stack info attackers love.
    """
    if not url:
        return "Need a URL."

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        resp = requests.get(url, headers=headers_req, timeout=15, allow_redirects=True)
        resp_headers = {k.title(): v for k, v in resp.headers.items()}
    except requests.exceptions.Timeout:
        return f"[TIMEOUT] {url}"
    except Exception as e:
        return f"[ERROR] {e}"

    lines = [f"[SECURITY HEADERS] {resp.url}\n"]

    present = 0
    total = len(SECURITY_HEADERS)

    lines.append("  === Security Headers ===\n")
    for header, (short, note) in SECURITY_HEADERS.items():
        val = resp_headers.get(header.title())
        if val:
            present += 1
            lines.append(f"  ✓ {header}")
            lines.append(f"      Value : {val[:100]}")
            lines.append(f"      Note  : {note}")
        else:
            lines.append(f"  ✗ {header} — MISSING")
            lines.append(f"      Note  : {note}")
        lines.append("")

    # Score
    score = int((present / total) * 100)
    if score >= 80:
        grade, color = "A", "Good"
    elif score >= 60:
        grade, color = "B", "Decent"
    elif score >= 40:
        grade, color = "C", "Weak"
    elif score >= 20:
        grade, color = "D", "Bad"
    else:
        grade, color = "F", "Embarrassing"

    lines.append(f"  === Score: {present}/{total} ({score}%) — Grade {grade} ({color}) ===\n")

    # Leaky headers
    found_leaky = []
    for h in LEAKY_HEADERS:
        val = resp_headers.get(h.title())
        if val:
            found_leaky.append((h, val))

    if found_leaky:
        lines.append("  === Info-Leaking Headers (remove these) ===")
        for h, v in found_leaky:
            lines.append(f"  ⚠ {h}: {v}")

    return "\n".join(lines)
