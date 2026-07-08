import requests

def check_cors(url: str) -> str:
    """
    Test CORS configuration on a target.
    Sends requests with various Origin headers to see what the server reflects/allows.
    Misconfigured CORS = cross-origin data theft. Wildcard CORS on an API = GG.
    """
    if not url:
        return "Need a URL."

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        f"null",
        url.replace("https://", "https://evil."),  # evil subdomain
        "https://localhost",
    ]

    lines = [f"[CORS CHECKER] {url}\n"]

    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    issues = []

    for origin in test_origins:
        try:
            # Simple request
            req_headers = {**base_headers, "Origin": origin}
            resp = requests.get(url, headers=req_headers, timeout=10)

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            acam = resp.headers.get("Access-Control-Allow-Methods", "")
            acah = resp.headers.get("Access-Control-Allow-Headers", "")

            lines.append(f"  Origin: {origin}")
            lines.append(f"    Allow-Origin      : {acao or '(not set)'}")
            lines.append(f"    Allow-Credentials : {acac or '(not set)'}")
            if acam:
                lines.append(f"    Allow-Methods     : {acam}")
            if acah:
                lines.append(f"    Allow-Headers     : {acah}")

            if acao == "*":
                issues.append(f"⚠ Wildcard CORS (*) — any origin can make cross-origin requests")
            if acao == origin and acac == "true":
                issues.append(f"⚠ CRITICAL: Server reflects arbitrary Origin AND allows credentials → Cross-origin credential theft")
            if acao == origin and origin != "null":
                issues.append(f"⚠ Server reflects arbitrary Origin: {origin}")
            if acao == "null":
                issues.append(f"⚠ Null origin allowed — file:// and data: pages can make requests")

        except Exception as e:
            lines.append(f"  Origin: {origin} — Error: {e}")

        # OPTIONS preflight
        try:
            preflight = requests.options(
                url,
                headers={**base_headers, "Origin": origin, "Access-Control-Request-Method": "POST"},
                timeout=10
            )
            pre_acao = preflight.headers.get("Access-Control-Allow-Origin", "")
            if pre_acao:
                lines.append(f"    Preflight ACAO    : {pre_acao}")
        except Exception:
            pass

        lines.append("")

    if issues:
        lines.append("  === FINDINGS ===")
        for issue in set(issues):
            lines.append(f"  {issue}")
    else:
        lines.append("  No obvious CORS misconfigurations detected.")

    return "\n".join(lines)


def trace_redirects(url: str) -> str:
    """
    Follow and map the full redirect chain for a URL.
    Open redirects, http->https downgrade, redirect loops, and
    third-party redirect hijacks all show up here.
    """
    if not url:
        return "Need a URL."

    if not url.startswith(("http://", "https://")):
        url = "http://" + url  # start with http to catch http->https redirects

    lines = [f"[REDIRECT TRACER] {url}\n"]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        history = resp.history
    except requests.exceptions.TooManyRedirects:
        lines.append("  ⚠ REDIRECT LOOP DETECTED — exceeded 30 redirects")
        return "\n".join(lines)
    except Exception as e:
        return f"[ERROR] {e}"

    if not history:
        lines.append(f"  No redirects — direct response: {resp.status_code} {resp.url}")
        return "\n".join(lines)

    lines.append(f"  Chain length: {len(history)} redirect(s)\n")

    all_urls = [r.url for r in history] + [resp.url]
    for i, (step, redirect) in enumerate(zip(history, all_urls[1:]), 1):
        location = step.headers.get("Location", redirect)
        lines.append(f"  Step {i}: [{step.status_code}] {step.url}")
        lines.append(f"    → {location}")

        # Flag interesting redirects
        if step.status_code in (301, 308):
            lines.append("    Permanent redirect")
        elif step.status_code in (302, 303, 307):
            lines.append("    Temporary redirect")

        if "http://" in step.url and "https://" in location:
            lines.append("    HTTP → HTTPS upgrade ✓")
        elif "https://" in step.url and "http://" in location:
            lines.append("    ⚠ HTTPS → HTTP DOWNGRADE")

        from urllib.parse import urlparse
        orig_domain = urlparse(step.url).netloc
        dest_domain = urlparse(location).netloc
        if dest_domain and orig_domain != dest_domain:
            lines.append(f"    ⚠ Cross-domain redirect: {orig_domain} → {dest_domain}")

    lines.append(f"\n  Final: [{resp.status_code}] {resp.url}")

    return "\n".join(lines)


def test_http_methods(url: str) -> str:
    """
    Test which HTTP methods the server accepts.
    PUT/DELETE on a web server without auth is a big problem.
    TRACE enables XST attacks. OPTIONS reveals allowed methods.
    """
    if not url:
        return "Need a URL."

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
               "TRACE", "CONNECT", "PROPFIND", "MKCOL"]

    lines = [f"[HTTP METHODS] {url}\n"]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    # First try OPTIONS
    try:
        opt = requests.options(url, headers=headers, timeout=10)
        allow = opt.headers.get("Allow", "")
        if allow:
            lines.append(f"  OPTIONS response Allow header: {allow}\n")
    except Exception:
        pass

    for method in methods:
        try:
            resp = requests.request(method, url, headers=headers, timeout=10, allow_redirects=False)
            status = resp.status_code
            flag = ""
            if method in ("PUT", "DELETE", "PATCH") and status not in (405, 403, 401, 404):
                flag = "  ⚠ DANGEROUS — writable method accepted"
            elif method == "TRACE" and status == 200:
                flag = "  ⚠ TRACE enabled — XST attack possible"
            elif method == "PROPFIND" and status not in (405, 403, 404):
                flag = "  ⚠ WebDAV enabled"
            lines.append(f"  {method:10s} [{status}]{flag}")
        except Exception as e:
            lines.append(f"  {method:10s} [ERROR] {e}")

    return "\n".join(lines)
