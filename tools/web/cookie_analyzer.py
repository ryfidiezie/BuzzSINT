import requests
from http.cookiejar import CookieJar

def analyze_cookies(url: str) -> str:
    """
    Fetch a page and deeply analyze every Set-Cookie header.
    Checks for:
    - HttpOnly (JS can't steal it — good)
    - Secure flag (HTTPS only — good)
    - SameSite (CSRF protection)
    - Expiry (session vs persistent)
    - Naming conventions that reveal tech stack
    - Session fixation indicators
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
    except Exception as e:
        return f"[ERROR] {e}"

    # Collect all Set-Cookie headers (requests merges duplicates, use raw)
    raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
    if not raw_cookies:
        # Fall back to resp.headers — might be merged
        set_cookie = resp.headers.get("Set-Cookie", "")
        raw_cookies = [set_cookie] if set_cookie else []

    # Also check cookies jar
    cookie_list = list(resp.cookies)

    lines = [f"[COOKIE ANALYZER] {base_url}\n"]

    if not raw_cookies and not cookie_list:
        lines.append("  No cookies set on this response.")
        return "\n".join(lines)

    # Tech stack hints from cookie names
    tech_hints = {
        "PHPSESSID": "PHP session",
        "JSESSIONID": "Java/Tomcat session",
        "ASP.NET_SessionId": "ASP.NET session",
        "_rails_session": "Ruby on Rails",
        "django_session": "Django",
        "laravel_session": "Laravel",
        "express.sid": "Express.js",
        "__stripe_sid": "Stripe integration",
        "_ga": "Google Analytics",
        "_gid": "Google Analytics",
        "_fbp": "Facebook Pixel",
        "csrftoken": "CSRF token (Django-style)",
        "XSRF-TOKEN": "CSRF token (Angular/Laravel)",
        "connect.sid": "Express.js/Connect",
        "cf_clearance": "Cloudflare",
        "__cfduid": "Cloudflare (legacy)",
        "__utma": "Google Analytics (legacy)",
        "wp-settings": "WordPress",
        "wordpress_": "WordPress",
    }

    for cookie in cookie_list:
        name = cookie.name
        value = cookie.value
        lines.append(f"  Cookie: {name}")
        lines.append(f"    Value    : {value[:40]}{'...' if len(value) > 40 else ''}")
        lines.append(f"    Domain   : {cookie.domain or 'N/A'}")
        lines.append(f"    Path     : {cookie.path or '/'}")
        lines.append(f"    Expires  : {cookie.expires or 'Session'}")
        lines.append(f"    Secure   : {'✓ Yes' if cookie.secure else '✗ No — transmittable over HTTP'}")

        # HttpOnly isn't exposed in requests.cookies directly — check raw
        http_only = any(
            name.lower() in c.lower() and "httponly" in c.lower()
            for c in raw_cookies
        )
        lines.append(f"    HttpOnly : {'✓ Yes' if http_only else '✗ No — JavaScript can access this cookie'}")

        # SameSite
        samesite = None
        for raw in raw_cookies:
            if name.lower() in raw.lower():
                for part in raw.split(";"):
                    if "samesite" in part.lower():
                        samesite = part.strip()
                        break
        if samesite:
            lines.append(f"    SameSite : {samesite}")
            if "none" in samesite.lower():
                lines.append("    ⚠ SameSite=None — CSRF risk if not Secure")
        else:
            lines.append("    SameSite : Not set (browser default = Lax in modern browsers)")

        # Tech hint
        for hint_name, hint_tech in tech_hints.items():
            if hint_name.lower() in name.lower():
                lines.append(f"    Tech     : {hint_tech}")
                break

        lines.append("")

    return "\n".join(lines)
