import requests
import re

# Tech signatures: (pattern_in_header_or_html, friendly_name, category)
SIGNATURES = [
    # Web servers
    (r"server:\s*nginx", "Nginx", "Web Server"),
    (r"server:\s*apache", "Apache", "Web Server"),
    (r"server:\s*iis", "IIS (Microsoft)", "Web Server"),
    (r"server:\s*cloudflare", "Cloudflare", "CDN/Proxy"),
    (r"server:\s*lighttpd", "Lighttpd", "Web Server"),
    (r"server:\s*openresty", "OpenResty (Nginx+Lua)", "Web Server"),
    (r"server:\s*caddy", "Caddy", "Web Server"),

    # CDNs / Proxies
    (r"x-served-by:.*fastly", "Fastly CDN", "CDN"),
    (r"x-cache:.*cloudfront", "AWS CloudFront", "CDN"),
    (r"via:.*varnish", "Varnish Cache", "Cache"),
    (r"x-powered-by:.*vercel", "Vercel", "Hosting"),
    (r"x-vercel-id:", "Vercel", "Hosting"),
    (r"x-amz-cf-id:", "AWS CloudFront", "CDN"),
    (r"x-azure-ref:", "Azure CDN", "CDN"),

    # Languages / Frameworks (headers)
    (r"x-powered-by:.*php", "PHP", "Language"),
    (r"x-powered-by:.*asp\.net", "ASP.NET", "Framework"),
    (r"x-powered-by:.*express", "Express.js", "Framework"),
    (r"x-powered-by:.*next\.js", "Next.js", "Framework"),

    # CMS (HTML body)
    (r'content="WordPress', "WordPress", "CMS"),
    (r"/wp-content/", "WordPress", "CMS"),
    (r"/wp-includes/", "WordPress", "CMS"),
    (r'content="Drupal', "Drupal", "CMS"),
    (r'generator.*joomla', "Joomla", "CMS"),
    (r'generator.*squarespace', "Squarespace", "Website Builder"),
    (r'data-wf-site', "Webflow", "Website Builder"),
    (r'shopify\.com', "Shopify", "E-Commerce"),
    (r'cdn\.shopify\.com', "Shopify", "E-Commerce"),
    (r'woocommerce', "WooCommerce", "E-Commerce Plugin"),
    (r'ghost\.io|content="Ghost', "Ghost CMS", "CMS"),

    # JS Frameworks
    (r'__NEXT_DATA__', "Next.js", "JS Framework"),
    (r'__nuxt', "Nuxt.js", "JS Framework"),
    (r'ng-version=|angular', "Angular", "JS Framework"),
    (r'data-reactroot|react\.development', "React", "JS Framework"),
    (r'__svelte', "Svelte", "JS Framework"),
    (r'vue\.js|vue\.min\.js', "Vue.js", "JS Framework"),

    # Analytics / Tracking
    (r'google-analytics\.com|gtag\(', "Google Analytics", "Analytics"),
    (r'googletagmanager\.com', "Google Tag Manager", "Analytics"),
    (r'hotjar\.com', "Hotjar", "Analytics"),
    (r'segment\.com|segment\.io', "Segment", "Analytics"),
    (r'matomo\.js|piwik\.js', "Matomo", "Analytics"),
    (r'mixpanel\.com', "Mixpanel", "Analytics"),

    # Security
    (r"x-xss-protection:", "XSS Protection Header", "Security"),
    (r"strict-transport-security:", "HSTS Enabled", "Security"),
    (r"content-security-policy:", "CSP Header Present", "Security"),
    (r"x-frame-options:", "Clickjacking Protection", "Security"),

    # Database hints (rare but happens)
    (r'mongodb\+srv|mongoose', "MongoDB", "Database"),
    (r'firebase\.google\.com', "Firebase", "Database/Backend"),
    (r'supabase\.io|supabase\.co', "Supabase", "Database/Backend"),
]


def fingerprint_tech(url: str) -> str:
    """
    Fingerprint the tech stack of a target URL.
    Checks HTTP response headers + HTML body against known signatures.
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
        resp.raise_for_status()
        body = resp.text.lower()
        raw_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        combined = raw_headers + "\n" + body
    except requests.exceptions.Timeout:
        return f"[TIMEOUT] {url} took too long."
    except Exception as e:
        return f"[ERROR] {e}"

    found = {}  # name -> category
    for pattern, name, category in SIGNATURES:
        if re.search(pattern, combined, re.IGNORECASE):
            if name not in found:
                found[name] = category

    lines = [f"[TECH FINGERPRINT] {resp.url}\n"]

    # Show raw interesting headers
    interesting_headers = ["server", "x-powered-by", "x-generator", "via",
                           "x-served-by", "x-cache", "cf-ray", "x-vercel-id"]
    lines.append("  --- Response Headers ---")
    for h in interesting_headers:
        val = resp.headers.get(h) or resp.headers.get(h.title())
        if val:
            lines.append(f"  {h}: {val}")

    lines.append("")
    lines.append(f"  --- Detected Technologies ({len(found)}) ---")

    if not found:
        lines.append("  Nothing identifiable. Could be custom stack or heavily obfuscated.")
    else:
        # Group by category
        by_cat: dict = {}
        for name, cat in found.items():
            by_cat.setdefault(cat, []).append(name)

        for cat, names in sorted(by_cat.items()):
            lines.append(f"\n  [{cat}]")
            for n in names:
                lines.append(f"    - {n}")

    return "\n".join(lines)
