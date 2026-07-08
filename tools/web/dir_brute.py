import requests
import re
import concurrent.futures

# Common paths to probe — mix of generic and CMS-specific
DIR_WORDLIST = [
    # Admin & auth
    "admin", "admin/", "administrator", "login", "signin", "auth",
    "dashboard", "panel", "manage", "management", "control",
    "wp-admin", "wp-login.php", "wp-content", "wp-includes",
    "phpmyadmin", "pma", "mysqladmin", "cpanel", "webmail",
    "plesk", "directadmin", "ispconfig",
    # APIs
    "api", "api/v1", "api/v2", "api/v3", "graphql", "rest",
    "swagger", "swagger-ui", "swagger-ui.html", "api-docs",
    "openapi.json", "openapi.yaml", "swagger.json",
    # DevOps / monitoring
    "jenkins", "gitlab", "ci", "build", "deploy", "grafana",
    "kibana", "prometheus", "metrics", "health", "healthz",
    "status", "ping", "monitor",
    # Config / secrets
    ".env", ".git", ".git/config", ".git/HEAD",
    ".gitignore", ".htaccess", ".htpasswd",
    "config", "config.php", "config.json", "config.yml",
    "configuration", "settings", "settings.php",
    "web.config", "app.config", "database.yml",
    # Backups
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "db.sql", "dump.sql", "database.sql", "site.zip",
    "old", "bak", "archive",
    # Info disclosure
    "phpinfo.php", "info.php", "test.php", "debug",
    "server-status", "server-info", "nginx_status",
    "robots.txt", "sitemap.xml", "sitemap.txt",
    "crossdomain.xml", "clientaccesspolicy.xml",
    # Common dirs
    "upload", "uploads", "files", "file", "media", "images",
    "static", "assets", "js", "css", "fonts",
    "private", "internal", "hidden", "secret",
    "logs", "log", "tmp", "temp", "cache",
    # CMS specific
    "wp-json", "xmlrpc.php", "feed", "rss",
    "joomla", "drupal", "magento", "prestashop",
    "user/login", "user/register",
    # Cloud / infrastructure
    "actuator", "actuator/env", "actuator/health",  # Spring Boot
    "__debug__",  # Django
    "rails/info", "rails/mailers",  # Rails
    "telescope", "horizon",  # Laravel
    "sidekiq",  # Ruby
    ".well-known/security.txt",
    ".well-known/apple-app-site-association",
]


def _probe_path(base: str, path: str, session: requests.Session):
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    try:
        resp = session.get(url, timeout=5, allow_redirects=False)
        if resp.status_code not in (404, 400, 410):
            return url, resp.status_code, len(resp.content)
    except Exception:
        pass
    return None, None, None


def dir_brute(url: str) -> str:
    """
    Directory/file brute force against a web target.
    Probes common admin panels, config files, backups, and API endpoints.
    Flags anything that isn't a 404.
    """
    if not url:
        return "Need a URL."

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    lines = [f"[DIR BRUTE] {url} — probing {len(DIR_WORDLIST)} paths (50 threads)\n"]

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })

    found = []
    juicy = ["admin", ".env", ".git", "config", "backup", "sql", "phpinfo",
             "graphql", "swagger", "actuator", "debug", "secret", "private"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(_probe_path, url, path, session): path for path in DIR_WORDLIST}
        for future in concurrent.futures.as_completed(futures):
            hit_url, status, size = future.result()
            if hit_url:
                found.append((hit_url, status, size))

    found.sort(key=lambda x: x[1])

    if not found:
        lines.append("  Nothing found. Either hardened or wrong URL.")
        return "\n".join(lines)

    lines.append(f"  Found {len(found)} non-404 responses:\n")
    for hit_url, status, size in found:
        path = hit_url.replace(url.rstrip("/"), "")
        is_juicy = any(j in hit_url.lower() for j in juicy)
        flag = "  ⚠ JUICY" if is_juicy else ""
        status_color = "[200]" if status == 200 else f"[{status}]"
        lines.append(f"  {status_color}  {size:8,} bytes  {path}{flag}")

    return "\n".join(lines)
