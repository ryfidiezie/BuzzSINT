import dns.resolver
import concurrent.futures

# Common subdomain wordlist — enough to find the real stuff without being massive
WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta",
    "app", "portal", "dashboard", "login", "secure", "vpn", "remote", "cdn",
    "media", "static", "assets", "img", "images", "files", "upload", "uploads",
    "blog", "shop", "store", "payment", "pay", "checkout", "auth", "oauth",
    "sso", "id", "identity", "accounts", "account", "my", "user", "users",
    "support", "help", "docs", "documentation", "wiki", "kb", "forum",
    "m", "mobile", "wap", "api2", "api-v2", "v2", "v1", "v3", "internal",
    "intranet", "corp", "office", "old", "new", "backup", "bak", "data",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "kibana", "grafana", "prometheus", "jenkins", "ci", "build", "deploy",
    "git", "gitlab", "github", "jira", "confluence", "slack", "chat",
    "smtp", "pop", "imap", "webmail", "mail2", "ns", "ns1", "ns2", "dns",
    "mx", "mx1", "mx2", "autodiscover", "autoconfig", "exchange",
    "dev2", "staging2", "uat", "qa", "prod", "production", "live",
    "sandbox", "demo", "preview", "canary", "dr", "disaster", "backup2",
    "monitor", "monitoring", "status", "health", "metrics", "logs",
    "sentry", "bug", "tracker", "pm", "management",
]


def _resolve_subdomain(subdomain: str, domain: str):
    fqdn = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
        ips = [r.to_text() for r in answers]
        return fqdn, ips
    except Exception:
        return None, None


def dns_brute(domain: str) -> str:
    """
    Brute force subdomains using a curated wordlist.
    Faster than crt.sh for finding actively resolving hosts.
    Runs 50 threads concurrently — chews through the wordlist fast.
    """
    if not domain:
        return "Need a domain."

    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    lines = [f"[DNS BRUTE] Brute forcing {len(WORDLIST)} subdomains on {domain} (50 threads)\n"]

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_resolve_subdomain, sub, domain): sub for sub in WORDLIST}
        for future in concurrent.futures.as_completed(futures):
            fqdn, ips = future.result()
            if fqdn and ips:
                found.append((fqdn, ips))

    found.sort()

    if not found:
        lines.append("  Nothing resolved. Either clean setup or needs a bigger wordlist.")
        return "\n".join(lines)

    lines.append(f"  Found {len(found)} live subdomains:\n")
    for fqdn, ips in found:
        lines.append(f"  {fqdn:50s}  ->  {', '.join(ips)}")

    return "\n".join(lines)
