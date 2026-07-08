def generate_dorks(target: str) -> str:
    """
    Generate Google dork queries for a target domain.
    Ready to copy-paste into Google / DuckDuckGo / Bing.
    Each dork category targets something specific — exposed files,
    login portals, subdomains, cached sensitive content, etc.
    """
    if not target:
        return "Need a target domain."

    target = target.replace("https://", "").replace("http://", "").split("/")[0]

    dorks = {
        "Exposed Files & Backups": [
            f'site:{target} ext:sql OR ext:bak OR ext:log OR ext:env',
            f'site:{target} ext:xml OR ext:conf OR ext:cfg OR ext:ini',
            f'site:{target} "index of /" backup',
            f'site:{target} filetype:pdf confidential OR internal OR private',
            f'site:{target} ext:php intitle:"phpinfo()"',
        ],
        "Login & Admin Portals": [
            f'site:{target} inurl:login OR inurl:admin OR inurl:dashboard',
            f'site:{target} inurl:wp-admin OR inurl:wp-login',
            f'site:{target} intitle:"Login" OR intitle:"Sign In"',
            f'site:{target} inurl:portal OR inurl:signin OR inurl:auth',
        ],
        "Exposed Credentials / Sensitive Data": [
            f'site:{target} intext:"password" OR intext:"passwd" filetype:txt',
            f'site:{target} intext:"api_key" OR intext:"secret_key" OR intext:"access_token"',
            f'site:{target} intext:"BEGIN RSA PRIVATE KEY"',
            f'site:{target} "db_password" OR "database_password"',
        ],
        "Subdomains & Infrastructure": [
            f'site:*.{target} -www',
            f'site:{target} inurl:dev OR inurl:staging OR inurl:test',
            f'site:{target} inurl:api OR inurl:v1 OR inurl:v2',
            f'intext:"{target}" site:pastebin.com',
            f'intext:"{target}" site:github.com',
        ],
        "Cached / Indexed Content": [
            f'cache:{target}',
            f'site:{target} intext:"Forbidden" OR intext:"Access Denied"',
            f'site:{target} inurl:.git OR inurl:.svn OR inurl:.DS_Store',
            f'site:{target} "This site is under construction"',
        ],
        "Error Pages (Info Disclosure)": [
            f'site:{target} intext:"Warning: mysql_" OR intext:"ORA-" OR intext:"SQLite"',
            f'site:{target} intext:"stack trace" OR intext:"Traceback"',
            f'site:{target} intext:"Fatal error" OR intext:"Parse error"',
            f'site:{target} intitle:"500 Internal Server Error"',
        ],
    }

    lines = [f"[DORK GENERATOR] Queries for: {target}\n"]
    lines.append("  Copy these into Google, DuckDuckGo, or Bing.\n")

    for category, queries in dorks.items():
        lines.append(f"  === {category} ===")
        for q in queries:
            lines.append(f"  {q}")
        lines.append("")

    lines.append("  Pro tip: Use https://dorksearch.com or https://pentest-tools.com/information-gathering/google-hacking for automated dork runs.")

    return "\n".join(lines)
