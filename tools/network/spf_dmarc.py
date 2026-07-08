import dns.resolver

def spf_dmarc_check(domain: str) -> str:
    """
    Check SPF, DKIM (common selectors), and DMARC records.
    These tell you everything about a domain's email security posture.
    Missing or weak configs = domain is spoofable for phishing.
    """
    if not domain:
        return "Need a domain."

    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    lines = [f"[SPF / DKIM / DMARC] Email security check for {domain}\n"]

    def query_txt(host):
        try:
            answers = dns.resolver.resolve(host, "TXT", lifetime=5)
            return [r.to_text().strip('"') for r in answers]
        except Exception:
            return []

    # --- SPF ---
    lines.append("  === SPF ===")
    txt_records = query_txt(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]
    if spf_records:
        for spf in spf_records:
            lines.append(f"  Found: {spf}")
            if "-all" in spf:
                lines.append("  Grade: STRICT (-all) — unauthorized senders hard fail. Good.")
            elif "~all" in spf:
                lines.append("  Grade: SOFT (~all) — softfail, still deliverable. Weak.")
            elif "?all" in spf:
                lines.append("  Grade: NEUTRAL (?all) — no policy. Useless.")
            elif "+all" in spf:
                lines.append("  Grade: DANGEROUS (+all) — ANYONE can send as this domain!")
    else:
        lines.append("  NOT FOUND — domain has no SPF record.")
        lines.append("  ⚠ Domain is spoofable for phishing emails.")
    lines.append("")

    # --- DKIM (common selectors) ---
    lines.append("  === DKIM ===")
    dkim_selectors = [
        "default", "google", "mail", "email", "k1", "k2", "s1", "s2",
        "dkim", "selector1", "selector2", "smtp", "mta", "protonmail",
        "mailchimp", "mandrill", "sendgrid", "amazonses"
    ]
    found_dkim = []
    for sel in dkim_selectors:
        records = query_txt(f"{sel}._domainkey.{domain}")
        for r in records:
            if "v=DKIM1" in r or "p=" in r:
                found_dkim.append((sel, r[:120]))

    if found_dkim:
        for sel, rec in found_dkim:
            lines.append(f"  Selector '{sel}': {rec}...")
    else:
        lines.append("  No DKIM records found (checked common selectors).")
        lines.append("  Note: Custom selectors exist — check mail headers for the real selector.")
    lines.append("")

    # --- DMARC ---
    lines.append("  === DMARC ===")
    dmarc_records = query_txt(f"_dmarc.{domain}")
    dmarc = [r for r in dmarc_records if "v=DMARC1" in r]
    if dmarc:
        for d in dmarc:
            lines.append(f"  Found: {d}")
            if "p=reject" in d:
                lines.append("  Policy: REJECT — emails failing checks are rejected. Strong.")
            elif "p=quarantine" in d:
                lines.append("  Policy: QUARANTINE — failing emails go to spam. Decent.")
            elif "p=none" in d:
                lines.append("  Policy: NONE — monitoring only, no enforcement. Weak.")
            rua = [p for p in d.split(";") if "rua=" in p]
            if rua:
                lines.append(f"  Reports to: {rua[0].strip()}")
    else:
        lines.append("  NOT FOUND — no DMARC policy.")
        lines.append("  ⚠ Combined with weak SPF, domain is wide open for spoofing.")

    return "\n".join(lines)
