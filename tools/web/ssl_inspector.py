import socket
import ssl
import datetime

def inspect_ssl(hostname: str) -> str:
    """
    Deep SSL/TLS cert inspection.
    Pulls the full cert chain, SANs, issuer, validity window, cipher suite.
    SANs are gold — they reveal every domain that shares this cert
    (subdomains, sister sites, internal hostnames that slipped through).
    """
    if not hostname:
        return "Need a hostname."

    # Strip protocol if someone pastes a URL
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]
    port = 443

    lines = [f"[SSL INSPECTOR] {hostname}:{port}\n"]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        lines.append(f"  ⚠ Cert verification FAILED: {e}")
        lines.append("  (Trying without verification to grab cert anyway...)\n")
        try:
            context2 = ssl.create_default_context()
            context2.check_hostname = False
            context2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context2.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert(binary_form=False)
        except Exception as e2:
            return f"[ERROR] Can't connect at all: {e2}"
    except Exception as e:
        return f"[ERROR] {e}"

    # --- Cipher Info ---
    if cipher:
        lines.append(f"  Cipher Suite : {cipher[0]}")
        lines.append(f"  Protocol     : {cipher[1]}")
        lines.append(f"  Key Bits     : {cipher[2]}")
        lines.append("")

    if not cert:
        lines.append("  Could not retrieve cert details (binary form only).")
        return "\n".join(lines)

    # --- Subject ---
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    lines.append(f"  Subject CN   : {subject.get('commonName', 'N/A')}")
    lines.append(f"  Organization : {subject.get('organizationName', 'N/A')}")
    lines.append(f"  Country      : {subject.get('countryName', 'N/A')}")
    lines.append("")
    lines.append(f"  Issued By    : {issuer.get('commonName', 'N/A')} / {issuer.get('organizationName', 'N/A')}")
    lines.append("")

    # --- Validity ---
    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")

    def parse_cert_date(s):
        try:
            return datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
        except Exception:
            return None

    not_before = parse_cert_date(not_before_str)
    not_after = parse_cert_date(not_after_str)
    now = datetime.datetime.utcnow()

    if not_before and not_after:
        days_left = (not_after - now).days
        status = "✓ VALID" if days_left > 0 else "✗ EXPIRED"
        lines.append(f"  Valid From   : {not_before.strftime('%Y-%m-%d')}")
        lines.append(f"  Valid Until  : {not_after.strftime('%Y-%m-%d')}  [{status}, {abs(days_left)} days {'left' if days_left > 0 else 'ago'}]")
        if 0 < days_left < 30:
            lines.append(f"  ⚠ EXPIRING SOON — only {days_left} days left!")
        lines.append("")

    # --- SANs (the juicy part) ---
    sans = cert.get("subjectAltName", [])
    if sans:
        san_vals = [v for t, v in sans if t == "DNS"]
        lines.append(f"  Subject Alt Names ({len(san_vals)} entries) — potential related domains:")
        for san in sorted(san_vals):
            lines.append(f"    {san}")
    else:
        lines.append("  No SANs found.")

    return "\n".join(lines)
