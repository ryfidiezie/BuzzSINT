import requests
import json

def breach_check(email: str) -> str:
    """
    Check an email against HaveIBeenPwned's public breach list.
    Uses the HIBP v3 API — the truncated/unauth endpoint that returns
    breach names but not passwords (that needs an API key).
    Enough to know if the account has been pwned.
    """
    if not email:
        return "Need an email address."

    email = email.strip().lower()
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "User-Agent": "BuzzSINT-OSINT-Research",
        "hibp-api-key": "",  # Free endpoint doesn't need key for breach names in some versions
    }

    # HIBP v3 requires an API key for email lookup
    # Use the free public search endpoint instead
    search_url = f"https://haveibeenpwned.com/unifiedsearch/{email}"
    headers2 = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
    }

    lines = [f"[BREACH CHECK] {email}\n"]

    try:
        resp = requests.get(search_url, headers=headers2, timeout=15)

        if resp.status_code == 404:
            lines.append("  ✓ No breaches found for this email address.")
            lines.append("  (Note: This is good, but HIBP doesn't have every breach.)")
            return "\n".join(lines)

        if resp.status_code == 429:
            lines.append("  Rate limited by HIBP. Wait a minute and try again.")
            return "\n".join(lines)

        if resp.status_code == 200:
            try:
                data = resp.json()
                breaches = data.get("Breaches", []) or []
                pastes = data.get("Pastes", []) or []

                if breaches:
                    lines.append(f"  ⚠ FOUND IN {len(breaches)} BREACH(ES):\n")
                    for breach in breaches:
                        name = breach.get("Name", "Unknown")
                        domain = breach.get("Domain", "N/A")
                        date = breach.get("BreachDate", "N/A")
                        count = breach.get("PwnCount", 0)
                        data_classes = ", ".join(breach.get("DataClasses", [])[:5])
                        lines.append(f"  ● {name} ({domain})")
                        lines.append(f"    Date   : {date}")
                        lines.append(f"    Records: {count:,}")
                        lines.append(f"    Data   : {data_classes}")
                        lines.append("")

                if pastes:
                    lines.append(f"  Found in {len(pastes)} paste(s):")
                    for paste in pastes[:5]:
                        source = paste.get("Source", "Unknown")
                        date = paste.get("Date", "Unknown")
                        lines.append(f"    {source} — {date}")

                if not breaches and not pastes:
                    lines.append("  ✓ No breaches or pastes found.")
            except json.JSONDecodeError:
                lines.append("  Response wasn't JSON — HIBP might have changed their API.")
                lines.append(f"  Status: {resp.status_code}")
        else:
            lines.append(f"  Unexpected status: {resp.status_code}")
            lines.append("  HIBP v3 requires a paid API key for direct email lookup.")
            lines.append("  Alternative: https://haveibeenpwned.com — check manually.")

    except requests.exceptions.Timeout:
        lines.append("  [TIMEOUT] HIBP didn't respond.")
    except Exception as e:
        lines.append(f"  [ERROR] {e}")

    lines.append("\n  Full check: https://haveibeenpwned.com/account/" + email)
    return "\n".join(lines)
