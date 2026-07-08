import requests
import json

def enumerate_subdomains(domain: str) -> str:
    """
    Pull subdomains from crt.sh (Certificate Transparency logs).
    No API key needed — crt.sh is public and indexes every cert ever issued.
    """
    if not domain:
        return "Give me a domain, genius."

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    results = []

    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return f"[TIMEOUT] crt.sh took too long — try again or check your connection."
    except requests.exceptions.HTTPError as e:
        return f"[HTTP ERROR] {e}"
    except json.JSONDecodeError:
        return "[PARSE ERROR] crt.sh returned garbage — domain might not exist in CT logs."
    except Exception as e:
        return f"[ERROR] {e}"

    # Deduplicate and clean
    seen = set()
    subdomains = []
    for entry in data:
        name = entry.get("name_value", "")
        # crt.sh can return multi-line SANs
        for sub in name.split("\n"):
            sub = sub.strip().lower().lstrip("*.")
            if sub and sub not in seen and domain in sub:
                seen.add(sub)
                subdomains.append(sub)

    subdomains.sort()

    if not subdomains:
        return f"No subdomains found in CT logs for {domain}. Either it's squeaky clean or you typo'd it."

    lines = [f"[crt.sh] Found {len(subdomains)} unique subdomains for {domain}:\n"]
    lines += [f"  {s}" for s in subdomains]
    return "\n".join(lines)
