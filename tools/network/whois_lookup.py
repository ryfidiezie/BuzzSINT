import whois
import json

def get_whois_info(domain: str) -> str:
    """Perform a WHOIS lookup for the given domain."""
    if not domain:
        return "No domain provided."
    
    try:
        w = whois.whois(domain)
        # Convert to a readable string (dict to formatted JSON)
        return json.dumps(w, indent=2, default=str)
    except Exception as e:
        return f"WHOIS Lookup failed: {e}"
