import requests

def analyze_headers(url: str) -> str:
    """Fetch and analyze HTTP headers for a given URL."""
    if not url:
        return "No URL provided."
    
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        headers = response.headers
        
        result = [f"--- HTTP Headers for {url} (Status: {response.status_code}) ---"]
        for key, value in headers.items():
            result.append(f"{key}: {value}")
            
        # Basic security header checks
        result.append("\n--- Security Header Analysis ---")
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection"
        ]
        
        for sh in security_headers:
            if sh in headers:
                result.append(f"[+] {sh} is PRESENT.")
            else:
                result.append(f"[-] {sh} is MISSING.")
                
        return "\n".join(result)
        
    except requests.exceptions.RequestException as e:
        return f"Header analysis failed: {e}"
