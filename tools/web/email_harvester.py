import requests
import re

def harvest_emails(url: str) -> str:
    """
    Scrape a URL for email addresses exposed in HTML.
    Checks both visible text and raw source (sometimes devs are dumb
    and leave emails in comments, JS vars, meta tags, etc.)
    """
    if not url:
        return "Give me a URL to scrape."

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        resp.raise_for_status()
        html = resp.text
    except requests.exceptions.Timeout:
        return f"[TIMEOUT] {url} didn't respond in 15s."
    except requests.exceptions.HTTPError as e:
        return f"[HTTP ERROR] {e}"
    except Exception as e:
        return f"[ERROR] {e}"

    # Regex for emails — deliberately broad to catch obfuscated ones too
    email_pattern = re.compile(
        r"[a-zA-Z0-9._%+\-]+\s*[\[@\(at\)]\s*[a-zA-Z0-9.\-]+\s*[.\[dot\]]\s*[a-zA-Z]{2,}",
        re.IGNORECASE
    )
    # Strict pattern for clean emails
    strict_pattern = re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        re.IGNORECASE
    )

    raw_matches = set(strict_pattern.findall(html))

    # Filter out false positives (image names, libraries, etc.)
    noise = {"example.com", "domain.com", "email.com", "sentry.io", "w3.org",
             "schema.org", "fontawesome.com", "jquery.com"}
    emails = sorted({
        e.lower() for e in raw_matches
        if not any(n in e.lower() for n in noise)
    })

    final_url = resp.url
    lines = [f"[EMAIL HARVEST] Scraped: {final_url}\n"]

    if not emails:
        lines.append("No emails found. Either they're smart about it or nothing's there.")
        lines.append("Try scraping /contact, /about, /team pages directly.")
    else:
        lines.append(f"Found {len(emails)} email address(es):\n")
        for email in emails:
            lines.append(f"  {email}")

    return "\n".join(lines)
