import requests
import re

def find_forms(url: str) -> str:
    """
    Scrape all HTML forms from a page.
    Maps every input field, action URL, and method.
    Forms are the primary attack surface for injection, CSRF, and auth bypass.
    """
    if not url:
        return "Need a URL."

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
        base_url = resp.url
    except Exception as e:
        return f"[ERROR] {e}"

    # Extract forms
    form_pattern = re.compile(r'<form([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
    input_pattern = re.compile(r'<input([^>]*)>', re.IGNORECASE)
    textarea_pattern = re.compile(r'<textarea([^>]*)>', re.IGNORECASE)
    select_pattern = re.compile(r'<select([^>]*)>', re.IGNORECASE)
    button_pattern = re.compile(r'<button([^>]*)>(.*?)</button>', re.IGNORECASE | re.DOTALL)

    def get_attr(tag_str, attr):
        match = re.search(rf'{attr}=["\']([^"\']*)["\']', tag_str, re.IGNORECASE)
        return match.group(1) if match else None

    forms = form_pattern.findall(html)
    lines = [f"[FORM FINDER] {base_url}\n"]
    lines.append(f"  Found {len(forms)} form(s):\n")

    for i, (form_attrs, form_body) in enumerate(forms, 1):
        action = get_attr(form_attrs, "action") or "(current page)"
        method = (get_attr(form_attrs, "method") or "GET").upper()
        form_id = get_attr(form_attrs, "id") or "N/A"
        enc = get_attr(form_attrs, "enctype") or "application/x-www-form-urlencoded"

        lines.append(f"  Form {i}:")
        lines.append(f"    Action  : {action}")
        lines.append(f"    Method  : {method}")
        lines.append(f"    ID      : {form_id}")
        lines.append(f"    Enctype : {enc}")

        if method == "GET":
            lines.append("    ⚠ GET form — parameters in URL, no CSRF risk but visible in logs/history")
        if "multipart" in enc.lower():
            lines.append("    → File upload form")

        # Find CSRF tokens
        csrf_fields = []
        all_inputs = input_pattern.findall(form_body)
        for inp in all_inputs:
            name = get_attr(inp, "name") or ""
            if any(c in name.lower() for c in ["csrf", "token", "nonce", "_wpnonce"]):
                csrf_fields.append(name)

        if csrf_fields:
            lines.append(f"    CSRF Token: {', '.join(csrf_fields)} ✓")
        else:
            lines.append("    CSRF Token: None found ⚠")

        lines.append("    Fields:")
        for inp in all_inputs:
            itype = get_attr(inp, "type") or "text"
            iname = get_attr(inp, "name") or "(unnamed)"
            ivalue = get_attr(inp, "value") or ""
            placeholder = get_attr(inp, "placeholder") or ""
            lines.append(f"      [{itype:12s}] name={iname!r:<25} {f'value={ivalue!r}' if ivalue else ''} {f'placeholder={placeholder!r}' if placeholder else ''}")

        for ta in textarea_pattern.findall(form_body):
            lines.append(f"      [textarea   ] name={get_attr(ta, 'name') or '(unnamed)'!r}")

        for sel in select_pattern.findall(form_body):
            lines.append(f"      [select     ] name={get_attr(sel, 'name') or '(unnamed)'!r}")

        lines.append("")

    return "\n".join(lines)
