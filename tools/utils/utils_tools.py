import hashlib
import hmac

def hash_generator(text: str) -> str:
    """
    Generate every common hash of the input text.
    MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3 variants.
    """
    if not text:
        return "Need input text to hash."

    data = text.encode("utf-8")
    lines = [f"[HASH GENERATOR] Input: {text!r} ({len(data)} bytes)\n"]

    algos = [
        ("MD5",     hashlib.md5(data).hexdigest()),
        ("SHA1",    hashlib.sha1(data).hexdigest()),
        ("SHA224",  hashlib.sha224(data).hexdigest()),
        ("SHA256",  hashlib.sha256(data).hexdigest()),
        ("SHA384",  hashlib.sha384(data).hexdigest()),
        ("SHA512",  hashlib.sha512(data).hexdigest()),
        ("SHA3-256",hashlib.sha3_256(data).hexdigest()),
        ("SHA3-512",hashlib.sha3_512(data).hexdigest()),
        ("BLAKE2b", hashlib.blake2b(data).hexdigest()),
        ("BLAKE2s", hashlib.blake2s(data).hexdigest()),
    ]

    for name, digest in algos:
        lines.append(f"  {name:12s}: {digest}")

    return "\n".join(lines)


def hash_lookup(hash_val: str) -> str:
    """
    Look up a hash against free public cracking databases.
    MD5/SHA1/SHA256 that appear in password dumps are often pre-cracked.
    """
    if not hash_val:
        return "Need a hash to look up."

    hash_val = hash_val.strip().lower()
    lines = [f"[HASH LOOKUP] {hash_val}\n"]

    # Detect hash type by length
    hash_types = {
        32: "MD5",
        40: "SHA1",
        56: "SHA224",
        64: "SHA256",
        96: "SHA384",
        128: "SHA512",
    }
    htype = hash_types.get(len(hash_val), "Unknown")
    lines.append(f"  Detected type: {htype} ({len(hash_val)} chars)\n")

    # Try md5decrypt.net (free API)
    import requests

    # Method 1: md5.gromweb.com
    try:
        resp = requests.get(
            f"https://md5.gromweb.com/?md5={hash_val}",
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        import re
        match = re.search(r'<em class="long-animation">(.*?)</em>', resp.text)
        if match and match.group(1) != hash_val:
            lines.append(f"  ✓ CRACKED (md5.gromweb.com): {match.group(1)!r}")
        else:
            lines.append("  gromweb.com: Not found")
    except Exception as e:
        lines.append(f"  gromweb.com: Error — {e}")

    # Method 2: Lookup links
    lines.append("\n  Manual lookup resources:")
    lines.append(f"  CrackStation : https://crackstation.net/ (paste hash)")
    lines.append(f"  HashKiller   : https://hashkiller.io/listmanager")
    lines.append(f"  Hashes.com   : https://hashes.com/en/decrypt/hash")
    lines.append(f"  MD5Decrypt   : https://md5decrypt.net/en/#answer (MD5 only)")

    return "\n".join(lines)


def encode_decode(text: str) -> str:
    """
    Encode/decode input in Base64, URL encoding, and Hex.
    Auto-detects if input is already encoded and decodes it.
    """
    import base64
    import urllib.parse

    if not text:
        return "Need some text."

    text = text.strip()
    lines = [f"[ENCODE/DECODE] Input: {text!r}\n"]

    # --- Base64 ---
    lines.append("  === Base64 ===")
    # Encode
    b64_encoded = base64.b64encode(text.encode("utf-8")).decode()
    lines.append(f"  Encoded : {b64_encoded}")
    # Try decode
    try:
        # Pad if needed
        padded = text + "=" * (4 - len(text) % 4) if len(text) % 4 else text
        b64_decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        lines.append(f"  Decoded : {b64_decoded}")
    except Exception:
        lines.append("  Decoded : (not valid base64)")
    lines.append("")

    # --- URL Encoding ---
    lines.append("  === URL Encoding ===")
    url_encoded = urllib.parse.quote(text)
    lines.append(f"  Encoded : {url_encoded}")
    try:
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text:
            lines.append(f"  Decoded : {url_decoded}")
    except Exception:
        pass
    lines.append("")

    # --- Hex ---
    lines.append("  === Hex ===")
    hex_encoded = text.encode("utf-8").hex()
    lines.append(f"  Encoded : {hex_encoded}")
    try:
        hex_decoded = bytes.fromhex(text.replace(" ", "").replace("0x", "")).decode("utf-8", errors="replace")
        if hex_decoded != text:
            lines.append(f"  Decoded : {hex_decoded}")
    except Exception:
        lines.append("  Decoded : (not valid hex)")
    lines.append("")

    # --- HTML Entities ---
    lines.append("  === HTML Entities ===")
    import html
    html_encoded = html.escape(text)
    html_decoded = html.unescape(text)
    lines.append(f"  Escaped   : {html_encoded}")
    if html_decoded != text:
        lines.append(f"  Unescaped : {html_decoded}")

    return "\n".join(lines)


def jwt_decoder(token: str) -> str:
    """
    Decode a JWT without verification.
    Shows header, payload, and signature analysis.
    Flags dangerous configs: alg:none, weak algorithms, missing expiry.
    """
    import base64
    import json

    if not token:
        return "Need a JWT token."

    token = token.strip()
    lines = [f"[JWT DECODER] {token[:30]}...\n"]

    parts = token.split(".")
    if len(parts) != 3:
        return f"[ERROR] Not a JWT — needs 3 parts separated by dots. Got {len(parts)} parts."

    def b64_decode_part(part: str) -> dict:
        # JWT uses URL-safe base64 without padding
        padded = part + "=" * (4 - len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)

    try:
        header = b64_decode_part(parts[0])
        lines.append("  === Header ===")
        for k, v in header.items():
            lines.append(f"  {k}: {v}")

        alg = header.get("alg", "").upper()
        if alg == "NONE":
            lines.append("  ⚠ CRITICAL: alg=none — signature bypassed, token is unsigned!")
        elif alg in ("HS256", "HS384", "HS512"):
            lines.append(f"  Algorithm: {alg} (HMAC-SHA — symmetric, secret must be strong)")
        elif alg.startswith("RS") or alg.startswith("ES"):
            lines.append(f"  Algorithm: {alg} (Asymmetric — stronger)")
        lines.append("")
    except Exception as e:
        lines.append(f"  Header decode failed: {e}\n")

    try:
        payload = b64_decode_part(parts[1])
        lines.append("  === Payload ===")
        for k, v in payload.items():
            # Format timestamps
            if k in ("exp", "iat", "nbf") and isinstance(v, int):
                import datetime
                dt = datetime.datetime.utcfromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S UTC")
                lines.append(f"  {k}: {v} ({dt})")
            else:
                lines.append(f"  {k}: {v}")

        # Flags
        import time
        now = time.time()
        exp = payload.get("exp")
        if exp is None:
            lines.append("\n  ⚠ No expiry (exp) — token never expires")
        elif exp < now:
            import datetime
            lines.append(f"\n  ⚠ TOKEN EXPIRED at {datetime.datetime.utcfromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        else:
            import datetime
            lines.append(f"\n  ✓ Token expires: {datetime.datetime.utcfromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S UTC')}")

        if not payload.get("iss"):
            lines.append("  ⚠ No issuer (iss) claim")
        if not payload.get("aud"):
            lines.append("  ⚠ No audience (aud) claim")

    except Exception as e:
        lines.append(f"  Payload decode failed: {e}\n")

    lines.append(f"\n  === Signature ===")
    lines.append(f"  {parts[2][:40]}...")
    lines.append("  Note: Signature NOT verified — this is for analysis only.")
    lines.append("  To verify: jwt.io or python-jwt library with the secret/public key.")

    return "\n".join(lines)


def ip_converter(ip: str) -> str:
    """
    Convert an IP between decimal, hex, octal, binary, and integer forms.
    Also useful for WAF bypasses — some firewalls don't recognize
    decimal notation (2130706433) or hex (0x7f000001) as localhost.
    """
    import ipaddress

    if not ip:
        return "Need an IP address."

    ip = ip.strip()
    lines = [f"[IP CONVERTER] {ip}\n"]

    try:
        # Handle integer input
        if ip.isdigit():
            addr = ipaddress.IPv4Address(int(ip))
        elif ip.startswith("0x"):
            addr = ipaddress.IPv4Address(int(ip, 16))
        else:
            addr = ipaddress.ip_address(ip)
    except ValueError as e:
        return f"[ERROR] {e}"

    if isinstance(addr, ipaddress.IPv4Address):
        packed = addr.packed
        n = int(addr)
        octets = [b for b in packed]

        lines += [
            f"  Dotted Decimal : {addr}",
            f"  Integer        : {n}",
            f"  Hexadecimal    : 0x{n:08X}  ({'.'.join(f'{o:02x}' for o in octets)})",
            f"  Octal          : {'0' + '.'.join(oct(o)[2:] for o in octets)}",
            f"  Binary         : {'.'.join(f'{o:08b}' for o in octets)}",
            f"  CIDR /32       : {addr}/32",
            "",
            f"  === WAF Bypass Formats ===",
            f"  Integer      : http://{n}/",
            f"  Hex          : http://0x{n:08X}/",
            f"  Octal        : http://0{'.'.join(f'0{oct(o)[2:]}' for o in octets)}/",
            f"  Mixed hex    : http://0x{n >> 16:04X}.{n & 0xFFFF}/",
        ]

        # Special addresses
        if addr.is_loopback:
            lines.append(f"\n  Type: Loopback (localhost)")
        elif addr.is_private:
            lines.append(f"\n  Type: Private / RFC1918")
        elif addr.is_global:
            lines.append(f"\n  Type: Public / Global")
        if addr.is_reserved:
            lines.append(f"  Note: Reserved address")

    else:
        n = int(addr)
        lines += [
            f"  IPv6 Full      : {addr.exploded}",
            f"  IPv6 Compressed: {addr}",
            f"  Integer        : {n}",
            f"  Hexadecimal    : {n:#034x}",
        ]

    return "\n".join(lines)
