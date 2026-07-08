import re

def phone_osint(number: str) -> str:
    """
    Analyze a phone number — format, country, carrier type, line type.
    Uses pattern matching + public knowledge. No API needed.
    Also generates lookup URLs for deeper research.
    """
    if not number:
        return "Need a phone number."

    # Strip everything but digits and +
    clean = re.sub(r'[^\d+]', '', number.strip())
    lines = [f"[PHONE OSINT] {number}\n"]
    lines.append(f"  Cleaned: {clean}\n")

    # Country code detection
    country_codes = {
        "1":    ("United States / Canada", "NANP"),
        "7":    ("Russia / Kazakhstan", "RU/KZ"),
        "20":   ("Egypt", "EG"),
        "27":   ("South Africa", "ZA"),
        "30":   ("Greece", "GR"),
        "31":   ("Netherlands", "NL"),
        "32":   ("Belgium", "BE"),
        "33":   ("France", "FR"),
        "34":   ("Spain", "ES"),
        "36":   ("Hungary", "HU"),
        "39":   ("Italy", "IT"),
        "40":   ("Romania", "RO"),
        "41":   ("Switzerland", "CH"),
        "43":   ("Austria", "AT"),
        "44":   ("United Kingdom", "GB"),
        "45":   ("Denmark", "DK"),
        "46":   ("Sweden", "SE"),
        "47":   ("Norway", "NO"),
        "48":   ("Poland", "PL"),
        "49":   ("Germany", "DE"),
        "51":   ("Peru", "PE"),
        "52":   ("Mexico", "MX"),
        "54":   ("Argentina", "AR"),
        "55":   ("Brazil", "BR"),
        "56":   ("Chile", "CL"),
        "57":   ("Colombia", "CO"),
        "61":   ("Australia", "AU"),
        "62":   ("Indonesia", "ID"),
        "63":   ("Philippines", "PH"),
        "64":   ("New Zealand", "NZ"),
        "65":   ("Singapore", "SG"),
        "66":   ("Thailand", "TH"),
        "81":   ("Japan", "JP"),
        "82":   ("South Korea", "KR"),
        "84":   ("Vietnam", "VN"),
        "86":   ("China", "CN"),
        "90":   ("Turkey", "TR"),
        "91":   ("India", "IN"),
        "92":   ("Pakistan", "PK"),
        "94":   ("Sri Lanka", "LK"),
        "95":   ("Myanmar", "MM"),
        "98":   ("Iran", "IR"),
        "212":  ("Morocco", "MA"),
        "213":  ("Algeria", "DZ"),
        "216":  ("Tunisia", "TN"),
        "218":  ("Libya", "LY"),
        "234":  ("Nigeria", "NG"),
        "254":  ("Kenya", "KE"),
        "380":  ("Ukraine", "UA"),
        "420":  ("Czech Republic", "CZ"),
        "972":  ("Israel", "IL"),
        "994":  ("Azerbaijan", "AZ"),
        "998":  ("Uzbekistan", "UZ"),
    }

    digits = clean.lstrip("+")
    detected_country = None
    detected_cc = None
    for cc in sorted(country_codes.keys(), key=len, reverse=True):
        if digits.startswith(cc):
            detected_country, region = country_codes[cc]
            detected_cc = cc
            break

    if detected_cc:
        lines.append(f"  Country Code  : +{detected_cc} ({detected_country})")
        national = digits[len(detected_cc):]
        lines.append(f"  National Part : {national}")

        # NANP specific (US/Canada)
        if detected_cc == "1" and len(national) == 10:
            area = national[:3]
            exchange = national[3:6]
            subscriber = national[6:]
            lines.append(f"  Format (NANP) : ({area}) {exchange}-{subscriber}")
            lines.append(f"  Area Code     : {area}")
    else:
        lines.append(f"  Country Code  : Unknown")

    lines.append(f"  Total Digits  : {len(digits)}")

    # VoIP / toll-free detection (US)
    if digits.startswith("1"):
        national = digits[1:]
        toll_free = ["800", "888", "877", "866", "855", "844", "833", "822"]
        if len(national) >= 3 and national[:3] in toll_free:
            lines.append(f"  Type          : Toll-Free (US)")
        premium = ["900", "976"]
        if len(national) >= 3 and national[:3] in premium:
            lines.append(f"  Type          : Premium Rate — watch out")

    lines.append("")
    lines.append("  === Lookup Resources ===")
    encoded = re.sub(r'\D', '', clean)
    lines.append(f"  Truecaller  : https://www.truecaller.com/search/us/{encoded}")
    lines.append(f"  NumLookup   : https://www.numlookup.com/?number={clean}")
    lines.append(f"  Spy Dialer  : https://www.spydialer.com/default.aspx?fl={encoded}")
    lines.append(f"  AnyWho      : https://www.anywho.com/reverse-phone/{encoded}")
    lines.append(f"  Google Dork : site:linkedin.com \"{number}\" OR \"{clean}\"")

    return "\n".join(lines)


def shodan_dorker(query: str) -> str:
    """
    Generate Shodan search queries for a target.
    Shodan indexes internet-connected devices — servers, cameras, routers,
    industrial systems, anything with an open port.
    These queries need a Shodan account (free tier works for basic search).
    """
    if not query:
        return "Need a domain, IP, org name, or tech keyword."

    query = query.strip()
    lines = [f"[SHODAN DORKER] Queries for: {query}\n"]
    lines.append("  Paste these into https://shodan.io/search (free account needed)\n")

    dorks = {
        "Basic Target": [
            f'hostname:"{query}"',
            f'ssl.cert.subject.cn:"{query}"',
            f'ssl:"{query}"',
            f'http.title:"{query}"',
            f'http.html:"{query}"',
        ],
        "Open Services (if querying by IP/domain)": [
            f'hostname:"{query}" port:22',
            f'hostname:"{query}" port:3389',
            f'hostname:"{query}" port:21',
            f'hostname:"{query}" port:23',
            f'hostname:"{query}" port:3306',
            f'hostname:"{query}" port:6379',
            f'hostname:"{query}" port:27017',
            f'hostname:"{query}" port:9200',
        ],
        "Vulnerable Stuff": [
            f'hostname:"{query}" vuln:CVE-2021-44228',  # Log4Shell
            f'hostname:"{query}" vuln:CVE-2021-26855',  # ProxyLogon
            f'hostname:"{query}" http.status:200 http.title:"phpMyAdmin"',
        ],
        "Exposed Tech (by org/keyword)": [
            f'org:"{query}"',
            f'org:"{query}" product:"MongoDB"',
            f'org:"{query}" product:"Elasticsearch"',
            f'org:"{query}" product:"Apache httpd"',
            f'org:"{query}" port:22 banner:"OpenSSH"',
            f'org:"{query}" "default password"',
            f'org:"{query}" http.title:"Dashboard"',
            f'org:"{query}" http.title:"Login"',
        ],
        "IoT / Cameras": [
            f'org:"{query}" product:"webcam"',
            f'org:"{query}" "Server: IP Camera"',
            f'org:"{query}" port:554',  # RTSP
        ],
    }

    for category, queries in dorks.items():
        lines.append(f"  === {category} ===")
        for q in queries:
            lines.append(f"  {q}")
            lines.append(f"  → https://www.shodan.io/search?query={requests_encode(q)}")
        lines.append("")

    lines.append("  Pro tip: Shodan.io/explore has pre-built searches for cameras, ICS, etc.")
    return "\n".join(lines)


def requests_encode(s: str) -> str:
    import urllib.parse
    return urllib.parse.quote(s)
