import requests

# Platforms to check — (display_name, url_template, expected_status_on_found)
PLATFORMS = [
    ("GitHub",         "https://github.com/{}",                     200),
    ("GitLab",         "https://gitlab.com/{}",                     200),
    ("Twitter/X",      "https://twitter.com/{}",                    200),
    ("Instagram",      "https://www.instagram.com/{}/",             200),
    ("TikTok",         "https://www.tiktok.com/@{}",                200),
    ("Reddit",         "https://www.reddit.com/user/{}",            200),
    ("LinkedIn",       "https://www.linkedin.com/in/{}",            200),
    ("YouTube",        "https://www.youtube.com/@{}",               200),
    ("Twitch",         "https://www.twitch.tv/{}",                  200),
    ("Steam",          "https://steamcommunity.com/id/{}",          200),
    ("Pinterest",      "https://www.pinterest.com/{}",              200),
    ("Tumblr",         "https://{}.tumblr.com",                     200),
    ("Medium",         "https://medium.com/@{}",                    200),
    ("Dev.to",         "https://dev.to/{}",                         200),
    ("Keybase",        "https://keybase.io/{}",                     200),
    ("HackerNews",     "https://news.ycombinator.com/user?id={}",   200),
    ("ProductHunt",    "https://www.producthunt.com/@{}",           200),
    ("Pastebin",       "https://pastebin.com/u/{}",                 200),
    ("DockerHub",      "https://hub.docker.com/u/{}",               200),
    ("PyPI",           "https://pypi.org/user/{}",                  200),
    ("npm",            "https://www.npmjs.com/~{}",                 200),
    ("Replit",         "https://replit.com/@{}",                    200),
    ("Codepen",        "https://codepen.io/{}",                     200),
    ("Behance",        "https://www.behance.net/{}",                200),
    ("Dribbble",       "https://dribbble.com/{}",                   200),
    ("Fiverr",         "https://www.fiverr.com/{}",                 200),
    ("Etsy",           "https://www.etsy.com/shop/{}",              200),
]


def _check_platform(username: str, display: str, url_tmpl: str, expected: int, session: requests.Session):
    url = url_tmpl.format(username)
    try:
        resp = session.get(url, timeout=8, allow_redirects=True)
        found = resp.status_code == expected
        # Some platforms return 200 even for missing users — check content
        if found and any(phrase in resp.text.lower() for phrase in
                         ["user not found", "page not found", "does not exist",
                          "sorry, this page", "404", "account suspended"]):
            found = False
        return display, url, found
    except Exception:
        return display, url, None


def username_checker(username: str) -> str:
    """
    Check a username across 27 platforms concurrently.
    Great for correlating identities across the internet.
    """
    if not username:
        return "Need a username to check."

    username = username.strip().lstrip("@")
    lines = [f"[USERNAME CHECKER] Checking '{username}' across {len(PLATFORMS)} platforms\n"]

    import concurrent.futures
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; OSINT-research)"})

    found_list = []
    not_found = []
    error_list = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {
            ex.submit(_check_platform, username, d, u, e, session): d
            for d, u, e in PLATFORMS
        }
        for future in concurrent.futures.as_completed(futures):
            display, url, found = future.result()
            if found is True:
                found_list.append((display, url))
            elif found is False:
                not_found.append(display)
            else:
                error_list.append(display)

    found_list.sort()
    not_found.sort()

    lines.append(f"  === FOUND ({len(found_list)}) ===")
    for display, url in found_list:
        lines.append(f"  ✓ {display:20s}  {url}")

    lines.append(f"\n  === NOT FOUND ({len(not_found)}) ===")
    lines.append(f"  {', '.join(not_found)}")

    if error_list:
        lines.append(f"\n  === ERRORS (timeout/blocked) ===")
        lines.append(f"  {', '.join(error_list)}")

    return "\n".join(lines)
