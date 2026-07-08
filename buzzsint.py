import asyncio
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Button, Input, Log, ListItem, ListView, Label
from textual.reactive import reactive
from textual import work

# ── Network ─────────────────────────────────────────────────────────────────
from tools.network.dns_lookup import get_dns_records
from tools.network.whois_lookup import get_whois_info
from tools.network.subdomain_enum import enumerate_subdomains
from tools.network.port_scanner import scan_ports
from tools.network.ip_geo import geolocate_ip
from tools.network.reverse_ip import reverse_ip
from tools.network.asn_lookup import asn_lookup
from tools.network.zone_transfer import zone_transfer
from tools.network.dns_brute import dns_brute
from tools.network.spf_dmarc import spf_dmarc_check
from tools.network.cidr_calc import cidr_calc
from tools.network.bgp_lookup import bgp_lookup

# ── Web ──────────────────────────────────────────────────────────────────────
from tools.web.ssl_inspector import inspect_ssl
from tools.web.tech_fingerprint import fingerprint_tech
from tools.web.header_analyzer import analyze_headers
from tools.web.security_headers import grade_security_headers
from tools.web.email_harvester import harvest_emails
from tools.web.link_extractor import extract_links
from tools.web.robots_parser import parse_robots
from tools.web.dir_brute import dir_brute
from tools.web.js_analyzer import analyze_js
from tools.web.cookie_analyzer import analyze_cookies
from tools.web.form_finder import find_forms
from tools.web.cors_redirect_methods import check_cors, trace_redirects, test_http_methods

# ── OSINT ────────────────────────────────────────────────────────────────────
from tools.osint.wayback import wayback_lookup
from tools.osint.dork_gen import generate_dorks
from tools.osint.username_checker import username_checker
from tools.osint.breach_check import breach_check
from tools.osint.github_recon import github_recon
from tools.osint.phone_shodan import phone_osint, shodan_dorker

# ── Threat Intel ─────────────────────────────────────────────────────────────
from tools.threat.threat_intel import check_blacklists, cve_lookup, tor_exit_check

# ── Crypto / Darkweb ─────────────────────────────────────────────────────────
from tools.crypto.crypto_tools import bitcoin_lookup, eth_lookup, onion_extractor

# ── Utils ────────────────────────────────────────────────────────────────────
from tools.utils.utils_tools import hash_generator, hash_lookup, encode_decode, jwt_decoder, ip_converter


BUZZWORDS = [
    "Tip: crt.sh is your best free friend for subdomain recon.",
    "Tip: Redis on 6379 with no auth = jackpot. Check your port scans.",
    "Tip: SANs on SSL certs reveal domains the dev thought were hidden.",
    "Tip: Wayback Machine finds admin panels devs 'deleted'.",
    "Tip: .env files indexed by Google are a classic skid find.",
    "Tip: MongoDB on 27017 open to the internet — it happens. A lot.",
    "Tip: Stack traces in error pages = free tech stack intel.",
    "Tip: Dev/staging subdomains are almost never as hardened as prod.",
    "Tip: Check pastebin.com and github.com for your target domain.",
    "Tip: ASN lookups tell you who's hosting — useful for pivoting.",
    "Tip: HSTS missing? Downgrade attack surface exists.",
    "Tip: robots.txt Disallow paths are a roadmap to the good stuff.",
    "Tip: Shared hosting = one vuln affects every domain on that IP.",
    "Tip: Security headers grade F = someone is not doing their job.",
    "Tip: alg=none in JWT = signature bypass. Free auth bypass.",
    "Tip: JS files are public. Devs put secrets there. Always check.",
    "Tip: AXFR zone transfer = full DNS dump when it works (~5% do).",
    "Tip: SPF +all = anyone can spoof this domain's email.",
    "Tip: PUT/DELETE accepted without auth = writable server.",
    "Tip: SameSite=None cookies without Secure = CSRF wide open.",
]

# ── Module Registry ───────────────────────────────────────────────────────────
# Format: {group_name: [(display_name, function, input_hint), ...]}
GROUPS = {
    "◆ NETWORK": [
        ("DNS Lookup",       get_dns_records,     "domain.com"),
        ("WHOIS",            get_whois_info,      "domain.com"),
        ("Subdomain Enum",   enumerate_subdomains,"domain.com"),
        ("DNS Brute Force",  dns_brute,           "domain.com"),
        ("Zone Transfer",    zone_transfer,       "domain.com"),
        ("Port Scanner",     scan_ports,          "domain.com or IP"),
        ("IP Geolocation",   geolocate_ip,        "IP or domain"),
        ("Reverse IP",       reverse_ip,          "IP or domain"),
        ("ASN Lookup",       asn_lookup,          "AS13335 or IP"),
        ("BGP Lookup",       bgp_lookup,          "AS13335 or IP"),
        ("SPF / DMARC",      spf_dmarc_check,     "domain.com"),
        ("CIDR Calc",        cidr_calc,           "192.168.1.0/24"),
    ],
    "◆ WEB": [
        ("Header Analysis",  analyze_headers,     "https://domain.com"),
        ("Security Headers", grade_security_headers,"https://domain.com"),
        ("SSL Inspector",    inspect_ssl,         "domain.com"),
        ("Tech Fingerprint", fingerprint_tech,    "https://domain.com"),
        ("Dir Brute Force",  dir_brute,           "https://domain.com"),
        ("JS Analyzer",      analyze_js,          "https://domain.com"),
        ("Form Finder",      find_forms,          "https://domain.com"),
        ("Cookie Analyzer",  analyze_cookies,     "https://domain.com"),
        ("CORS Check",       check_cors,          "https://domain.com"),
        ("Redirect Tracer",  trace_redirects,     "domain.com"),
        ("HTTP Methods",     test_http_methods,   "https://domain.com"),
        ("Email Harvester",  harvest_emails,      "https://domain.com"),
        ("Link Extractor",   extract_links,       "https://domain.com"),
        ("Robots.txt",       parse_robots,        "domain.com"),
    ],
    "◆ OSINT": [
        ("Wayback Machine",  wayback_lookup,      "domain.com"),
        ("Dork Generator",   generate_dorks,      "domain.com"),
        ("Username Check",   username_checker,    "username"),
        ("Breach Check",     breach_check,        "email@domain.com"),
        ("GitHub Recon",     github_recon,        "username or search:term"),
        ("Phone OSINT",      phone_osint,         "+1 555 123 4567"),
        ("Shodan Dorker",    shodan_dorker,       "domain or org name"),
    ],
    "◆ THREAT INTEL": [
        ("Blacklist Check",  check_blacklists,    "IP address"),
        ("CVE Lookup",       cve_lookup,          "CVE-2021-44228 or keyword"),
        ("Tor Exit Check",   tor_exit_check,      "IP address"),
    ],
    "◆ CRYPTO": [
        ("Bitcoin Lookup",   bitcoin_lookup,      "BTC address"),
        ("Ethereum Lookup",  eth_lookup,          "0x... ETH address"),
        ("Onion Extractor",  onion_extractor,     "URL or paste text"),
    ],
    "◆ UTILS": [
        ("Hash Generator",   hash_generator,      "text to hash"),
        ("Hash Lookup",      hash_lookup,         "md5/sha1/sha256 hash"),
        ("Encode / Decode",  encode_decode,       "text or encoded string"),
        ("JWT Decoder",      jwt_decoder,         "eyJ... JWT token"),
        ("IP Converter",     ip_converter,        "IP, integer, or 0x hex"),
    ],
}

# Flat lookup: display_name -> (fn, hint)
FLAT_MODULES: dict = {}
for group_mods in GROUPS.values():
    for name, fn, hint in group_mods:
        FLAT_MODULES[name] = (fn, hint)


class TipTicker(Static):
    tip_index = reactive(0)

    def on_mount(self) -> None:
        self.update_tip()
        self.set_interval(6.0, self.cycle_tip)

    def cycle_tip(self) -> None:
        self.tip_index = (self.tip_index + 1) % len(BUZZWORDS)
        self.update_tip()

    def update_tip(self) -> None:
        self.update(BUZZWORDS[self.tip_index])


class BuzzSINT(App):
    """BuzzSINT — OSINT that actually does something."""

    CSS = """
    Screen {
        background: #0d0d0d;
        color: #e0e0e0;
    }

    Header {
        background: #111111;
        color: #00ff88;
        text-style: bold;
    }

    Footer {
        background: #111111;
        color: #555555;
    }

    #layout {
        layout: horizontal;
        height: 100%;
    }

    #sidebar {
        width: 28;
        height: 100%;
        background: #0f0f0f;
        border-right: solid #1a1a1a;
    }

    #sidebar-title {
        content-align: center middle;
        background: #00ff88;
        color: #000000;
        text-style: bold;
        height: 3;
        width: 100%;
    }

    #module-list {
        background: #0f0f0f;
        height: 1fr;
    }

    ListView > ListItem {
        padding: 0 1;
        color: #666666;
    }

    ListView > ListItem:hover {
        background: #151515;
        color: #cccccc;
    }

    ListView > ListItem.--highlight {
        background: #001a0d;
        color: #00ff88;
        text-style: bold;
    }

    #main-content {
        height: 100%;
        width: 1fr;
        layout: vertical;
    }

    #input-area {
        height: 5;
        padding: 1 2;
        background: #111111;
        border-bottom: solid #1a1a1a;
        layout: horizontal;
    }

    #target-input {
        width: 1fr;
        background: #0a0a0a;
        border: solid #2a2a2a;
        color: #e0e0e0;
    }

    #target-input:focus {
        border: solid #00ff88;
    }

    #run-btn {
        width: 14;
        margin-left: 2;
        background: #00ff88;
        color: #000000;
        text-style: bold;
        border: none;
    }

    #run-btn:hover {
        background: #00dd77;
    }

    #clear-btn {
        width: 10;
        margin-left: 1;
        background: #222222;
        color: #888888;
        border: none;
    }

    #clear-btn:hover {
        background: #333333;
        color: #ffffff;
    }

    #output-log {
        height: 1fr;
        background: #080808;
        color: #bbbbbb;
        border: none;
        padding: 1 2;
    }

    TipTicker {
        dock: bottom;
        height: 3;
        content-align: center middle;
        background: #0a1208;
        border-top: solid #1a2a15;
        color: #558844;
    }
    """

    TITLE = "BuzzSINT // OSINT Framework"
    BINDINGS = [
        ("ctrl+c", "quit", "Quit"),
        ("ctrl+l", "clear_log", "Clear"),
        ("enter", "run_module", "Run"),
    ]

    current_module = reactive(list(FLAT_MODULES.keys())[0])
    is_running = reactive(False)

    def _build_list_items(self):
        """Build sidebar items with group headers mixed in."""
        items = []
        for group_name, mods in GROUPS.items():
            # Group header — not selectable
            items.append(ListItem(Static(f"  {group_name}"), id=f"grp-{group_name}"))
            for name, fn, hint in mods:
                safe_id = "mod-" + name.lower().replace(" ", "-").replace("/", "-")
                items.append(ListItem(Static(f"    {name}"), id=safe_id))
        return items

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal(id="layout"):
            with Vertical(id="sidebar"):
                yield Static("[ BUZZSINT ]", id="sidebar-title")
                yield ListView(*self._build_list_items(), id="module-list")

            with Vertical(id="main-content"):
                with Horizontal(id="input-area"):
                    yield Input(
                        placeholder=f"Target ({FLAT_MODULES[self.current_module][1]})",
                        id="target-input"
                    )
                    yield Button("▶ Run", variant="success", id="run-btn")
                    yield Button("Clear", id="clear-btn")

                yield Log(id="output-log", highlight=True)

        yield TipTicker()
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#output-log", Log)
        total = len(FLAT_MODULES)
        groups = len(GROUPS)
        log.write(
            "  ██████╗ ██╗   ██╗███████╗███████╗███████╗██╗███╗  ██╗████████╗\n"
            "  ██╔══██╗██║   ██║╚════██║╚════██║██╔════╝██║████╗ ██║╚══██╔══╝\n"
            "  ██████╔╝██║   ██║    ██╔╝    ██╔╝███████╗██║██╔██╗██║   ██║   \n"
            "  ██╔══██╗██║   ██║   ██╔╝    ██╔╝ ╚════██║██║██║╚████║   ██║   \n"
            "  ██████╔╝╚██████╔╝   ██║     ██║  ███████║██║██║ ╚███║   ██║   \n"
            "  ╚═════╝  ╚═════╝    ╚═╝     ╚═╝  ╚══════╝╚═╝╚═╝  ╚══╝   ╚═╝  \n\n"
        )
        log.write(f"  {total} modules across {groups} categories. Zero API keys required.\n")
        log.write("  Select a module from the sidebar. Tab to input. Enter to run.\n\n")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if not item_id.startswith("mod-"):
            return  # ignore group headers

        # Find the module name by matching the static text
        static = event.item.query_one(Static)
        name = static.renderable.strip()

        if name in FLAT_MODULES:
            self.current_module = name
            hint = FLAT_MODULES[name][1]
            self.query_one("#target-input", Input).placeholder = f"Target ({hint})"
            self.query_one("#output-log", Log).write(f"[ {name} ] — {hint}\n")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-btn":
            self.action_run_module()
        elif event.button.id == "clear-btn":
            self.action_clear_log()

    def action_run_module(self) -> None:
        if self.is_running:
            self.query_one("#output-log", Log).write("Already running. Chill.\n")
            return
        target = self.query_one("#target-input", Input).value.strip()
        if not target:
            self.query_one("#output-log", Log).write("Error: Target is empty.\n")
            return
        self.execute_module(target)

    def action_clear_log(self) -> None:
        self.query_one("#output-log", Log).clear()

    @work(thread=True)
    def execute_module(self, target: str) -> None:
        self.is_running = True
        log = self.query_one("#output-log", Log)
        fn, hint = FLAT_MODULES[self.current_module]

        self.app.call_from_thread(
            log.write,
            f"Running [{self.current_module}] -> {target}\n"
            f"{'-' * 60}\n"
        )

        try:
            result = fn(target)
        except Exception as e:
            result = f"Module crashed: {type(e).__name__}: {e}"

        self.app.call_from_thread(log.write, f"{result}\n{'-' * 60}\nDone.\n\n")
        self.is_running = False


if __name__ == "__main__":
    app = BuzzSINT()
    app.run()
