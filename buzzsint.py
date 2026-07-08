import asyncio
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Button, Input, Log, ListItem, ListView, Label
from textual.reactive import reactive
from textual import work

from tools.dns_lookup import get_dns_records
from tools.whois_lookup import get_whois_info
from tools.header_analyzer import analyze_headers
from tools.subdomain_enum import enumerate_subdomains
from tools.port_scanner import scan_ports
from tools.ip_geo import geolocate_ip
from tools.email_harvester import harvest_emails
from tools.tech_fingerprint import fingerprint_tech
from tools.wayback import wayback_lookup
from tools.ssl_inspector import inspect_ssl
from tools.dork_gen import generate_dorks
from tools.reverse_ip import reverse_ip
from tools.robots_parser import parse_robots
from tools.security_headers import grade_security_headers
from tools.link_extractor import extract_links


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
    "Tip: VPN ≠ anonymity. ISP can still see you're using a VPN.",
    "Tip: HSTS missing? Downgrade attack surface exists.",
    "Tip: Google dorks + site:pastebin.com find leaked API keys.",
    "Tip: robots.txt Disallow paths are a roadmap to the good stuff.",
    "Tip: Shared hosting = one vuln affects every domain on that IP.",
    "Tip: Security headers grade F = someone is not doing their job.",
]

# Module registry: name -> (function, input_hint)
MODULES = {
    "Subdomain Enum":     (enumerate_subdomains,    "domain.com"),
    "DNS Lookup":         (get_dns_records,          "domain.com"),
    "WHOIS Lookup":       (get_whois_info,           "domain.com"),
    "Port Scanner":       (scan_ports,               "domain.com or IP"),
    "IP Geolocation":     (geolocate_ip,             "IP or domain"),
    "Reverse IP":         (reverse_ip,               "IP or domain"),
    "SSL Inspector":      (inspect_ssl,              "domain.com"),
    "Tech Fingerprint":   (fingerprint_tech,         "https://domain.com"),
    "Header Analysis":    (analyze_headers,          "https://domain.com"),
    "Security Headers":   (grade_security_headers,   "https://domain.com"),
    "Email Harvester":    (harvest_emails,           "https://domain.com"),
    "Link Extractor":     (extract_links,            "https://domain.com"),
    "Wayback Machine":    (wayback_lookup,           "domain.com"),
    "Robots.txt":         (parse_robots,             "domain.com"),
    "Dork Generator":     (generate_dorks,           "domain.com"),
}


class TipTicker(Static):
    tip_index = reactive(0)

    def on_mount(self) -> None:
        self.update_tip()
        self.set_interval(6.0, self.cycle_tip)

    def cycle_tip(self) -> None:
        self.tip_index = (self.tip_index + 1) % len(BUZZWORDS)
        self.update_tip()

    def update_tip(self) -> None:
        self.update(f"[bold cyan]{BUZZWORDS[self.tip_index]}[/bold cyan]")


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
        color: #888888;
    }

    #layout {
        layout: horizontal;
        height: 100%;
    }

    #sidebar {
        width: 26;
        height: 100%;
        background: #111111;
        border-right: solid #00ff88;
        padding: 1 0;
    }

    #sidebar-title {
        content-align: center middle;
        background: #00ff88;
        color: #0d0d0d;
        text-style: bold;
        height: 3;
        width: 100%;
        padding: 0 1;
    }

    #module-list {
        background: #111111;
        height: 1fr;
    }

    ListView > ListItem {
        padding: 0 2;
        color: #aaaaaa;
    }

    ListView > ListItem:hover {
        background: #1a2a1a;
        color: #00ff88;
    }

    ListView > ListItem.--highlight {
        background: #003322;
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
        border-bottom: solid #333333;
        layout: horizontal;
    }

    #target-input {
        width: 1fr;
        background: #1a1a1a;
        border: solid #444444;
        color: #e0e0e0;
    }

    #target-input:focus {
        border: solid #00ff88;
    }

    #run-btn {
        width: 16;
        margin-left: 2;
        background: #00ff88;
        color: #0d0d0d;
        text-style: bold;
        border: none;
    }

    #run-btn:hover {
        background: #00cc66;
    }

    #clear-btn {
        width: 12;
        margin-left: 1;
        background: #333333;
        color: #aaaaaa;
        border: none;
    }

    #clear-btn:hover {
        background: #444444;
        color: #ffffff;
    }

    #output-log {
        height: 1fr;
        background: #0d0d0d;
        color: #cccccc;
        border: none;
        padding: 1 2;
    }

    TipTicker {
        dock: bottom;
        height: 3;
        content-align: center middle;
        background: #0a1a0a;
        border-top: solid #003322;
        color: #00ff88;
    }
    """

    TITLE = "BuzzSINT // OSINT Framework"
    BINDINGS = [
        ("ctrl+c", "quit", "Quit"),
        ("ctrl+l", "clear_log", "Clear"),
        ("enter", "run_module", "Run"),
    ]

    current_module = reactive("Subdomain Enum")
    is_running = reactive(False)

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal(id="layout"):
            with Vertical(id="sidebar"):
                yield Static("[ MODULES ]", id="sidebar-title")
                yield ListView(
                    *[ListItem(Static(name), id=f"mod-{i}") for i, name in enumerate(MODULES.keys())],
                    id="module-list"
                )

            with Vertical(id="main-content"):
                with Horizontal(id="input-area"):
                    yield Input(
                        placeholder=f"Target ({MODULES[self.current_module][1]})",
                        id="target-input"
                    )
                    yield Button("▶ Run", variant="success", id="run-btn")
                    yield Button("Clear", id="clear-btn")

                yield Log(id="output-log", highlight=True)  # markup kwarg removed — not supported in 0.76

        yield TipTicker()
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#output-log", Log)
        log.write(
            "██████╗ ██╗   ██╗███████╗███████╗███████╗██╗███╗  ██╗████████╗\n"
            "██╔══██╗██║   ██║╚════██║╚════██║██╔════╝██║████╗ ██║╚══██╔══╝\n"
            "██████╔╝██║   ██║    ██╔╝    ██╔╝███████╗██║██╔██╗██║   ██║   \n"
            "██╔══██╗██║   ██║   ██╔╝    ██╔╝ ╚════██║██║██║╚████║   ██║   \n"
            "██████╔╝╚██████╔╝   ██║     ██║  ███████║██║██║ ╚███║   ██║   \n"
            "╚═════╝  ╚═════╝    ╚═╝     ╚═╝  ╚══════╝╚═╝╚═╝  ╚══╝   ╚═╝  \n\n"
        )
        log.write(f"Select a module from the sidebar. Enter your target. Hit Run.\n")
        log.write(f"Loaded {len(MODULES)} modules. No API keys needed for any of them.\n\n")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        module_names = list(MODULES.keys())
        try:
            idx = int(event.item.id.split("-")[1])
            self.current_module = module_names[idx]
        except (ValueError, IndexError):
            return

        hint = MODULES[self.current_module][1]
        self.query_one("#target-input", Input).placeholder = f"Target ({hint})"

        log = self.query_one("#output-log", Log)
        log.write(f"[ {self.current_module} ] — {hint}\n")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-btn":
            self.action_run_module()
        elif event.button.id == "clear-btn":
            self.action_clear_log()

    def action_run_module(self) -> None:
        if self.is_running:
            self.query_one("#output-log", Log).write("Already running, hold on...\n")
            return
        target = self.query_one("#target-input", Input).value.strip()
        if not target:
            self.query_one("#output-log", Log).write("Error: Target can't be empty.\n")
            return
        self.execute_module(target)

    def action_clear_log(self) -> None:
        self.query_one("#output-log", Log).clear()

    @work(thread=True)
    def execute_module(self, target: str) -> None:
        self.is_running = True
        log = self.query_one("#output-log", Log)
        fn, hint = MODULES[self.current_module]

        self.app.call_from_thread(
            log.write,
            f"Running [{self.current_module}] on -> {target}\n"
            f"{'-' * 60}\n"
        )

        try:
            result = fn(target)
        except Exception as e:
            result = f"Module crashed: {e}"

        self.app.call_from_thread(log.write, f"{result}\n")
        self.app.call_from_thread(
            log.write,
            f"{'-' * 60}\n"
            f"Done.\n\n"
        )
        self.is_running = False


if __name__ == "__main__":
    app = BuzzSINT()
    app.run()
