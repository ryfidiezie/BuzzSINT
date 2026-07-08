import socket
import concurrent.futures
from typing import List, Tuple

# The ports that actually matter — services running here tell a story
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 9300, 27017
]

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP/TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    27017: "MongoDB"
}

INTERESTING = {22, 23, 3389, 5900, 6379, 9200, 27017}  # stuff that raises eyebrows


def _check_port(host: str, port: int, timeout: float = 1.5) -> Tuple[int, bool, str]:
    """Try to connect. Returns (port, is_open, banner_or_empty)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(0.5)
            banner = ""
            try:
                banner = s.recv(256).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
            return port, True, banner
    except Exception:
        return port, False, ""


def scan_ports(target: str, custom_ports: List[int] = None) -> str:
    """
    Threaded port scanner. Resolves hostname, scans top ports concurrently.
    Flags juicy services (Redis, Mongo, ES, RDP, VNC — the stuff that makes
    pentesters do a little dance).
    """
    if not target:
        return "Need a target, chief."

    ports = custom_ports or TOP_PORTS

    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return f"[DNS FAIL] Can't resolve {target} — check spelling or it's dead."

    lines = [f"[PORT SCAN] Target: {target} ({ip})"]
    lines.append(f"Scanning {len(ports)} ports with 50 threads...\n")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_check_port, ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))

    open_ports.sort()

    if not open_ports:
        lines.append("All ports closed / filtered. Nothing to see here.")
        return "\n".join(lines)

    lines.append(f"Found {len(open_ports)} open port(s):\n")
    for port, banner in open_ports:
        svc = PORT_NAMES.get(port, "Unknown")
        flag = " ⚠ INTERESTING" if port in INTERESTING else ""
        line = f"  {port:5d}/tcp  OPEN  [{svc}]{flag}"
        if banner:
            # truncate banner to keep output clean
            line += f"\n         Banner: {banner[:100]!r}"
        lines.append(line)

    return "\n".join(lines)
