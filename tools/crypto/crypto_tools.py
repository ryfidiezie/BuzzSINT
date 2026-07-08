import requests

def bitcoin_lookup(address: str) -> str:
    """
    Look up a Bitcoin address on the blockchain.
    blockchain.info API — free, no key.
    Shows balance, total received/sent, transaction count.
    Useful for tracking payments, ransomware wallets, fraud.
    """
    if not address:
        return "Need a Bitcoin address."

    address = address.strip()
    lines = [f"[BITCOIN LOOKUP] {address}\n"]

    url = f"https://blockchain.info/rawaddr/{address}?limit=10"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 400:
            return f"[ERROR] Invalid Bitcoin address format: {address}"
        if resp.status_code == 404:
            return f"[ERROR] Address not found or has never transacted."
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return f"[ERROR] {e}"

    satoshi = 100_000_000  # 1 BTC = 100M satoshi

    balance = data.get("final_balance", 0) / satoshi
    received = data.get("total_received", 0) / satoshi
    sent = data.get("total_sent", 0) / satoshi
    n_tx = data.get("n_tx", 0)

    lines += [
        f"  Balance        : {balance:.8f} BTC",
        f"  Total Received : {received:.8f} BTC",
        f"  Total Sent     : {sent:.8f} BTC",
        f"  Transactions   : {n_tx:,}",
        "",
    ]

    if balance > 0:
        lines.append(f"  ⚠ Active wallet — has funds")

    txs = data.get("txs", [])
    if txs:
        lines.append(f"  Last {len(txs)} transactions:")
        for tx in txs[:10]:
            tx_hash = tx.get("hash", "N/A")[:20] + "..."
            tx_time = tx.get("time", 0)
            import datetime
            tx_date = datetime.datetime.utcfromtimestamp(tx_time).strftime("%Y-%m-%d") if tx_time else "?"

            # Net value for this address
            out_val = sum(
                o.get("value", 0) for o in tx.get("out", [])
                if any(inp.get("prev_out", {}).get("addr") == address
                       for inp in tx.get("inputs", []))
            )
            lines.append(f"    [{tx_date}] {tx_hash} — {out_val / satoshi:.6f} BTC")

    lines.append(f"\n  Explorer: https://www.blockchain.com/explorer/addresses/btc/{address}")
    return "\n".join(lines)


def eth_lookup(address: str) -> str:
    """
    Look up an Ethereum address via Etherscan API.
    Free tier, no API key needed for basic balance queries.
    Shows ETH balance and recent transactions.
    """
    if not address:
        return "Need an Ethereum address (0x...)."

    address = address.strip()
    if not address.startswith("0x") or len(address) != 42:
        return f"[ERROR] Doesn't look like a valid ETH address: {address}"

    lines = [f"[ETH LOOKUP] {address}\n"]

    # Balance via etherscan (no API key for basic)
    balance_url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey=YourApiKeyToken"
    txlist_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=desc&apikey=YourApiKeyToken"

    try:
        balance_resp = requests.get(balance_url, timeout=15)
        balance_data = balance_resp.json()
        if balance_data.get("status") == "1":
            wei = int(balance_data.get("result", 0))
            eth = wei / 1e18
            lines.append(f"  Balance   : {eth:.6f} ETH")
        else:
            lines.append(f"  Balance   : API key required for Etherscan — use free key at etherscan.io/apis")

        tx_resp = requests.get(txlist_url, timeout=15)
        tx_data = tx_resp.json()
        if tx_data.get("status") == "1":
            txs = tx_data.get("result", [])
            lines.append(f"  Transactions: {len(txs)} (recent)")
            for tx in txs[:10]:
                import datetime
                ts = int(tx.get("timeStamp", 0))
                date = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
                val = int(tx.get("value", 0)) / 1e18
                frm = tx.get("from", "?")[:12] + "..."
                to = tx.get("to", "?")[:12] + "..."
                lines.append(f"    [{date}] {frm} → {to}  {val:.4f} ETH")
        else:
            lines.append("  TX History: Free API key from etherscan.io/apis needed")

    except Exception as e:
        lines.append(f"  Error: {e}")

    lines.append(f"\n  Explorer: https://etherscan.io/address/{address}")
    lines.append(f"  Blockscan: https://blockscan.com/address/{address}")
    return "\n".join(lines)


def onion_extractor(text_or_url: str) -> str:
    """
    Extract .onion links from text, a URL, or a paste.
    Useful for darkweb research, threat intel, and mapping Tor infrastructure.
    """
    import re

    if not text_or_url:
        return "Need text or a URL to extract .onion links from."

    lines = [f"[ONION EXTRACTOR]\n"]

    content = text_or_url
    if text_or_url.startswith(("http://", "https://")):
        try:
            resp = requests.get(
                text_or_url,
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True
            )
            content = resp.text
            lines[0] = f"[ONION EXTRACTOR] {resp.url}\n"
        except Exception as e:
            return f"[ERROR] {e}"

    # v2 (16 char) and v3 (56 char) onion addresses
    onion_pattern = re.compile(
        r'\b([a-z2-7]{16}\.onion|[a-z2-7]{56}\.onion)\b',
        re.IGNORECASE
    )
    matches = set(m.lower() for m in onion_pattern.findall(content))

    if not matches:
        lines.append("  No .onion addresses found.")
        return "\n".join(lines)

    v2 = [m for m in sorted(matches) if len(m.split(".")[0]) == 16]
    v3 = [m for m in sorted(matches) if len(m.split(".")[0]) == 56]

    lines.append(f"  Found {len(matches)} .onion address(es):\n")

    if v3:
        lines.append(f"  v3 Addresses ({len(v3)}) [Current standard]:")
        for addr in v3:
            lines.append(f"    http://{addr}")

    if v2:
        lines.append(f"\n  v2 Addresses ({len(v2)}) [Deprecated since Oct 2021]:")
        for addr in v2:
            lines.append(f"    http://{addr}")

    lines.append("\n  Access via Tor Browser or torsocks.")
    return "\n".join(lines)
