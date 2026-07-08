import dns.resolver
import dns.query
import dns.zone
import dns.exception

def zone_transfer(domain: str) -> str:
    """
    Attempt a DNS zone transfer (AXFR) against all NS servers for a domain.
    Most properly configured servers reject this. When they don't, you get
    every DNS record in the zone — the full internal map. It's like a
    misconfiguration jackpot that still works on ~5% of domains.
    """
    if not domain:
        return "Need a domain."

    domain = domain.strip().lower()
    lines = [f"[ZONE TRANSFER] Attempting AXFR on {domain}\n"]

    # First, get nameservers
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        nameservers = [str(r.target).rstrip(".") for r in ns_answers]
    except Exception as e:
        return f"[ERROR] Can't resolve NS records for {domain}: {e}"

    lines.append(f"  Nameservers found: {', '.join(nameservers)}\n")

    success = False
    for ns in nameservers:
        lines.append(f"  Trying AXFR against {ns}...")
        try:
            ns_ip = dns.resolver.resolve(ns, "A")[0].to_text()
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            records = []
            for name, node in z.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"    {name}.{domain}  {rdataset.rdtype}  {rdata}")

            lines.append(f"  SUCCESS! Zone transfer worked on {ns}")
            lines.append(f"  {len(records)} records dumped:\n")
            lines.extend(records)
            success = True
        except dns.exception.FormError:
            lines.append(f"    Rejected (REFUSED) — properly secured.")
        except Exception as e:
            lines.append(f"    Failed: {type(e).__name__}: {e}")

    if not success:
        lines.append("\n  All NS servers refused AXFR — this domain is locked down.")

    return "\n".join(lines)
