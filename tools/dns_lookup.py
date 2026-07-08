import dns.resolver

def get_dns_records(domain: str) -> str:
    """Perform a DNS lookup for A, AAAA, MX, and TXT records."""
    if not domain:
        return "No domain provided."

    records_types = ['A', 'AAAA', 'MX', 'TXT']
    result = []
    
    for record_type in records_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result.append(f"--- {record_type} Records ---")
            for rdata in answers:
                result.append(rdata.to_text())
        except dns.resolver.NoAnswer:
            result.append(f"--- {record_type} Records ---")
            result.append("No answer found.")
        except dns.resolver.NXDOMAIN:
            return f"Domain {domain} does not exist."
        except Exception as e:
            result.append(f"--- {record_type} Records ---")
            result.append(f"Error: {e}")
        result.append("")
    
    return "\n".join(result)
