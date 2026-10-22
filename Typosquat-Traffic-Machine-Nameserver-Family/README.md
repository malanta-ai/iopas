# Typosquat Traffic Machine (Nameserver Family)

Indicator list for Malanta's research *Different Brands. The Same Traffic Machine.* (October 2026).

It covers about 115,000 typosquat and expired "front" domains delegated to a family of 11 private nameserver domains, plus the nameserver, parking and threat infrastructure described in the research.

## Files

| File | Contents |
| --- | --- |
| `different-brands-same-traffic-machine-indicators.csv` | 115,122 indicators, snapshot 20 Oct 2026 |

## Format

- **Defanged.** `[.]` replaces the last dot and `hxxps` replaces `https`. Re-fang values before loading them into tools.
- **Header row:** `indicator,indicator_type,role,nameserver_domain,recommended_use,observed,notes`.

| Column | Meaning |
| --- | --- |
| `indicator` | The defanged value |
| `indicator_type` | `domain`, `hostname`, `ipv4`, `cidr`, `url`, `polygon-contract`, `file-path` or `string` |
| `role` | What the indicator does: front domain, nameserver domain, nameserver host or IP, dense parking network, malware or lure host, ad-tech router, behavioural fingerprint |
| `nameserver_domain` | For front domains and nameserver infrastructure, the nameserver domain it uses (label only, e.g. `badgerdns`) |
| `recommended_use` | See below |
| `observed` | Date of the observation (YYYY-MM-DD) |
| `notes` | Context, where useful |

| `recommended_use` | Meaning |
| --- | --- |
| `nameserver-policy` | Front domain. Cover it through nameserver-based DNS policy (RPZ `NSDNAME`) rather than domain by domain. |
| `rpz-nsdname-candidate` | Nameserver domain or host. Candidate for RPZ `NSDNAME` after a log-only assessment. |
| `rpz-nsip-candidate` | Nameserver address. Candidate for RPZ `NSIP` after a log-only assessment. |
| `validate-before-ip-action` | Network or IP at a hosting provider that may also serve other customers. |
| `block` | Confirmed malicious host, file URL or lure redirector. |
| `review` | Routing or destination host seen on the operator's traffic. Validate locally. |
| `categorize` | Commercial ad-tech or affiliate service. Categorize it; do not attribute it to the operator. |
| `hunt` | Host or log artefact (contract, file path, string) for threat hunting. |

## Notes

- **Listed by delegation.** Front domains are listed because they delegate to the nameserver family, not because each was judged individually. Some legitimate domains may be delegated to these nameservers. Review before enforcement.
- **Third-party domains excluded.** These are domains whose DNS reaches the family only through a lapsed third-party nameserver domain, and one business with a mixed delegation.
- **Shared infrastructure not listed.** Two dense networks in shared cloud space and the third-party parking landers are left out.
- **Contact.** For more detail, contact hello@malanta.ai.

## Related public writeup

Malanta research paper: *Different Brands. The Same Traffic Machine.*
