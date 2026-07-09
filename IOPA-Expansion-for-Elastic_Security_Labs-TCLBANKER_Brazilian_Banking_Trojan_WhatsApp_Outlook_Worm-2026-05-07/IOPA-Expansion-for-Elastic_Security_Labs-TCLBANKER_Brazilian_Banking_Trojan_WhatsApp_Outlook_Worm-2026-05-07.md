# Malanta - Bring Your Own IOCs Report

- **Report ID:** 0186b87e-e458-4fe1-b5aa-c0deeab80b71
- **Generated:** May 07, 2026 03:18 UTC
- **Seeds:** 4
- **Malanta IoPAs:** 3

## 1. Executive Summary

- Malanta enrichment covered 4 seeds: `arquivos-omie.com`, `campanha1-api.ef971a42.workers.dev`, `documents.ef971a42.workers.dev`, and `mxtestacionamentos.com`.
- Scope remained limited: 3 expansion indicators, 12 evidence-graph nodes, 10 edges, and 0 cluster-sourced IoPAs.
- No indicators were classified as malicious or suspicious: 0 malicious, 0 suspicious.
- APT attribution was reported to Turla / Russia with 62% confidence from `malanta_api`; assessment confidence: Medium.
- Notable infrastructure pattern: 2 of 4 seeds used `workers.dev` subdomains, indicating Cloudflare Workers-style staging infrastructure in the seed set.
- Overall confidence: Low-to-Medium. Attribution exists, but absence of cluster-sourced IoPAs and malicious/suspicious classifications limits the strength of the pre-attack infrastructure assessment.

## 2. Seed IOCs

**Report date:** 2026-05-07

| Type | Indicator |
| --- | --- |
| domain | `campanha1-api.ef971a42.workers.dev` |
| domain | `documents.ef971a42.workers.dev` |
| domain | `arquivos-omie.com` |
| domain | `mxtestacionamentos.com` |

## 3. Expansion Indicators

**3 high-confidence indicator(s) discovered through pivoting on seed IOCs (DNS, WHOIS, hosted domains, infrastructure pivots, clusters, code repositories).**

| # | Seed Indicator | Type | Indicator | Discovery Source | Proximity | Adversarial Resource Linkage | Malanta Indicator of Pre-Attack | Malanta Malicious Classification (beta) | Malanta Classification Date | Lead Time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `campanha1-api.ef971a42.workers.dev` | domain | `campanha1-api.ef971a42.workers.dev` | Seed IOC | DIRECT |  | Yes | Malicious | 2025-12-02 | +155d |
| 2 | `documents.ef971a42.workers.dev` | domain | `documents.ef971a42.workers.dev` | Seed IOC | DIRECT |  | Yes | Malicious | 2025-12-02 | +155d |
| 3 | `mxtestacionamentos.com` | ip | `191.96.224.96` | mxtestacionamentos.com (seed) → 191.96.224.96 (hosted IP) | CLOSE · 1 hop |  | Yes | — | — | — |

## 4. APT Attribution (beta)

#### turla (Russia)

**Aliases:** Turla, Snake, Venomous Bear, Waterbug, Uroburos

Turla is a Russia-linked espionage group known for long-running operations against governments, diplomatic entities, and strategic organizations. This attribution is based only on the provided Malanta match.

**Confidence:**
62.15%
 (source: malanta_api, 1 records)

**Indicators:**

`workers.dev`
Seed

**Known TTPs:** 
Watering-hole and spearphishing operations
Use of compromised or staged infrastructure
Custom backdoors including Snake/Uroburos
Stealthy command-and-control and proxy chaining

**Rationale:** 
workers.dev — Malanta Threat-Intelligence Database matched this seed indicator directly to turla.
campanha1-api.ef971a42.workers.dev — seed falls under the matched workers.dev indicator in the Malanta turla record.
documents.ef971a42.workers.dev — seed falls under the matched workers.dev indicator in the Malanta turla record.
arquivos-omie.com — no provided Malanta turla match; not used for attribution.
mxtestacionamentos.com — no provided Malanta turla match; not used for attribution.

## 5. MITRE ATT&CK Mapping

**Pre-Attack mapping**

#### Resource Development (TA0042)

| Technique | Name |
| --- | --- |
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains |
| [T1583.007](https://attack.mitre.org/techniques/T1583/007/) | Acquire Infrastructure: Serverless |
