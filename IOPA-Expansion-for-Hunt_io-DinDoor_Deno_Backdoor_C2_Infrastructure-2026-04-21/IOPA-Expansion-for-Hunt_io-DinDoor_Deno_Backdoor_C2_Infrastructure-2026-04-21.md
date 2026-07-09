# Malanta - Bring Your Own IOCs Report

- **Report ID:** 4f0e8797-187
- **Generated:** Apr 26, 2026 07:12 UTC
- **Seeds:** 37
- **Malanta Clusters:** 4
- **Malanta IoPAs:** 34

## 1. Executive Summary

- Malanta enrichment of 37 seed IOCs identified 34 expansion indicators and 8 cluster-sourced IoPAs, indicating staged pre-attack infrastructure rather than only post-compromise artifacts.
- Four domains were classified malicious: `bubuklaysdertolitodas.com` and `geralnewlong.com` at p=1.0; `coinbase.com.lv` and `verification-stokr.io` at p=0.9885. No suspicious-only domains were reported.
- Four clusters each contained 1 domain, 1 malicious label, and 100% risk: `E8120272-B5B...`, `0E03EA2D-75F...`, `59EAED30-B09...`, and `38F86DE0-6FC...`.
- APT attribution is Medium confidence: TEMP.Zagros/Iran and Shuckworm/Russia were both reported by `malanta_api` at 62% confidence.
- Code-repository intelligence found 9 seeds in URLhaus, including `209.99.189.170`, `192.109.200.151`, `85.192.27.152`, `193.233.82.43`, and `45.135.180.200`.
- Overall confidence: High for malicious infrastructure clustering; Medium for actor attribution and hosting-pattern assessment due to limited hosting/ASN detail provided.

## 2. Seed IOCs

Automatically extracted from [https://hunt.io/blog/dindoor-deno-runtime-backdoor-msi-analysis](https://hunt.io/blog/dindoor-deno-runtime-backdoor-msi-analysis)

**Report date:** 2026-04-21

| Type | Indicator |
| --- | --- |
| domain | `annaionovna.com` |
| domain | `justtalken.com` |
| domain | `serialmenot.com` |
| domain | `aeeracaspsl.site` |
| domain | `agilemast3r.duckdns.org` |
| domain | `bandage.healthydefinitetrunk.com` |
| domain | `bitatits.surf` |
| domain | `generalnewlong.com` |
| domain | `grafana.healthydefinitetrunk.com` |
| domain | `hngfbgfbfb.cyou` |
| domain | `ilspaeysoff.site` |
| domain | `ineracaspsl.site` |
| domain | `landmas.info` |
| domain | `myspaeysoff.site` |
| domain | `playerdragonbike.com` |
| domain | `surgery.healthydefinitetrunk.com` |
| domain | `weaplink.com` |
| ip | `138.124.240.76` |
| ip | `138.124.240.77` |
| ip | `140.82.18.48` |
| ip | `146.19.254.84` |
| ip | `178.104.137.180` |
| ip | `178.16.52.191` |
| ip | `185.218.19.117` |
| ip | `192.109.200.151` |
| ip | `193.233.82.43` |
| ip | `193.24.123.25` |
| ip | `194.48.141.192` |
| ip | `199.217.99.189` |
| ip | `199.91.220.142` |
| ip | `199.91.220.216` |
| ip | `2.26.117.169` |
| ip | `2.27.122.16` |
| ip | `209.99.189.170` |
| ip | `45.135.180.200` |
| ip | `45.151.106.88` |
| ip | `85.192.27.152` |

## 3. Expansion Indicators

**15 high-confidence indicator(s) discovered through pivoting on seed IOCs (DNS, WHOIS, hosted domains, infrastructure pivots, clusters, code repositories).
 + 19 low-confidence (see below)**

| # | Seed Indicator | Type | Indicator | Discovery Source | Proximity | Adversarial Resource Linkage | Malanta Indicator of Pre-Attack | Malanta Malicious Classification (beta) | Malanta Classification Date | Lead Time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `annaionovna.com` | domain | `annaionovna.com` | Seed IOC | DIRECT |  | Yes | Malicious | 2026-04-13 | +7d |
| 2 | `justtalken.com` | domain | `justtalken.com` | Seed IOC | DIRECT |  | Yes | Malicious | 2026-04-09 | +11d |
| 3 | `serialmenot.com` | domain | `serialmenot.com` | Seed IOC | DIRECT |  | Yes | Malicious | 2026-03-11 | +40d |
| 4 | `140.82.18.48` | domain | `coinbase.com.lv` | 140.82.18.48 (seed) → coinbase.com.lv (IP reverse) | VERY CLOSE · 1 hop | Cluster ID: 0E03EA2D-75F6-9AD0-04B1-540B309779A0 | Yes | Malicious | 2025-12-26 | +115d |
| 5 | `193.24.123.25` | domain | `aespaeysoff.site` | 193.24.123.25 (seed) → aespaeysoff.site (IP reverse) | VERY CLOSE · 1 hop |  | Yes | — | — | — |
| 6 | `192.109.200.151` | domain | `geralnewlong.com` | 192.109.200.151 (seed) → Cluster 59EAED30-B09 → geralnewlong.com | VERY CLOSE · 1 hop | Cluster ID: 59EAED30-B096-F8E9-7274-E71958CC2F99 | Yes | Malicious | 2026-04-09 | +11d |
| 7 | `193.24.123.25` | domain | `ileracaspsl.site` | 193.24.123.25 (seed) → ileracaspsl.site (IP reverse) | VERY CLOSE · 1 hop |  | Yes | — | — | — |
| 8 | `193.24.123.25` | domain | `inspaeysoff.site` | 193.24.123.25 (seed) → inspaeysoff.site (IP reverse) | VERY CLOSE · 1 hop |  | Yes | — | — | — |
| 9 | `193.24.123.25` | domain | `myeracaspsl.site` | 193.24.123.25 (seed) → myeracaspsl.site (IP reverse) | VERY CLOSE · 1 hop |  | Yes | — | — | — |
| 10 | `178.16.52.191` | ip | `178.16.52.64` | 178.16.52.191 (seed; matched via 178.16.52.64) → SecWiki/linux-kernel-exploits (flagged by urlhaus) → Gandalf-ocinzento/C2-Tracker (pivot via fork_network: Gandalf-ocinzento) → 178.16.52.64 (/24 subnet match) | CLOSE · 1 hop | Found in data/Hookbot IPs.txt (line 4): 94.183.168.33, 192.253.234.63, 156.238.243.16, 178.16.52.64; Cluster ID: 38F86DE0-6FC0-5FD3-E7A2-CC240DDE3C14 | Yes | — | — | — |
| 11 | `193.24.123.25` | ip | `193.24.123.84` | 193.24.123.25 (seed; matched via 193.24.123.84) → pr0xylife/DarkGate (flagged by urlhaus) → MikhailKasimov/validin-phish-feed (pivot via fork_network: MikhailKasimov) → 193.24.123.84 (/24 subnet match) | CLOSE · 1 hop | Found in validin-phish-feed-4.txt (line 81922); Cluster ID: E8120272-B5BF-777E-0509-0A936105BE75 | Yes | — | — | — |
| 12 | `199.217.99.189` | domain | `klikzonewyr.com` | 199.217.99.189 (seed) → klikzonewyr.com (IP reverse) | VERY CLOSE · 1 hop |  | Yes | — | — | — |
| 13 | `45.135.180.200` | domain | `utka.click` | 45.135.180.200 (seed) → utka.click (IP reverse) | VERY CLOSE · 1 hop |  | Yes | — | — | — |
| 14 | `178.16.52.191` | domain | `bubuklaysdertolitodas.com` | 178.16.52.191 (seed) → 178.16.52.64 (code repo) → Cluster 38F86DE0-6FC → bubuklaysdertolitodas.com | CLOSE · 2 hops | Cluster ID: 38F86DE0-6FC0-5FD3-E7A2-CC240DDE3C14 | Yes | Malicious | 2025-10-29 | +173d |
| 15 | `193.24.123.25` | domain | `verification-stokr.io` | 193.24.123.25 (seed) → 193.24.123.84 (code repo) → Cluster E8120272-B5B → verification-stokr.io | CLOSE · 2 hops | Cluster ID: E8120272-B5BF-777E-0509-0A936105BE75 | Yes | Malicious | 2026-01-13 | +97d |

**Low-Confidence Indicators (19) — below relevance threshold**

| # | Seed Indicator | Type | Indicator | Discovery Source | Proximity | Adversarial Resource Linkage | Malanta Indicator of Pre-Attack | Malanta Malicious Classification (beta) | Malanta Classification Date | Lead Time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `146.19.254.84` | ip | `146.19.254.101` | 146.19.254.84 (seed; matched via 146.19.254.101) → VolkanSah/Auto-Proxy-Fetcher (flagged by urlhaus) → infdevv/Composite-Autoproxy (pivot via fork_network: fork:VolkanSah/Auto-Proxy-Fetcher) → 146.19.254.101 (/24 subnet match) | CLOSE · 1 hop | Found in misc_proxies.txt (line 305): socks4://91.223.52.141:5678, socks4://14.232.166.150:5678, http://188.227.196.62:1080, socks5://146.19.254.101:5555, socks4://185.191.165.28:1080, socks4://95.43.244.15:4153, http://103.105.76.65:8080 | Yes | — | — | — |
| 2 | `178.16.52.191` | ip | `178.16.52.53` | 178.16.52.191 (seed; matched via 178.16.52.53) → SecWiki/linux-kernel-exploits (flagged by urlhaus) → Gandalf-ocinzento/C2-Tracker (pivot via fork_network: Gandalf-ocinzento) → 178.16.52.53 (/24 subnet match) | CLOSE · 1 hop | Found in data/Sliver C2 IPs.txt (line 252): 158.220.115.82, 38.143.109.169, 18.158.1.133, 178.16.52.53, 185.209.42.105, 52.52.233.130, 130.94.33.52 | Yes | — | — | — |
| 3 | `178.16.52.191` | ip | `178.16.52.91` | 178.16.52.191 (seed; matched via 178.16.52.91) → SecWiki/linux-kernel-exploits (flagged by urlhaus) → Gandalf-ocinzento/C2-Tracker (pivot via fork_network: Gandalf-ocinzento) → 178.16.52.91 (/24 subnet match) | CLOSE · 1 hop | Found in data/Sliver C2 IPs.txt (line 262): 164.92.136.111, 18.169.87.175, 80.78.18.42, 178.16.52.91, 64.226.101.105, 181.214.100.88, 176.117.68.140 | Yes | — | — | — |
| 4 | `178.16.52.191` | ip | `178.16.52.92` | 178.16.52.191 (seed; matched via 178.16.52.92) → SecWiki/linux-kernel-exploits (flagged by urlhaus) → Gandalf-ocinzento/C2-Tracker (pivot via fork_network: Gandalf-ocinzento) → 178.16.52.92 (/24 subnet match) | CLOSE · 1 hop | Found in data/Sliver C2 IPs.txt (line 428): 107.172.67.68, 101.33.246.201, 182.255.46.159, 178.16.52.92, 35.176.102.236, 13.134.114.209, 145.223.70.112 | Yes | — | — | — |
| 5 | `178.16.52.191` | ip | `178.16.52.93` | 178.16.52.191 (seed; matched via 178.16.52.93) → SecWiki/linux-kernel-exploits (flagged by urlhaus) → Gandalf-ocinzento/C2-Tracker (pivot via fork_network: Gandalf-ocinzento) → 178.16.52.93 (/24 subnet match) | CLOSE · 1 hop | Found in data/Sliver C2 IPs.txt (line 209): 45.140.213.84, 167.172.12.244, 195.20.17.49, 178.16.52.93, 159.195.59.191, 142.171.228.216, 172.237.36.196 | Yes | — | — | — |
| 6 | `178.16.52.191` | ip | `178.16.52.94` | 178.16.52.191 (seed; matched via 178.16.52.94) → SecWiki/linux-kernel-exploits (flagged by urlhaus) → Gandalf-ocinzento/C2-Tracker (pivot via fork_network: Gandalf-ocinzento) → 178.16.52.94 (/24 subnet match) | CLOSE · 1 hop | Found in data/Sliver C2 IPs.txt (line 280): 3.9.62.133, 18.171.16.32, 138.197.224.55, 178.16.52.94, 208.87.128.140, 66.103.201.249, 54.176.133.154 | Yes | — | — | — |
| 7 | `178.16.52.191` | ip | `178.16.52.95` | 178.16.52.191 (seed; matched via 178.16.52.95) → SecWiki/linux-kernel-exploits (flagged by urlhaus) → Gandalf-ocinzento/C2-Tracker (pivot via fork_network: Gandalf-ocinzento) → 178.16.52.95 (/24 subnet match) | CLOSE · 1 hop | Found in data/Sliver C2 IPs.txt (line 77): 164.68.126.4, 161.35.64.250, 64.52.80.159, 178.16.52.95, 207.180.207.252, 47.84.83.56, 93.127.128.88 | Yes | — | — | — |
| 8 | `192.109.200.151` | ip | `192.109.200.0` | 192.109.200.151 (seed; matched via 192.109.200.0) → ReVanced/revanced-bots (flagged by urlhaus) → risjsnx/lmms.io (pivot via fork_network: risjsnx) → 192.109.200.0 (/24 subnet match) | CLOSE · 1 hop | Found in dev/block-aeza.conf (line 129): deny 85.192.26.0/24;, deny 45.142.122.0/24;, deny 193.232.178.0/24;, deny 192.109.200.0/24;, deny 2a0f:cdc6:5030::/44;, deny 193.188.20.0/24;, deny 85.192.28.0/24; | Yes | — | — | — |
| 9 | `192.109.200.151` | ip | `192.109.200.213` | 192.109.200.151 (seed; matched via 192.109.200.213) → xPOURY4/X-Auto-Reply-Assistant (flagged by urlhaus) → Xavier001/IOCs (pivot via fork_network: Xavier001) → 192.109.200.213 (/24 subnet match) | CLOSE · 1 hop | Found in IP-Abused-Level4-original.txt (line 741): 190.181.27.22, 190.242.189.253, 191.5.31.61, 192.109.200.213, 192.109.200.219, 192.155.90.118, 192.155.90.220 | Yes | — | — | — |
| 10 | `192.109.200.151` | ip | `192.109.200.219` | 192.109.200.151 (seed; matched via 192.109.200.219) → xPOURY4/X-Auto-Reply-Assistant (flagged by urlhaus) → Xavier001/IOCs (pivot via fork_network: Xavier001) → 192.109.200.219 (/24 subnet match) | CLOSE · 1 hop | Found in IP-Abused-Level4-original.txt (line 742): 190.242.189.253, 191.5.31.61, 192.109.200.213, 192.109.200.219, 192.155.90.118, 192.155.90.220, 192.241.154.87 | Yes | — | — | — |
| 11 | `192.109.200.151` | ip | `192.109.200.225` | 192.109.200.151 (seed; matched via 192.109.200.225) → xPOURY4/X-Auto-Reply-Assistant (flagged by urlhaus) → Xavier001/IOCs (pivot via fork_network: Xavier001) → 192.109.200.225 (/24 subnet match) | CLOSE · 1 hop | Found in IP-Abused-Level4-original.txt (line 178): 189.50.142.82, 189.217.130.86, 190.124.153.17, 192.109.200.225, 193.32.162.82, 193.32.162.157, 199.45.154.141 | Yes | — | — | — |
| 12 | `192.109.200.151` | ip | `192.109.200.33` | 192.109.200.151 (seed; matched via 192.109.200.33) → pomerium/pomerium (flagged by urlhaus) → pomerium/torbulkexitlist (pivot via owner: pomerium) → 192.109.200.33 (/24 subnet match) | CLOSE · 1 hop | Found in torbulkexitlist.json (line 1524): "id": "192.108.48.150", },, {, "id": "192.109.200.33", },, {, "id": "192.121.44.26" | Yes | — | — | — |
| 13 | `193.233.82.43` | ip | `193.233.82.106` | 193.233.82.43 (seed; matched via 193.233.82.106) → OlivierLaflamme/Cheatsheet-God (flagged by urlhaus) → vpnlate703-star/TikTok-Bot (pivot via fork_network: vpnlate703-star) → 193.233.82.106 (/24 subnet match) | CLOSE · 1 hop | Found in Proxies.txt (line 1678): 181.83.228.224:7071, 139.180.185.83:3128, 14.160.3.77:5678, 193.233.82.106:8085, 89.186.17.82:3737, 131.196.8.1:999, 161.35.139.101:8080 | Yes | — | — | — |
| 14 | `193.24.123.25` | ip | `193.24.123.196` | 193.24.123.25 (seed; matched via 193.24.123.196) → SecWiki/linux-kernel-exploits (flagged by urlhaus) → Gandalf-ocinzento/C2-Tracker (pivot via fork_network: Gandalf-ocinzento) → 193.24.123.196 (/24 subnet match) | CLOSE · 1 hop | Found in data/Sliver C2 IPs.txt (line 417): 80.78.30.33, 143.198.136.6, 52.28.208.13, 193.24.123.196, 182.92.159.149, 45.150.108.43, 103.69.194.85 | Yes | — | — | — |
| 15 | `199.217.99.189` | ip | `199.217.99.123` | 199.217.99.189 (seed; matched via 199.217.99.123) → hakimil/hack-crypto-wallet (flagged by urlhaus) → VolkanSah/Auto-Proxy-Fetcher (pivot via follower: VolkanSah) → 199.217.99.123 (/24 subnet match) | CLOSE · 1 hop | Found in proxies.txt (line 297): 195.211.71.200:1433, 196.1.97.198:80, 198.177.57.197:80, 199.217.99.123:2525, 201.182.204.18:9999, 202.5.36.147:8090, 202.5.37.120:21225 | Yes | — | — | — |
| 16 | `209.99.189.170` | ip | `209.99.189.200` | 209.99.189.170 (seed; matched via 209.99.189.200) → pomerium/pomerium (flagged by urlhaus) → pomerium/torbulkexitlist (pivot via owner: pomerium) → 209.99.189.200 (/24 subnet match) | CLOSE · 1 hop | Found in torbulkexitlist.json (line 2070): "id": "209.141.61.225", },, {, "id": "209.99.189.200", },, {, "id": "212.21.66.6" | Yes | — | — | — |
| 17 | `45.135.180.200` | ip | `45.135.180.207` | 45.135.180.200 (seed; matched via 45.135.180.207) → SecWiki/linux-kernel-exploits (flagged by urlhaus) → Gandalf-ocinzento/C2-Tracker (pivot via fork_network: Gandalf-ocinzento) → 45.135.180.207 (/24 subnet match) | CLOSE · 1 hop | Found in data/Sliver C2 IPs.txt (line 375): 51.83.133.9, 52.58.156.181, 157.245.46.190, 45.135.180.207, 107.150.1.174, 13.135.45.177, 43.134.67.236 | Yes | — | — | — |
| 18 | `85.192.27.152` | ip | `85.192.27.0` | 85.192.27.152 (seed; matched via 85.192.27.0) → ReVanced/revanced-bots (flagged by urlhaus) → risjsnx/lmms.io (pivot via fork_network: risjsnx) → 85.192.27.0 (/24 subnet match) | CLOSE · 1 hop | Found in dev/block-aeza.conf (line 66): deny 85.192.61.0/24;, deny 77.105.167.0/24;, deny 85.192.38.0/24;, deny 85.192.27.0/24;, deny 109.172.95.0/24;, deny 138.124.89.0/24;, deny 2a01:e5c0:f000::/36; | Yes | — | — | — |
| 19 | `weaplink.com` | ip | `193.143.1.59` | weaplink.com (seed) → 193.143.1.59 (hosted IP) | CLOSE · 1 hop |  | Yes | — | — | — |

## 4. APT Attribution (beta)

#### TEMP.Zagros (Iran)

**Aliases:** MuddyWater, Seedworm, Static Kitten, MERCURY, Earth Vetala

TEMP.Zagros is an Iran-linked intrusion set commonly associated with espionage operations against government, telecom, education, and regional organizations. Public reporting often overlaps it with MuddyWater/Seedworm-style activity.

**Confidence:**
62.15%
 (source: malanta_api, 1 records)

**Indicators:**

`serialmenot.com`
Seed

**Known TTPs:** 
Spearphishing with malicious documents and links.
PowerShell backdoors and script-based loaders.
Abuse of legitimate admin and RMM tools.
Web shells and staged C2 infrastructure.
Targeting Middle East and regional government entities.

**Rationale:** 
serialmenot.com — Malanta DB lists this Seed under “Seed indicators linked to this APT”; direct TEMP.Zagros attribution anchor.
aeeracaspsl.site — submitted seed, but no provided evidence directly maps it to TEMP.Zagros; linkage is not independently demonstrated.
178.16.52.191 — repo search matched nearby 178.16.52.53/.91-.95 in Gandalf Sliver C2 lists, but not TEMP.Zagros-specific.
193.24.123.25 — repo search matched 193.24.123.84 in validin-phish-feed and .196 in Sliver C2 lists; no TEMP.Zagros tag shown.
192.109.200.151 — repo search matched 192.109.200.0/24 in risjsnx/lmms.io block-aeza.conf; infrastructure-abuse context only.

#### Shuckworm (Russia)

**Aliases:** Gamaredon, Armageddon, Primitive Bear, ACTINIUM, Trident Ursa

Shuckworm is a Russia-linked espionage group widely associated with operations against Ukrainian government, defense, and critical-sector targets. It is known for rapid infrastructure rotation and phishing-led access operations.

**Confidence:**
62.15%
 (source: malanta_api, 1 records)

**Indicators:**

`140.82.18.48`
Seed

**Associated IPs (1):** `140.82.18.48`

**Known TTPs:** 
Spearphishing with malicious attachments or links
Dynamic DNS and disposable domain infrastructure
PowerShell, VBScript, and batch-based execution
Frequent C2 and payload infrastructure rotation
Credential theft and persistent remote access

**Rationale:** 
`140.82.18.48` is explicitly listed by Malanta as a `Seed` indicator linked to Shuckworm.
Malanta reports exactly one Shuckworm match, with `Associated IPs: 140.82.18.48`, making this the direct attribution anchor.
The provided seed domains do not themselves appear in the Shuckworm match; attribution depends on the discovered/seed IP `140.82.18.48`.
Repository hits for `178.16.52.191`, `193.24.123.25`, `45.135.180.200`, and others show generic C2/proxy context, not direct Shuckworm linkage.

## 5. MITRE ATT&CK Mapping

**Pre-Attack mapping**

#### Resource Development (TA0042)

| Technique | Name |
| --- | --- |
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains |
