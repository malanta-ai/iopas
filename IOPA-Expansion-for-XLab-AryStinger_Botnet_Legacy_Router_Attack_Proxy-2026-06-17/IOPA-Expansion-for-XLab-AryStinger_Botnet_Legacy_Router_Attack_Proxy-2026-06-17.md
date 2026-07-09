# Malanta - Bring Your Own IOCs Report

- **Report ID:** 06fdc56d-f0dc-4dc2-82fb-5a795cf6b509
- **Generated:** Jun 19, 2026 03:14 UTC
- **Seeds:** 11
- **Malanta Clusters:** 4
- **Malanta IoPAs:** 3759

## 1. Executive Summary

- Malanta enrichment of 11 seed IOCs identified 3,760 cluster-sourced IoPAs across 4 infrastructure clusters, with 3,759 expansion indicators and an evidence graph of 4,954 nodes / 48,433 edges.
- Findings represent pre-attack infrastructure staging: 6 domains classified malicious and 9 suspicious; named malicious-labelled domains include `bo919.com` (p=0.9753), `62db.com`, `94xo.cc`, `b327.com` (p=0.9239), and `62pg.com` (p=0.7764).
- Highest-risk cluster: `39FD3037-85A...` with 6 domains, 1 malicious, and reported risk of 100.0%; largest exposure is `844C15D3-901...` with 3,015 domains and 2 malicious.
- No APT attribution can be made from the provided evidence; confidence in attribution is Low due to absence of actor, TTP, hosting, registrar, or certificate details.
- Overall confidence: Medium-High for infrastructure clustering and IoPA scope; Low for actor attribution and hosting-pattern conclusions because supporting evidence was not provided.

## 2. Seed IOCs

**Report date:** 2026-06-17

| Type | Indicator |
| --- | --- |
| domain | `dybic.ajb8.com` |
| domain | `eixfi.ajb8.com` |
| domain | `hgodpcx.ajb8.com` |
| domain | `hgodpcx.auq8.com` |
| domain | `io.ary2.com` |
| domain | `opi7.com` |
| domain | `sdkv1.dataexplore.cc` |
| domain | `sdkv1.dataexplore.co` |
| domain | `xonice.ahb8.com` |
| domain | `xook.ajb8.com` |
| ip | `107.150.106.14` |

## 3. Expansion Indicators

**232 high-confidence indicator(s) discovered through pivoting on seed IOCs (DNS, WHOIS, hosted domains, infrastructure pivots, clusters, code repositories).**

| # | Seed Indicator | Type | Indicator | Discovery Source | Proximity | Adversarial Resource Linkage | Malanta Indicator of Pre-Attack | Malanta Malicious Classification (beta) | Malanta Classification Date | Lead Time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `opi7.com` | domain | `464zz.com` | opi7.com (seed) → Cluster 844C15D3-901 → 464zz.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 2 | `opi7.com` | domain | `8vn9.com` | opi7.com (seed) → Cluster 844C15D3-901 → 8vn9.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 3 | `opi7.com` | domain | `96iu.com` | opi7.com (seed) → Cluster 844C15D3-901 → 96iu.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 4 | `opi7.com` | domain | `97op.com` | opi7.com (seed) → Cluster 844C15D3-901 → 97op.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 5 | `opi7.com` | domain | `97rk.com` | opi7.com (seed) → Cluster 844C15D3-901 → 97rk.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 6 | `opi7.com` | domain | `d4fz.com` | opi7.com (seed) → Cluster 844C15D3-901 → d4fz.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 7 | `opi7.com` | domain | `jsjixiao.com` | opi7.com (seed) → Cluster 844C15D3-901 → jsjixiao.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | Suspicious | 2026-06-17 | — |
| 8 | `opi7.com` | domain | `p18j.com` | opi7.com (seed) → Cluster 844C15D3-901 → p18j.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 9 | `opi7.com` | domain | `s2rx.com` | opi7.com (seed) → Cluster 844C15D3-901 → s2rx.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 10 | `opi7.com` | domain | `wrg6.com` | opi7.com (seed) → Cluster 844C15D3-901 → wrg6.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 11 | `opi7.com` | domain | `028scgl.com` | opi7.com (seed) → Cluster 844C15D3-901 → 028scgl.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 12 | `opi7.com` | domain | `14al.com` | opi7.com (seed) → Cluster 844C15D3-901 → 14al.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 13 | `opi7.com` | domain | `14ib.com` | opi7.com (seed) → Cluster 844C15D3-901 → 14ib.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 14 | `opi7.com` | domain | `14zm.com` | opi7.com (seed) → Cluster 844C15D3-901 → 14zm.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 15 | `opi7.com` | domain | `15fd.com` | opi7.com (seed) → Cluster 844C15D3-901 → 15fd.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 16 | `opi7.com` | domain | `15il.com` | opi7.com (seed) → Cluster 844C15D3-901 → 15il.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 17 | `opi7.com` | domain | `15vh.com` | opi7.com (seed) → Cluster 844C15D3-901 → 15vh.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 18 | `opi7.com` | domain | `15vw.com` | opi7.com (seed) → Cluster 844C15D3-901 → 15vw.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 19 | `opi7.com` | domain | `171ee.com` | opi7.com (seed) → Cluster 844C15D3-901 → 171ee.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 20 | `opi7.com` | domain | `1886cn.com` | opi7.com (seed) → Cluster 844C15D3-901 → 1886cn.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 21 | `opi7.com` | domain | `19io.com` | opi7.com (seed) → Cluster 844C15D3-901 → 19io.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 22 | `opi7.com` | domain | `20ln.com` | opi7.com (seed) → Cluster 844C15D3-901 → 20ln.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 23 | `opi7.com` | domain | `20oj.com` | opi7.com (seed) → Cluster 844C15D3-901 → 20oj.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 24 | `opi7.com` | domain | `20ov.com` | opi7.com (seed) → Cluster 844C15D3-901 → 20ov.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 25 | `opi7.com` | domain | `26oq.com` | opi7.com (seed) → Cluster 844C15D3-901 → 26oq.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 26 | `opi7.com` | domain | `27ig.com` | opi7.com (seed) → Cluster 844C15D3-901 → 27ig.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 27 | `opi7.com` | domain | `27rw.com` | opi7.com (seed) → Cluster 844C15D3-901 → 27rw.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 28 | `opi7.com` | domain | `292aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 292aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 29 | `opi7.com` | domain | `29lq.com` | opi7.com (seed) → Cluster 844C15D3-901 → 29lq.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 30 | `opi7.com` | domain | `29lr.com` | opi7.com (seed) → Cluster 844C15D3-901 → 29lr.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 31 | `opi7.com` | domain | `354aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 354aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 32 | `opi7.com` | domain | `367aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 367aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 33 | `opi7.com` | domain | `374aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 374aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 34 | `opi7.com` | domain | `384aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 384aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 35 | `opi7.com` | domain | `38ay.com` | opi7.com (seed) → Cluster 844C15D3-901 → 38ay.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 36 | `opi7.com` | domain | `53bu.com` | opi7.com (seed) → Cluster 844C15D3-901 → 53bu.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 37 | `opi7.com` | domain | `53nd.com` | opi7.com (seed) → Cluster 844C15D3-901 → 53nd.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 38 | `opi7.com` | domain | `53wn.com` | opi7.com (seed) → Cluster 844C15D3-901 → 53wn.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 39 | `opi7.com` | domain | `59nu.com` | opi7.com (seed) → Cluster 844C15D3-901 → 59nu.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 40 | `opi7.com` | domain | `62bu.com` | opi7.com (seed) → Cluster 844C15D3-901 → 62bu.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 41 | `opi7.com` | domain | `62db.com` | opi7.com (seed) → Cluster 844C15D3-901 → 62db.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | Malicious | 2026-06-09 | +7d |
| 42 | `opi7.com` | domain | `62ev.com` | opi7.com (seed) → Cluster 844C15D3-901 → 62ev.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 43 | `opi7.com` | domain | `62pg.com` | opi7.com (seed) → Cluster 844C15D3-901 → 62pg.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | Malicious | 2026-06-09 | +7d |
| 44 | `opi7.com` | domain | `62pi.com` | opi7.com (seed) → Cluster 844C15D3-901 → 62pi.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 45 | `opi7.com` | domain | `62zv.com` | opi7.com (seed) → Cluster 844C15D3-901 → 62zv.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 46 | `opi7.com` | domain | `747ee.com` | opi7.com (seed) → Cluster 844C15D3-901 → 747ee.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 47 | `opi7.com` | domain | `749bb.com` | opi7.com (seed) → Cluster 844C15D3-901 → 749bb.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 48 | `opi7.com` | domain | `752bb.com` | opi7.com (seed) → Cluster 844C15D3-901 → 752bb.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 49 | `opi7.com` | domain | `82xa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 82xa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 50 | `opi7.com` | domain | `83vi.com` | opi7.com (seed) → Cluster 844C15D3-901 → 83vi.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 51 | `opi7.com` | domain | `83zu.com` | opi7.com (seed) → Cluster 844C15D3-901 → 83zu.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | Suspicious | 2026-06-17 | — |
| 52 | `opi7.com` | domain | `871aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 871aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 53 | `opi7.com` | domain | `87yr.com` | opi7.com (seed) → Cluster 844C15D3-901 → 87yr.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 54 | `opi7.com` | domain | `87zi.com` | opi7.com (seed) → Cluster 844C15D3-901 → 87zi.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 55 | `opi7.com` | domain | `896aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 896aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 56 | `opi7.com` | domain | `929aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 929aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 57 | `opi7.com` | domain | `92oj.com` | opi7.com (seed) → Cluster 844C15D3-901 → 92oj.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 58 | `opi7.com` | domain | `93ln.com` | opi7.com (seed) → Cluster 844C15D3-901 → 93ln.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 59 | `opi7.com` | domain | `93om.com` | opi7.com (seed) → Cluster 844C15D3-901 → 93om.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 60 | `opi7.com` | domain | `93oq.com` | opi7.com (seed) → Cluster 844C15D3-901 → 93oq.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 61 | `opi7.com` | domain | `93pe.com` | opi7.com (seed) → Cluster 844C15D3-901 → 93pe.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 62 | `opi7.com` | domain | `93ul.com` | opi7.com (seed) → Cluster 844C15D3-901 → 93ul.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 63 | `opi7.com` | domain | `93vd.com` | opi7.com (seed) → Cluster 844C15D3-901 → 93vd.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 64 | `opi7.com` | domain | `945bb.com` | opi7.com (seed) → Cluster 844C15D3-901 → 945bb.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 65 | `opi7.com` | domain | `94gn.com` | opi7.com (seed) → Cluster 844C15D3-901 → 94gn.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 66 | `opi7.com` | domain | `94nw.com` | opi7.com (seed) → Cluster 844C15D3-901 → 94nw.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 67 | `opi7.com` | domain | `94om.com` | opi7.com (seed) → Cluster 844C15D3-901 → 94om.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | Suspicious | 2026-06-09 | +7d |
| 68 | `opi7.com` | domain | `94rh.com` | opi7.com (seed) → Cluster 844C15D3-901 → 94rh.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 69 | `opi7.com` | domain | `94rp.com` | opi7.com (seed) → Cluster 844C15D3-901 → 94rp.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 70 | `opi7.com` | domain | `94sv.com` | opi7.com (seed) → Cluster 844C15D3-901 → 94sv.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 71 | `opi7.com` | domain | `94ud.com` | opi7.com (seed) → Cluster 844C15D3-901 → 94ud.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 72 | `opi7.com` | domain | `94xa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 94xa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-04 | — |
| 73 | `opi7.com` | domain | `94xe.com` | opi7.com (seed) → Cluster 844C15D3-901 → 94xe.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-04 | — |
| 74 | `opi7.com` | domain | `952bb.com` | opi7.com (seed) → Cluster 844C15D3-901 → 952bb.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 75 | `opi7.com` | domain | `954aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 954aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 76 | `opi7.com` | domain | `959aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 959aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 77 | `opi7.com` | domain | `95xv.com` | opi7.com (seed) → Cluster 844C15D3-901 → 95xv.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 78 | `opi7.com` | domain | `967bb.com` | opi7.com (seed) → Cluster 844C15D3-901 → 967bb.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 79 | `opi7.com` | domain | `968aa.com` | opi7.com (seed) → Cluster 844C15D3-901 → 968aa.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 80 | `opi7.com` | domain | `96ki.com` | opi7.com (seed) → Cluster 844C15D3-901 → 96ki.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 81 | `opi7.com` | domain | `96kp.com` | opi7.com (seed) → Cluster 844C15D3-901 → 96kp.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 82 | `opi7.com` | domain | `96ob.com` | opi7.com (seed) → Cluster 844C15D3-901 → 96ob.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 83 | `opi7.com` | domain | `96qg.com` | opi7.com (seed) → Cluster 844C15D3-901 → 96qg.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 84 | `opi7.com` | domain | `96qx.com` | opi7.com (seed) → Cluster 844C15D3-901 → 96qx.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 85 | `opi7.com` | domain | `96rw.com` | opi7.com (seed) → Cluster 844C15D3-901 → 96rw.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-04 | — |
| 86 | `opi7.com` | domain | `96ry.com` | opi7.com (seed) → Cluster 844C15D3-901 → 96ry.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 87 | `opi7.com` | domain | `96xe.com` | opi7.com (seed) → Cluster 844C15D3-901 → 96xe.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 88 | `opi7.com` | domain | `97vd.com` | opi7.com (seed) → Cluster 844C15D3-901 → 97vd.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 89 | `opi7.com` | domain | `afumm.com` | opi7.com (seed) → Cluster 844C15D3-901 → afumm.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 90 | `opi7.com` | email | `alexsimon20121222@gmail.com` | opi7.com (seed) → alexsimon20121222@gmail.com (WHOIS) | VERY CLOSE · 1 hop | Cluster ID: 39FD3037-85AC-C759-0323-73D263120AA4 | Yes | — | — | — |
| 91 | `opi7.com` | domain | `bestclothingdirect.com` | opi7.com (seed) → Cluster 844C15D3-901 → bestclothingdirect.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 92 | `opi7.com` | domain | `exeproblems.com` | opi7.com (seed) → Cluster 844C15D3-901 → exeproblems.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 93 | `opi7.com` | domain | `hdpepvc.com` | opi7.com (seed) → Cluster 844C15D3-901 → hdpepvc.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 94 | `opi7.com` | domain | `huaqiaoai.com` | opi7.com (seed) → Cluster 844C15D3-901 → huaqiaoai.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 95 | `opi7.com` | domain | `huayu65.com` | opi7.com (seed) → Cluster 844C15D3-901 → huayu65.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 96 | `opi7.com` | domain | `hxplywood.com` | opi7.com (seed) → Cluster 844C15D3-901 → hxplywood.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 97 | `opi7.com` | domain | `ks-jcw.com` | opi7.com (seed) → Cluster 844C15D3-901 → ks-jcw.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 98 | `opi7.com` | domain | `pmkuangyi.com` | opi7.com (seed) → Cluster 844C15D3-901 → pmkuangyi.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 99 | `opi7.com` | domain | `soshebei.com` | opi7.com (seed) → Cluster 844C15D3-901 → soshebei.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | Suspicious | 2026-06-17 | — |
| 100 | `opi7.com` | domain | `suzhou-lg.com` | opi7.com (seed) → Cluster 844C15D3-901 → suzhou-lg.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 101 | `opi7.com` | domain | `yx601.com` | opi7.com (seed) → Cluster 844C15D3-901 → yx601.com | VERY CLOSE · 1 hop | Cluster ID: 844C15D3-9018-D766-2DA5-49DE0ED8A71E | Yes | — | 2026-06-09 | — |
| 102 | `dybic.ajb8.com` | domain | `033077.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 033077.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 103 | `xonice.ahb8.com` | domain | `06gu.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 06gu.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 104 | `xonice.ahb8.com` | domain | `108087.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 108087.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 105 | `dybic.ajb8.com` | domain | `122333.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 122333.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 106 | `dybic.ajb8.com` | domain | `12bet1.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 12bet1.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 107 | `dybic.ajb8.com` | domain | `136883.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 136883.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 108 | `xonice.ahb8.com` | email | `1597071@qq.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 1597071@qq.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 109 | `dybic.ajb8.com` | domain | `188hgame.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 188hgame.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 110 | `dybic.ajb8.com` | domain | `199008.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 199008.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 111 | `dybic.ajb8.com` | domain | `5185588.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 5185588.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 112 | `dybic.ajb8.com` | domain | `51xuefeng.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 51xuefeng.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 113 | `dybic.ajb8.com` | domain | `56767.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 56767.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 114 | `xonice.ahb8.com` | domain | `625266.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 625266.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 115 | `dybic.ajb8.com` | domain | `6782288.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 6782288.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 116 | `dybic.ajb8.com` | domain | `717788.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 717788.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 117 | `xonice.ahb8.com` | domain | `830589.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 830589.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 118 | `dybic.ajb8.com` | domain | `966966.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → 966966.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 119 | `xonice.ahb8.com` | domain | `998573.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 998573.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 120 | `xonice.ahb8.com` | domain | `998593.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 998593.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 121 | `xonice.ahb8.com` | domain | `998681.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 998681.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 122 | `xonice.ahb8.com` | domain | `998703.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 998703.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 123 | `xonice.ahb8.com` | domain | `998723.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 998723.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 124 | `xonice.ahb8.com` | domain | `998731.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 998731.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 125 | `xonice.ahb8.com` | domain | `998732.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 998732.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 126 | `xonice.ahb8.com` | domain | `998921.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → 998921.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 127 | `dybic.ajb8.com` | domain | `abk8.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → abk8.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 128 | `xonice.ahb8.com` | domain | `aby8.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → aby8.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 129 | `xonice.ahb8.com` | domain | `acq8.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → acq8.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 130 | `xonice.ahb8.com` | domain | `ahb8.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → ahb8.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 131 | `dybic.ajb8.com` | domain | `ahd8.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → ahd8.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 132 | `dybic.ajb8.com` | domain | `akj8.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → akj8.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 133 | `dybic.ajb8.com` | domain | `amvn8.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → amvn8.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 134 | `dybic.ajb8.com` | domain | `amxhtdyl.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → amxhtdyl.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 135 | `dybic.ajb8.com` | domain | `amyh9.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → amyh9.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 136 | `xonice.ahb8.com` | domain | `angden.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → angden.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 137 | `dybic.ajb8.com` | domain | `aox8.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → aox8.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 138 | `dybic.ajb8.com` | domain | `apu8.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → apu8.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 139 | `dybic.ajb8.com` | domain | `apv8.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → apv8.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 140 | `xonice.ahb8.com` | domain | `aqb8.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → aqb8.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 141 | `dybic.ajb8.com` | domain | `auo8.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → auo8.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 142 | `dybic.ajb8.com` | domain | `b037.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b037.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 143 | `dybic.ajb8.com` | domain | `b039.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b039.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 144 | `dybic.ajb8.com` | domain | `b041.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b041.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 145 | `dybic.ajb8.com` | domain | `b054.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b054.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 146 | `dybic.ajb8.com` | domain | `b059.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b059.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | Malicious | 2026-06-09 | +7d |
| 147 | `dybic.ajb8.com` | domain | `b079.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b079.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 148 | `dybic.ajb8.com` | domain | `b084.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b084.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 149 | `dybic.ajb8.com` | domain | `b239.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b239.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 150 | `dybic.ajb8.com` | domain | `b245.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b245.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 151 | `dybic.ajb8.com` | domain | `b261.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b261.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 152 | `dybic.ajb8.com` | domain | `b293.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b293.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 153 | `dybic.ajb8.com` | domain | `b295.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b295.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 154 | `dybic.ajb8.com` | domain | `b327.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b327.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | Malicious | 2026-06-09 | +7d |
| 155 | `dybic.ajb8.com` | domain | `b367.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b367.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 156 | `dybic.ajb8.com` | domain | `b372.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b372.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 157 | `dybic.ajb8.com` | domain | `b391.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b391.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 158 | `dybic.ajb8.com` | domain | `b397.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b397.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 159 | `dybic.ajb8.com` | domain | `b406.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b406.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 160 | `dybic.ajb8.com` | domain | `b408.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b408.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 161 | `dybic.ajb8.com` | domain | `b507.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b507.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 162 | `dybic.ajb8.com` | domain | `b593.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b593.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 163 | `dybic.ajb8.com` | domain | `b602.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b602.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 164 | `dybic.ajb8.com` | domain | `b619.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b619.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 165 | `dybic.ajb8.com` | domain | `b621.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b621.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 166 | `dybic.ajb8.com` | domain | `b625.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b625.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 167 | `dybic.ajb8.com` | domain | `b627.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b627.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 168 | `dybic.ajb8.com` | domain | `b890.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b890.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 169 | `dybic.ajb8.com` | domain | `b897.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → b897.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 170 | `dybic.ajb8.com` | domain | `bl988.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → bl988.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 171 | `dybic.ajb8.com` | domain | `bo919.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → bo919.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | Malicious | 2026-06-09 | +7d |
| 172 | `dybic.ajb8.com` | domain | `bojue188.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → bojue188.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 173 | `dybic.ajb8.com` | domain | `bsj688.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → bsj688.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 174 | `dybic.ajb8.com` | domain | `c036.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → c036.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 175 | `dybic.ajb8.com` | domain | `c406.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → c406.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 176 | `dybic.ajb8.com` | domain | `c427.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → c427.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 177 | `dybic.ajb8.com` | domain | `c472.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → c472.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 178 | `dybic.ajb8.com` | domain | `c492.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → c492.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 179 | `dybic.ajb8.com` | domain | `c495.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → c495.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-04 | — |
| 180 | `dybic.ajb8.com` | domain | `c497.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → c497.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 181 | `xonice.ahb8.com` | domain | `caolve.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → caolve.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 182 | `dybic.ajb8.com` | domain | `cczhentai.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → cczhentai.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 183 | `dybic.ajb8.com` | domain | `ddh5.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → ddh5.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 184 | `dybic.ajb8.com` | domain | `djw18.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → djw18.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 185 | `dybic.ajb8.com` | domain | `dld9.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → dld9.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 186 | `dybic.ajb8.com` | domain | `dsj99.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → dsj99.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 187 | `dybic.ajb8.com` | domain | `dwj9.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → dwj9.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 188 | `dybic.ajb8.com` | domain | `gf788.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → gf788.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 189 | `dybic.ajb8.com` | domain | `hqyl8.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → hqyl8.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 190 | `dybic.ajb8.com` | domain | `j5588.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → j5588.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 191 | `dybic.ajb8.com` | domain | `jj1188.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → jj1188.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 192 | `dybic.ajb8.com` | domain | `jyd77.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → jyd77.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 193 | `dybic.ajb8.com` | domain | `jz068.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → jz068.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 194 | `dybic.ajb8.com` | domain | `jz588.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → jz588.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 195 | `dybic.ajb8.com` | domain | `l0088.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → l0088.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | Suspicious | 2026-06-17 | — |
| 196 | `dybic.ajb8.com` | domain | `l5588.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → l5588.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 197 | `dybic.ajb8.com` | domain | `lgf99.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → lgf99.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 198 | `dybic.ajb8.com` | email | `lzlhlzlhpdk@163.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → lzlhlzlhpdk@163.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | — | — |
| 199 | `dybic.ajb8.com` | domain | `ms088.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → ms088.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 200 | `dybic.ajb8.com` | domain | `n4488.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → n4488.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 201 | `dybic.ajb8.com` | domain | `p4488.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → p4488.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 202 | `dybic.ajb8.com` | domain | `ruifeng1.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → ruifeng1.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 203 | `dybic.ajb8.com` | domain | `shenhua99.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → shenhua99.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 204 | `dybic.ajb8.com` | domain | `sts3.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → sts3.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 205 | `dybic.ajb8.com` | domain | `ths2.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → ths2.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 206 | `dybic.ajb8.com` | domain | `ths55.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → ths55.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 207 | `dybic.ajb8.com` | domain | `tt838.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → tt838.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 208 | `dybic.ajb8.com` | domain | `ttl77.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → ttl77.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 209 | `dybic.ajb8.com` | domain | `wb68.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → wb68.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 210 | `dybic.ajb8.com` | domain | `weilian6.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → weilian6.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 211 | `dybic.ajb8.com` | domain | `wst7.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → wst7.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 212 | `dybic.ajb8.com` | domain | `wx288.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → wx288.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 213 | `dybic.ajb8.com` | domain | `wxfkcy.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → wxfkcy.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 214 | `dybic.ajb8.com` | domain | `xab88.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → xab88.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 215 | `dybic.ajb8.com` | domain | `xg6666.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → xg6666.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 216 | `dybic.ajb8.com` | domain | `xinli1.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → xinli1.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 217 | `dybic.ajb8.com` | domain | `xj75.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → xj75.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 218 | `dybic.ajb8.com` | domain | `xpj288.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → xpj288.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 219 | `dybic.ajb8.com` | domain | `xsd188.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → xsd188.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 220 | `dybic.ajb8.com` | domain | `xyhnm.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → xyhnm.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 221 | `dybic.ajb8.com` | domain | `zaobet.com` | dybic.ajb8.com (seed) → Cluster A98AA41E-A6F → zaobet.com | VERY CLOSE · 1 hop | Cluster ID: A98AA41E-A6FF-A06D-D755-DAE73E6AA4A5 | Yes | — | 2026-06-09 | — |
| 222 | `xonice.ahb8.com` | domain | `zsu8.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → zsu8.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 223 | `xonice.ahb8.com` | domain | `zzu6.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → zzu6.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 224 | `xonice.ahb8.com` | domain | `zzu7.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → zzu7.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 225 | `xonice.ahb8.com` | domain | `zzv6.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → zzv6.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | 2026-06-09 | — |
| 226 | `xonice.ahb8.com` | domain | `zzv7.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → zzv7.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 227 | `xonice.ahb8.com` | domain | `zzv9.com` | xonice.ahb8.com (seed) → Cluster 9B82120B-8ED → zzv9.com | VERY CLOSE · 1 hop | Cluster ID: 9B82120B-8ED6-432B-07E3-1F621EF2EA38 | Yes | — | — | — |
| 228 | `opi7.com` | domain | `94sss.cc` | opi7.com (seed) → alexsimon20121222@gmail.com (WHOIS registrant) → Cluster 39FD3037-85A → 94sss.cc | CLOSE · 2 hops | Cluster ID: 39FD3037-85AC-C759-0323-73D263120AA4 | Yes | Suspicious | 2026-06-09 | +7d |
| 229 | `opi7.com` | domain | `94sxo.com` | opi7.com (seed) → alexsimon20121222@gmail.com (WHOIS registrant) → Cluster 39FD3037-85A → 94sxo.com | CLOSE · 2 hops | Cluster ID: 39FD3037-85AC-C759-0323-73D263120AA4 | Yes | Suspicious | 2026-06-09 | +7d |
| 230 | `opi7.com` | domain | `94xo.cc` | opi7.com (seed) → alexsimon20121222@gmail.com (WHOIS registrant) → Cluster 39FD3037-85A → 94xo.cc | CLOSE · 2 hops | Cluster ID: 39FD3037-85AC-C759-0323-73D263120AA4 | Yes | Malicious | 2026-06-09 | +7d |
| 231 | `opi7.com` | domain | `94xox.cc` | opi7.com (seed) → alexsimon20121222@gmail.com (WHOIS registrant) → Cluster 39FD3037-85A → 94xox.cc | CLOSE · 2 hops | Cluster ID: 39FD3037-85AC-C759-0323-73D263120AA4 | Yes | Suspicious | 2026-06-09 | +7d |
| 232 | `opi7.com` | domain | `94xxx.cc` | opi7.com (seed) → alexsimon20121222@gmail.com (WHOIS registrant) → Cluster 39FD3037-85A → 94xxx.cc | CLOSE · 2 hops | Cluster ID: 39FD3037-85AC-C759-0323-73D263120AA4 | Yes | Suspicious | 2026-06-09 | +7d |
| *... and 2915 more member(s) (2915 domains) in cluster 844C15D3-901 (0 malicious, 0 suspicious)
 (full list in JSON report)* |
| *... and 613 more member(s) (613 domains) in cluster A98AA41E-A6F (0 malicious, 0 suspicious)
 (full list in JSON report)* |

## 4. MITRE ATT&CK Mapping

**Pre-Attack mapping**

#### Resource Development (TA0042)

| Technique | Name |
| --- | --- |
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains |
