# Threat Source Evaluation

Last evaluated: 2026-05-17

LinkProof only integrates sources whose license and operational model are clear enough for a mobile app that may be published, open sourced, funded, or commercialized later. "Free to download" is not enough; commercial-use terms and redistribution constraints must also be clean.

## Currently Integrated

### 165 Anti-Fraud Stopped-Resolution Scam Websites

- Status: production
- Dataset: https://data.gov.tw/dataset/176455
- License: Government Open Data License, version 1.0
- LinkProof risk level: `confirmedScam`
- Reason: Taiwan government source with clean open-data licensing and direct domain relevance.

### MODA ADI Scam Domain Stop-Resolution List

- Status: production
- Dataset: https://data.gov.tw/dataset/165027
- License: Government Open Data License, version 1.0
- LinkProof risk level: `confirmedScam`
- Reason: Taiwan government source with clean open-data licensing and direct e-commerce scam relevance.

### 165 Anti-Fraud Fake Investment and Gambling Websites

- Status: production
- Dataset: https://data.gov.tw/dataset/160055
- License: Government Open Data License, version 1.0
- LinkProof risk level: `confirmedScam`
- Reason: Taiwan government source with clean open-data licensing. The dataset page notes the newer stopped-resolution dataset should be preferred for broader scope, but this legacy source still adds historical coverage.

### PhishTank

- Status: production, using public dump with optional keyed URL
- Source: https://www.phishtank.com/
- Feed: https://data.phishtank.com/data/online-valid.json.bz2, with https://data.phishtank.com/data/online-valid.csv.gz as the public fallback when the JSON dump is rate-limited.
- Developer docs: https://dev.phishtank.com/developer_info.php
- Terms: https://dev.phishtank.com/faq.php
- License posture: PhishTank FAQ says API use is allowed for commercial and non-commercial purposes.
- LinkProof risk level: `highRisk`
- Acquisition strategy:
  - With `PHISHTANK_API_KEY`: use keyed `online-valid.json.bz2` for higher rate-limit headroom.
  - Without key: use the public `online-valid.json.bz2` dump; fall back to public `online-valid.csv.gz` if the JSON dump is rate-limited.
- Granularity: URL. LinkProof preserves a short path prefix instead of converting PhishTank URLs into whole-domain matches, because shared platforms can host both legitimate and phishing pages.
- Build behavior: if PhishTank fetch fails, scheduled refresh logs a warning and reuses the last cached PhishTank source file only when the cache passes the known-legitimate-domain guard. If the cache is unsafe or unavailable, it still publishes government-sourced records and skips PhishTank for that bundle.
- Re-evaluate triggers:
  - PhishTank closes public dump access.
  - PhishTank registration reopens, allowing LinkProof to obtain an application key.
  - Daily dump consistently produces fewer than 1,000 normalized records.
  - A shared-platform false positive appears in dogfooding or App Store review.

## Evaluated and Declined

### OpenPhish Community Feed

- Status: declined
- Source: https://openphish.com/phishing_feeds.html
- Terms: https://openphish.com/terms.html
- Reason: OpenPhish Terms say the service is for personal use and commercial purposes require prior written consent. This is not clean enough for LinkProof production use.
- Re-evaluate: only if OpenPhish grants written permission or changes the Community Feed terms.

### URLhaus Community API / Public Downloads

- Status: declined for production; spike only
- Source: https://urlhaus.abuse.ch/
- Community API docs: https://urlhaus.abuse.ch/api/
- Commercial API page: https://www.spamhaus.com/data-access/abusech-api/
- Reason: URLhaus focuses on malware-distribution URLs, not phishing/scam URLs. The Community API is free under fair use, but the docs say commercial or for-profit needs may require the enhanced commercial API. This is not clean enough to ship as a default production source for a possibly commercial app.
- Spike policy: a local overlap spike is allowed for data-quality evaluation only. It must not write `scam-datasets.json`, must not run in GitHub Actions refresh, and must not become a production source without a licensing decision.
- Re-evaluate: if LinkProof commits to a non-commercial/public-interest model, or if abuse.ch/Spamhaus confirms written commercial-use terms acceptable for LinkProof.

## Under Investigation

These candidates should be investigated before any future integration:

- data.gov.tw search for `詐騙`, `警示`, `停止解析`, `投資警示`, `不當廣告`.
- 165 weekly risk pages that are not yet exposed as structured open data.
- Financial or investment warning lists from FSC or exchanges, only if records include actionable URLs/domains and clean open-data terms.
- Local government or regulator advertisement-violation datasets, only if URL/domain fields are present and the risk semantics fit LinkProof.

## Decision Rules

- Taiwan government open-data sources can raise risk to `confirmedScam`.
- Non-government OSINT sources are capped at `highRisk`.
- Sources with unclear commercial-use rights must stay out of production.
- Spike scripts are acceptable only when they are manual, test-covered, and excluded from scheduled publication workflows.
- Every new source needs an entry in this file before production integration.
