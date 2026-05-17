# LinkProof Dataset Sources

LinkProof builds its public risk dataset from Taiwan government open-data sources and selected free commercial-use community threat feeds. The build script normalizes each record into `scam-datasets.json`, deduplicates by domain and path prefix, and keeps the strongest source when multiple sources mention the same domain.

The published dataset uses schema v2: shared source/category/risk metadata is stored once in `sources`, and each domain record references it by `sourceID`. This keeps the public mobile payload small without losing traceability.

## Official Sources

| Source | Dataset page | Raw feed | LinkProof risk level |
| --- | --- | --- | --- |
| 165反詐騙諮詢專線_遭停止解析涉詐網站 | https://data.gov.tw/dataset/176455 | CSV from `opdadm.moi.gov.tw` | `confirmedScam` |
| 數位發展部數位產業署聲請詐騙網域名稱停止解析網址清單 | https://data.gov.tw/dataset/165027 | JSON from `www-api.moda.gov.tw` | `confirmedScam` |
| 165反詐騙諮詢專線_假投資(博弈)網站 | https://data.gov.tw/dataset/160055 | CSV from `opdadm.moi.gov.tw` | `confirmedScam` |

## Community Sources

### PhishTank

- **Source**: https://www.phishtank.com/
- **Feed**: `online-valid.json.bz2`, fetched with a registered application key when available.
- **Data**: Community-curated phishing URLs that PhishTank marks as verified and still online.
- **Update cadence**: Upstream updates hourly; LinkProof refreshes daily.
- **Commercial use**: PhishTank FAQ says API use is allowed for commercial and non-commercial purposes, and the Terms define API data as available for commercial use without charge.
- **Availability note**: PhishTank registration is currently disabled for new users. LinkProof treats this as an optional source; scheduled dataset refreshes skip it when `PHISHTANK_API_KEY` is not configured.
- **LinkProof risk level**: `highRisk`. PhishTank is not a Taiwan government source, so it cannot raise a record to `confirmedScam`.
- **Normalization**: Domain-only for this phase; `pathPrefix` remains empty. Domains pass through the same `normalize_dataset_domain` helper as Taiwan government sources.

## Normalization Rules

- Domains are lowercased, trimmed, and IDN-encoded to ASCII when possible.
- Invalid domains, IP-only hosts, and malformed records are skipped.
- Records are deduplicated by `(domain, pathPrefix)`.
- When duplicate domains exist, LinkProof keeps the record with the stronger risk level, then the higher-priority source, then the newer dataset date.
- `sourceURL` points to the human-readable source page rather than the raw file URL, so the app can show users a traceable source.

## Refresh Command

```sh
python scripts/build_dataset.py
python scripts/update_manifest.py
```

The scheduled GitHub Actions workflow runs the same commands and commits only when the generated dataset or manifest changes.
