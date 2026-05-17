# LinkProof Dataset Sources

LinkProof builds its public risk dataset from Taiwan government open-data sources. The build script normalizes each official record into `scam-datasets.json`, deduplicates by domain and path prefix, and keeps the strongest official source when multiple sources mention the same domain.

## Official Sources

| Source | Dataset page | Raw feed | LinkProof risk level |
| --- | --- | --- | --- |
| 165反詐騙諮詢專線_遭停止解析涉詐網站 | https://data.gov.tw/dataset/176455 | CSV from `opdadm.moi.gov.tw` | `confirmedScam` |
| 數位發展部數位產業署聲請詐騙網域名稱停止解析網址清單 | https://data.gov.tw/dataset/165027 | JSON from `www-api.moda.gov.tw` | `confirmedScam` |
| 165反詐騙諮詢專線_假投資(博弈)網站 | https://data.gov.tw/dataset/160055 | CSV from `opdadm.moi.gov.tw` | `confirmedScam` |

## Normalization Rules

- Domains are lowercased, trimmed, and IDN-encoded to ASCII when possible.
- Invalid domains, IP-only hosts, and malformed records are skipped.
- Records are deduplicated by `(domain, pathPrefix)`.
- When duplicate domains exist, LinkProof keeps the record with the stronger risk level, then the higher-priority source, then the newer dataset date.
- `sourceURL` points to the official dataset page rather than the raw file URL, so the app can show users a human-readable government source.

## Refresh Command

```sh
python scripts/build_dataset.py
python scripts/update_manifest.py
```

The scheduled GitHub Actions workflow runs the same commands and commits only when the generated dataset or manifest changes.
