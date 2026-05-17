# LinkProof Datasets

Public risk dataset bundles for LinkProof.

## Public URLs

- Manifest: `https://raw.githubusercontent.com/Openclaw-Metis/linkproof-datasets/main/manifest.json`
- Dataset: `https://raw.githubusercontent.com/Openclaw-Metis/linkproof-datasets/main/scam-datasets.json`

## Files

- `scam-datasets.json`: LinkProof risk dataset consumed by the mobile apps.
- `manifest.json`: Version, checksum, and dataset URL used by app update checks.
- `publications.json`: Machine-readable release history for generated dataset bundles.
- `CHANGELOG.md`: Human-readable summary of published dataset changes.
- `SOURCES.md`: Official source list and normalization rules.
- `THREAT_SOURCE_EVALUATION.md`: Licensing and product-fit decisions for current and rejected threat sources.
- `scripts/build_dataset.py`: Fetches public threat feeds and rebuilds `scam-datasets.json`.
- `scripts/fetch_phishtank.py`: Fetches and normalizes the PhishTank online-valid phishing feed.
- `scripts/merge_sources.py`: Applies cross-source dedupe and priority rules.
- `scripts/normalize_domain.py`: Shared dataset-domain and path normalization helper.
- `scripts/spike_urlhaus_overlap.py`: Manual URLhaus overlap spike. It is not used by production refresh.
- `scripts/requirements.txt`: Python dependencies for dataset builds and tests.
- `scripts/update_manifest.py`: Validates the dataset and regenerates `manifest.json`.
- `sources/`: Generated per-source normalized records used for auditability.

## Dataset Format

`scam-datasets.json` uses dataset `schemaVersion` 2. Shared risk metadata is stored once in `sources`; each record references a source by `sourceID`.

```json
{
  "schemaVersion": 2,
  "bundleVersion": "2026.05.17.gov2.9a67d8617efc",
  "fetchedAt": "2026-05-17T00:00:00Z",
  "sources": [
    {
      "id": "src_example",
      "riskLevel": "confirmedScam",
      "sourceName": {
        "zhTW": "官方來源",
        "enUS": "Official source"
      },
      "sourceURL": "https://data.gov.tw/dataset/example",
      "category": {
        "zhTW": "涉詐網域",
        "enUS": "Scam domain"
      }
    }
  ],
  "records": [
    {
      "domain": "example.test",
      "sourceID": "src_example",
      "datasetDate": "2026-05-17"
    }
  ]
}
```

## Update Workflow

1. Install dataset build dependencies:

   ```sh
   python -m pip install -r scripts/requirements.txt
   ```

2. Rebuild the dataset from public sources:

   ```sh
   python scripts/build_dataset.py
   ```

   PhishTank is fetched from its public `online-valid.json.bz2` dump by default, with `online-valid.csv.gz` as a public fallback when the JSON dump is rate-limited. If `PHISHTANK_API_KEY` exists in GitHub Secrets, the scheduled build uses the keyed URL for higher rate-limit headroom. If PhishTank is temporarily unavailable, the build logs a warning and reuses the last cached PhishTank source file when available; without a cache, it still publishes the government-sourced dataset. For explicit government-only local validation, run `python scripts/build_dataset.py --skip-phishtank`.

   The build fails if the generated record count drops more than 20% from the committed dataset, which protects against partial upstream outages. The same guard is applied per source once `sourceStats` exists in `publications.json`; use `--allow-source-drop <source-id>` only for an intentional source reset.

3. Regenerate the manifest:

   ```sh
   python scripts/update_manifest.py
   ```

4. Commit `scam-datasets.json`, `manifest.json`, `publications.json`, `CHANGELOG.md`, and changed files in `sources/`.
5. Push to `main`.

The scheduled `Refresh public dataset` GitHub Actions workflow runs the same build and manifest commands daily at 02:20 Asia/Taipei and commits only when generated files change. Each changed build prepends a release record to `publications.json` and regenerates `CHANGELOG.md`.

## Manual Validation

Run:

```sh
python -m pip install -r scripts/requirements.txt
python -m py_compile scripts/build_dataset.py scripts/update_manifest.py scripts/fetch_phishtank.py scripts/merge_sources.py scripts/normalize_domain.py
python -m pytest tests/
python scripts/update_manifest.py
python -m json.tool publications.json > /dev/null
git diff --exit-code manifest.json
```

If `manifest.json` changes, commit the updated checksum with the dataset.

The validation workflow verifies that the dataset is structurally valid and that `manifest.json` contains the current SHA-256 checksum.

## Manual Threat-Source Spikes

URLhaus is intentionally not a production source because its commercial-use terms are not clean enough for LinkProof's possible future monetization path. For a local data-quality spike only, run:

```sh
python scripts/spike_urlhaus_overlap.py --urlhaus-text tests/fixtures/urlhaus_text_sample.txt
```

Live URLhaus evaluation requires an explicit opt-in flag:

```sh
python scripts/spike_urlhaus_overlap.py --fetch-live --sample-size 100
```

Do not wire spike scripts into `.github/workflows/refresh.yml` or `scripts/build_dataset.py` without first updating `THREAT_SOURCE_EVALUATION.md`.
