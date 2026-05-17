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
- `scripts/build_dataset.py`: Fetches official Taiwan government open-data feeds and rebuilds `scam-datasets.json`.
- `scripts/update_manifest.py`: Validates the dataset and regenerates `manifest.json`.

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

1. Rebuild the dataset from official sources:

   ```sh
   python scripts/build_dataset.py
   ```

   The build fails if the generated record count drops more than 20% from the committed dataset, which protects against partial upstream outages. Use `--max-record-drop-ratio` only for an intentional source reset.

2. Regenerate the manifest:

   ```sh
   python scripts/update_manifest.py
   ```

3. Commit `scam-datasets.json`, `manifest.json`, `publications.json`, and `CHANGELOG.md`.
4. Push to `main`.

The scheduled `Refresh public dataset` GitHub Actions workflow runs the same build and manifest commands daily at 02:20 Asia/Taipei and commits only when generated files change. Each changed build prepends a release record to `publications.json` and regenerates `CHANGELOG.md`.

## Manual Validation

Run:

```sh
python -m py_compile scripts/build_dataset.py scripts/update_manifest.py
python scripts/update_manifest.py
python -m json.tool publications.json > /dev/null
git diff --exit-code manifest.json
```

If `manifest.json` changes, commit the updated checksum with the dataset.

The validation workflow verifies that the dataset is structurally valid and that `manifest.json` contains the current SHA-256 checksum.
