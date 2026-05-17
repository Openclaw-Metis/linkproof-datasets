# LinkProof Datasets

Public risk dataset bundles for LinkProof.

## Public URLs

- Manifest: `https://raw.githubusercontent.com/Openclaw-Metis/linkproof-datasets/main/manifest.json`
- Dataset: `https://raw.githubusercontent.com/Openclaw-Metis/linkproof-datasets/main/scam-datasets.json`

## Files

- `scam-datasets.json`: LinkProof risk dataset consumed by the mobile apps.
- `manifest.json`: Version, checksum, and dataset URL used by app update checks.
- `SOURCES.md`: Official source list and normalization rules.
- `scripts/build_dataset.py`: Fetches official Taiwan government open-data feeds and rebuilds `scam-datasets.json`.
- `scripts/update_manifest.py`: Validates the dataset and regenerates `manifest.json`.

## Update Workflow

1. Rebuild the dataset from official sources:

   ```sh
   python scripts/build_dataset.py
   ```

2. Regenerate the manifest:

   ```sh
   python scripts/update_manifest.py
   ```

3. Commit both `scam-datasets.json` and `manifest.json`.
4. Push to `main`.

The scheduled `Refresh public dataset` GitHub Actions workflow runs the same build and manifest commands daily at 02:20 Asia/Taipei and commits only when generated files change.

## Manual Validation

Run:

```sh
python -m py_compile scripts/build_dataset.py scripts/update_manifest.py
python scripts/update_manifest.py
git diff --exit-code manifest.json
```

If `manifest.json` changes, commit the updated checksum with the dataset.

The validation workflow verifies that the dataset is structurally valid and that `manifest.json` contains the current SHA-256 checksum.
