# LinkProof Datasets

Public risk dataset bundles for LinkProof.

## Public URLs

- Manifest: `https://raw.githubusercontent.com/Openclaw-Metis/linkproof-datasets/main/manifest.json`
- Dataset: `https://raw.githubusercontent.com/Openclaw-Metis/linkproof-datasets/main/scam-datasets.json`

## Files

- `scam-datasets.json`: LinkProof risk dataset consumed by the mobile apps.
- `manifest.json`: Version, checksum, and dataset URL used by app update checks.
- `scripts/update_manifest.py`: Validates the dataset and regenerates `manifest.json`.

## Update Workflow

1. Edit `scam-datasets.json`.
2. Run:

   ```sh
   python scripts/update_manifest.py
   ```

3. Commit both `scam-datasets.json` and `manifest.json`.
4. Push to `main`.

The validation workflow verifies that the dataset is structurally valid and that `manifest.json` contains the current SHA-256 checksum.
