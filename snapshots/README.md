# Frozen Threat-Intel Snapshots

Each subdirectory is a portable, immutable bundle of the threat-intel store:
`patterns.json` (durable, human-readable), `index.faiss` + `metadata.pkl`
(warm Tier 2 vectors), and `manifest.json` (counts + timestamp).

These are committed to git on purpose — a frozen intel set is then portable
across machines and reproducible in CI. Generate with:

    python scripts/intel.py --mock --snapshot
    # or from a dataset:
    python scripts/intel.py --dataset path/to/patterns.json --snapshot

Restore the latest into a fresh checkout with:

    python scripts/intel.py --restore

See [../docs/INTEL.md](../docs/INTEL.md) for the full threat-intel guide.
