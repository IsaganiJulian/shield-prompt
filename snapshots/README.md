# Frozen Threat-Intel Snapshots

Each subdirectory is a portable, immutable bundle of harvested Bright Data
intelligence: `patterns.json` (durable, human-readable), `index.faiss` +
`metadata.pkl` (warm Tier 2 vectors), and `manifest.json` (counts + timestamp).

These are committed to git on purpose — they are how harvested intel survives
the loss of Bright Data access. Generate with:

    python scripts/harvest.py --once --snapshot

Restore the latest into a fresh checkout with:

    python scripts/harvest.py --restore
