# ShieldPrompt — Threat Intelligence

Threat patterns power Tier 2 semantic search and the keyless Tier 1 dynamic
signatures. There is **no live scraping** — patterns come from a static dataset
file or the built-in mock seed, flow through `ingest → vector-sync → persist`,
and can be frozen into portable, git-committed snapshots.

## Where patterns come from

| Source | How | When to use |
|--------|-----|-------------|
| Built-in mock seed | `--mock` / `USE_MOCK_PATTERNS=true` | Dev, CI, smoke tests |
| Static dataset file | `--dataset path.json` / `DATASET_PATH=...` | A purchased/curated pattern set |
| Snapshot bundle | `--restore` | Reload a previously frozen set |

## Detection capability (all offline)

| Capability | Needs a key? |
|------------|--------------|
| Tier 1 built-in signatures | No |
| Tier 1 **dynamic** signatures (from ingested patterns) | **No** |
| Tier 2 vector search | OpenAI embedding key only |
| Tier 2 LLM re-scoring | Anthropic key |
| Tier 3 behavioral heuristics | No |

## The CLI — `scripts/intel.py`

```bash
# Seed mock patterns and freeze a snapshot:
python scripts/intel.py --mock --snapshot

# Ingest a purchased/curated dataset, then snapshot:
python scripts/intel.py --dataset data/my_patterns.json --snapshot

# Inspect the current store:
python scripts/intel.py --stats

# Restore the latest frozen snapshot into the live store:
python scripts/intel.py --restore
```

## Dataset schema

A dataset is a JSON **list** of records, or a **dict** keyed by `pattern_id`.
Each record:

```json
{
  "pattern_id": "ds_0001",
  "description": "Direct instruction override",
  "pattern_regex": "(?i)ignore\\s+(all\\s+)?previous\\s+instructions",
  "threat_type": "injection",
  "severity": "high",
  "source": "dataset",
  "references": ["https://example.com/advisory"],
  "first_seen": "2026-06-01T00:00:00",
  "last_updated": "2026-06-01T00:00:00"
}
```

Only `pattern_id` is required; everything else has sensible defaults
(`threat_type=injection`, `severity=medium`, timestamps default to now).
Patterns at/above `DYNAMIC_SIGNATURE_MIN_SEVERITY` (default `high`) with a
specific, compilable regex are promoted into keyless Tier 1 signatures.

## Snapshots

`export_snapshot()` writes `./snapshots/<label>/` with `patterns.json`,
`index.faiss`, `metadata.pkl`, and `manifest.json`, plus a `latest.txt` pointer.
`./snapshots` is committed to git so a frozen intel set is portable across
machines and reproducible in CI. Restore with `load_snapshot()` /
`intel.py --restore`.

## Config reference

| Key / env | Default | Purpose |
|-----------|---------|---------|
| `DATASET_PATH` | (unset) | Static dataset ingested on init |
| `SNAPSHOT_DIR` | `./snapshots` | Where frozen bundles are written |
| `AUTO_LOAD_ON_INIT` | `true` | Load warm cache from disk on startup |
| `USE_MOCK_PATTERNS` | `false` | Seed built-in mock patterns |
| `ENABLE_DYNAMIC_SIGNATURES` | `true` | Inject pattern regexes into Tier 1 |
| `DYNAMIC_SIGNATURE_MIN_SEVERITY` | `high` | Min severity promoted to Tier 1 |
