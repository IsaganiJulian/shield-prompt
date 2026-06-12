# ShieldPrompt — Bright Data Access Survival Plan

**Situation:** Bright Data access ends in ~12 days. Goal: extract maximum value
from the API while it lasts, then keep a fully workable detection system once
the key is gone.

## The core idea

Bright Data is only the *intake* side of ShieldPrompt. Detection itself does not
need it. The plan is to **harvest aggressively, freeze the intel into git, and
keep detecting from the frozen snapshot**:

| Capability after access ends | Needs Bright Data? | Needs other keys? |
|------------------------------|--------------------|-------------------|
| Tier 1 built-in signatures   | No                 | No                |
| Tier 1 **harvested** signatures (dynamic) | No    | **No** |
| Tier 2 vector search (frozen snapshot) | No        | OpenAI embed key only |
| Tier 2 LLM re-scoring        | No                 | Anthropic key     |
| Tier 3 behavioral heuristics | No                 | No                |
| Fetching *new* intel         | **Yes**            | —                 |

Only the last row dies with the key. Everything else keeps working off the
snapshot — and the dynamic Tier 1 path needs **no keys whatsoever**.

## What was built for this

- **Persistence loop closed** — every `update_patterns()` cycle now writes the
  pattern store (`./data/patterns/`) and FAISS index (`./data/vector_store/`)
  to disk, and `ThreatIntelligence` auto-loads them on startup.
- **Snapshots** — `export_snapshot()` freezes a portable bundle under
  `./snapshots/<label>/` (`patterns.json` + `index.faiss` + `metadata.pkl` +
  `manifest.json`). `./snapshots` is **committed to git**, so the intel outlives
  the key. Restore with `load_snapshot()`.
- **Dynamic Tier 1 signatures** — `get_dynamic_signatures()` promotes harvested
  high/critical pattern regexes into Tier 1. The router injects them into the
  detector automatically. Pure regex, zero API cost.
- **Offline safety** — `is_live()` reports scraping availability; offline
  `update_patterns()` runs no longer prune/delete the frozen intel.
- **`scripts/harvest.py`** — the CLI you run for the next 12 days.

## The 12-day playbook

### Day 1 — set up continuous harvesting
Put your keys in `.env` (`BRIGHT_DATA_API_KEY`, ideally `OPENAI_API_KEY` so the
vector index gets built too). Then run a harvest loop so intel accumulates and a
fresh snapshot is frozen every cycle:

```bash
# Foreground, hourly, snapshot each cycle:
python scripts/harvest.py --loop 3600 --snapshot --limit 100
```

Or schedule it with cron (survives reboots, no babysitting):

```cron
0 * * * * cd /path/to/Shield-Prompt && .venv/bin/python scripts/harvest.py --once --snapshot >> logs/harvest.log 2>&1
```

Raise `--limit` to pull more patterns per source per cycle while you still can.

### Days 1–12 — accumulate and commit
The pattern store dedupes and merges across cycles, so volume grows over time.
Periodically commit the frozen intel so it is permanently preserved in git:

```bash
git add snapshots/ && git commit -m "intel snapshot $(date +%F)"
```

Check progress anytime:

```bash
python scripts/harvest.py --stats
```

### Day 12 — final freeze
Do a last big harvest and a final snapshot, then commit:

```bash
python scripts/harvest.py --once --snapshot --limit 200
git add snapshots/ && git commit -m "final intel snapshot before access ends"
```

### After access ends — run from the snapshot
On any machine / fresh checkout, restore the latest frozen bundle into the live
store:

```bash
python scripts/harvest.py --restore        # loads snapshots/latest
python scripts/harvest.py --stats          # confirm patterns + dynamic sigs
```

Detection now runs entirely offline. The `DualGateRouter` auto-loads the
persisted store on init and injects the harvested signatures into Tier 1, so the
running firewall keeps using everything you collected — no Bright Data required.

## Maximizing value in the window

- **Run the loop continuously** — more cycles = more unique patterns merged.
- **Keep an OpenAI key set during harvesting** so the FAISS index is built and
  frozen alongside the patterns; then Tier 2 vector search works post-access
  using only the (cheap) embedding key for the query side.
- **Commit `snapshots/` often** — git history is the durable backup.
- **Tune `--limit` up** — you are trading API credits for permanent intel; spend
  them before they expire.

## Config reference (new keys)

| Key / env | Default | Purpose |
|-----------|---------|---------|
| `snapshot_dir` | `./snapshots` | Where frozen bundles are written |
| `auto_load_on_init` | `true` | Load warm cache from disk on startup |
| `enable_dynamic_signatures` | `true` | Inject harvested regexes into Tier 1 |
| `dynamic_signature_min_severity` | `high` | Min severity promoted to Tier 1 |
