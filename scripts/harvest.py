#!/usr/bin/env python3
"""
ShieldPrompt Threat-Intel Harvester
===================================

Maximize and durably preserve Bright Data threat intelligence before access
ends. Every harvest cycle fetches fresh patterns, ingests/prunes them, syncs
embeddings, and persists everything to the warm cache under ./data. The
``--snapshot`` flag additionally freezes a portable, git-committable bundle
under ./snapshots so the harvested intel outlives Bright Data access.

After access is gone, the same intel keeps powering detection:
    • Tier 1 dynamic signatures (harvested regexes) — need NO API keys.
    • Tier 2 vector search — needs only the OpenAI embedding key against the
      already-embedded snapshot (no Bright Data, no re-scraping).

Examples
--------
    # One harvest now, then freeze a snapshot for git:
    python scripts/harvest.py --once --snapshot

    # Harvest every hour for the next 12 days, snapshotting each cycle:
    python scripts/harvest.py --loop 3600 --snapshot

    # Show what's currently stored:
    python scripts/harvest.py --stats

    # Restore the latest frozen snapshot into the live store (offline use):
    python scripts/harvest.py --restore

    # Seed built-in mock patterns when you have no keys (smoke test):
    python scripts/harvest.py --once --mock
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

# Make the project importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from src.core.threat_intel import ThreatIntelligence  # noqa: E402

logger = logging.getLogger("harvest")


def _build_config(args: argparse.Namespace) -> dict:
    return {
        "bright_data_api_key": os.getenv("BRIGHT_DATA_API_KEY"),
        "openai_api_key": os.getenv("OPENAI_API_KEY"),
        "limit_per_source": args.limit,
        "use_mock_patterns": args.mock,
        # Always load whatever we already have so cycles accumulate.
        "auto_load_on_init": True,
    }


def _print_stats(ti: ThreatIntelligence) -> None:
    stats = ti.get_pattern_stats()
    print("\n=== Threat Intel Stats ===")
    print(f"  Live scraping available : {ti.is_live()}")
    print(f"  Total patterns          : {stats.get('total', 0)}")
    print(f"  By severity             : {stats.get('by_severity', {})}")
    print(f"  By type                 : {stats.get('by_type', {})}")
    print(f"  By source               : {stats.get('by_source', {})}")
    print(f"  Vector store            : {stats.get('vector_store', {})}")
    sigs = ti.get_dynamic_signatures()
    print(f"  Dynamic Tier 1 sigs     : {len(sigs)} (keyless detection)")
    snaps = ti.list_snapshots()
    print(f"  Snapshots on disk       : {len(snaps)}")
    if snaps:
        newest = snaps[0]
        print(f"  Newest snapshot         : {newest.get('label')} "
              f"({newest.get('pattern_count')} patterns, {newest.get('created_at')})")


def _harvest_once(ti: ThreatIntelligence, snapshot: bool) -> dict:
    if not ti.is_live() and not ti.config.get("use_mock_patterns"):
        logger.warning(
            "Bright Data access is NOT available — harvesting will return no new "
            "patterns. Use --restore to load a frozen snapshot, or --mock to seed."
        )
    result = ti.update_patterns(force=True)
    print(json.dumps(result, indent=2))

    if snapshot and result.get("status") in ("updated",):
        path = ti.export_snapshot()
        print(f"\nSnapshot frozen → {path}")
        print("  Commit ./snapshots to git so this intel survives access loss.")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="ShieldPrompt threat-intel harvester")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Run a single harvest cycle")
    mode.add_argument("--loop", type=int, metavar="SECONDS",
                      help="Harvest repeatedly every SECONDS")
    mode.add_argument("--stats", action="store_true", help="Print current intel stats and exit")
    mode.add_argument("--restore", nargs="?", const="__latest__", metavar="LABEL",
                      help="Restore a snapshot (default: latest) into the live store")

    parser.add_argument("--snapshot", action="store_true",
                        help="Freeze a git-committable snapshot after harvesting")
    parser.add_argument("--limit", type=int, default=50,
                        help="Max patterns per source per cycle (default: 50)")
    parser.add_argument("--mock", action="store_true",
                        help="Seed built-in mock patterns (no keys needed)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    ti = ThreatIntelligence(_build_config(args))

    if args.stats:
        _print_stats(ti)
        return 0

    if args.restore is not None:
        label = None if args.restore == "__latest__" else args.restore
        manifest = ti.load_snapshot(label)
        if not manifest:
            print("No snapshot restored (none found).")
            return 1
        print(json.dumps(manifest, indent=2))
        _print_stats(ti)
        return 0

    if args.loop:
        print(f"Harvest loop started (every {args.loop}s). Ctrl-C to stop.")
        try:
            while True:
                _harvest_once(ti, args.snapshot)
                _print_stats(ti)
                time.sleep(args.loop)
        except KeyboardInterrupt:
            print("\nHarvest loop stopped.")
        return 0

    # Default: single cycle.
    _harvest_once(ti, args.snapshot)
    _print_stats(ti)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
