#!/usr/bin/env python3
"""
ShieldPrompt Threat-Intel CLI
=============================

Manage the threat-intelligence store without any live scraping. Patterns come
from a static dataset file or the built-in mock seed; everything flows through
the same ingest -> vector-sync -> persist pipeline and can be frozen into a
portable, git-committable snapshot under ./snapshots.

Examples
--------
    # Seed built-in mock patterns and freeze a snapshot:
    python scripts/intel.py --mock --snapshot

    # Ingest a purchased/curated dataset (JSON list or dict of records):
    python scripts/intel.py --dataset path/to/patterns.json --snapshot

    # Show what's currently stored:
    python scripts/intel.py --stats

    # Restore the latest frozen snapshot into the live store:
    python scripts/intel.py --restore

Dataset schema (per record): pattern_id (required), description, pattern_regex,
threat_type, severity, source, references, first_seen, last_updated.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Make the project importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from src.core.threat_intel import ThreatIntelligence  # noqa: E402

logger = logging.getLogger("intel")


def _build_config() -> dict:
    return {
        "openai_api_key": os.getenv("OPENAI_API_KEY"),
        "auto_load_on_init": True,    # accumulate on top of the warm cache
    }


def _print_stats(ti: ThreatIntelligence) -> None:
    stats = ti.get_pattern_stats()
    print("\n=== Threat Intel Stats ===")
    print(f"  Total patterns      : {stats.get('total', 0)}")
    print(f"  By severity         : {stats.get('by_severity', {})}")
    print(f"  By type             : {stats.get('by_type', {})}")
    print(f"  By source           : {stats.get('by_source', {})}")
    print(f"  Vector store        : {stats.get('vector_store', {})}")
    sigs = ti.get_dynamic_signatures()
    print(f"  Dynamic Tier 1 sigs : {len(sigs)} (keyless detection)")
    snaps = ti.list_snapshots()
    print(f"  Snapshots on disk   : {len(snaps)}")
    if snaps:
        newest = snaps[0]
        print(f"  Newest snapshot     : {newest.get('label')} "
              f"({newest.get('pattern_count')} patterns, {newest.get('created_at')})")


def main() -> int:
    parser = argparse.ArgumentParser(description="ShieldPrompt threat-intel CLI")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--mock", action="store_true",
                      help="Seed built-in mock patterns")
    mode.add_argument("--dataset", metavar="PATH",
                      help="Ingest patterns from a static dataset JSON file")
    mode.add_argument("--stats", action="store_true",
                      help="Print current intel stats and exit")
    mode.add_argument("--restore", nargs="?", const="__latest__", metavar="LABEL",
                      help="Restore a snapshot (default: latest) into the live store")

    parser.add_argument("--snapshot", action="store_true",
                        help="Freeze a git-committable snapshot afterwards")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    ti = ThreatIntelligence(_build_config())

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

    if args.mock:
        result = ti.load_mock_patterns()
        print(f"Mock patterns seeded: {result.new_patterns} new "
              f"({ti.ingester.pattern_count} total)")
        ti.update_patterns()  # sync + persist

    if args.dataset:
        result = ti.ingest_dataset(args.dataset)
        print(json.dumps(result, indent=2))
        if result.get("status") == "error":
            return 1

    if args.snapshot:
        path = ti.export_snapshot()
        print(f"\nSnapshot frozen → {path}")
        print("  Commit ./snapshots to git to preserve this intel.")

    _print_stats(ti)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
