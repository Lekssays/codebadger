#!/usr/bin/env python3
"""
Print CodeBadger's recommended, memory-aware configuration constants.

Usage:
    python scripts/recommend_config.py                 # autodetect host
    python scripts/recommend_config.py --mem 256 --cores 96
    python scripts/recommend_config.py --heap 6        # size for bigger CPGs
    python scripts/recommend_config.py --compare config.yaml

This is the standalone twin of the block CodeBadger logs at startup.  Use it to
plan a host before launching, or to size a different machine.
"""

import argparse
import os
import sys

# Allow running directly from a checkout without installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.recommend import HostSpec, compute, current_from_config, detect_host, render


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mem", type=float, default=None, help="Total host RAM in GB (default: autodetect)")
    parser.add_argument("--cores", type=int, default=None, help="Host CPU cores (default: autodetect)")
    parser.add_argument("--heap", type=int, default=4, help="Standard query-server heap -Xmx in GB (default: 4)")
    parser.add_argument("--build-heap", type=int, default=6, help="Per build-worker frontend heap in GB (default: 6)")
    parser.add_argument("--headroom", type=int, default=None, help="GB reserved for OS/Docker/Postgres/Redis/API (default: ~15%%)")
    parser.add_argument("--build-workers", type=int, default=None, help="Override CPG build workers (default: cores/16, 2-6)")
    parser.add_argument("--gen-timeout", type=int, default=1800, help="CPG generation timeout in seconds (default: 1800)")
    parser.add_argument("--worker-mode", choices=["shared", "pool"], default="shared", help="Joern worker mode (default: shared)")
    parser.add_argument("--compare", metavar="CONFIG_YAML", default=None, help="Flag drift against a config.yaml")
    args = parser.parse_args()

    if args.mem is not None or args.cores is not None:
        detected = detect_host()
        host = HostSpec(
            total_mem_gb=args.mem if args.mem is not None else detected.total_mem_gb,
            cores=args.cores if args.cores is not None else detected.cores,
            source="manual" if (args.mem is not None and args.cores is not None) else detected.source,
        )
    else:
        host = detect_host()

    rec = compute(
        host,
        query_heap_gb=args.heap,
        build_heap_gb=args.build_heap,
        headroom_gb=args.headroom,
        build_workers=args.build_workers,
        generation_timeout_s=args.gen_timeout,
        worker_mode=args.worker_mode,
    )

    current = None
    if args.compare:
        try:
            from src.config import load_config

            current = current_from_config(load_config(args.compare))
        except Exception as e:
            print(f"Warning: could not load {args.compare} for comparison: {e}", file=sys.stderr)

    print(render(rec, current=current))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
