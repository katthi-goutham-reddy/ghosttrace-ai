"""
GhostTrace AI — Main Entry Point for HackerRank Orchestrate: Ghost Data Still Exists.

This module processes deletion audit requests from dataset/deletion_requests.csv
and outputs predictions to output.csv at the repository root according to the challenge contract.
"""
import sys
import time
import argparse
from pathlib import Path

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from code.config import Config
from code.audit_pipeline import AuditPipeline


def main():
    parser = argparse.ArgumentParser(description="GhostTrace AI Deletion Audit Agent")
    parser.add_argument(
        "--input",
        type=Path,
        default=Config.DELETION_REQUESTS_PATH,
        help="Input CSV file path (default: dataset/deletion_requests.csv)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Config.ROOT_OUTPUT_PATH,
        help="Output CSV file path (default: output.csv at repo root)"
    )
    parser.add_argument(
        "--samples",
        action="store_true",
        help="Run on public sample dataset (dataset/sample_deletion_requests.csv)"
    )
    args = parser.parse_args()

    input_path = Config.SAMPLE_DELETION_REQUESTS_PATH if args.samples else args.input
    output_path = args.output

    print("=" * 70)
    print("GhostTrace AI — Deletion Audit Pipeline")
    print("HackerRank Orchestrate: Ghost Data Still Exists")
    print("=" * 70)
    print(f"Input file:  {input_path}")
    print(f"Output file: {output_path}")

    start_time = time.time()
    pipeline = AuditPipeline()
    load_time = time.time() - start_time
    print(f"Loaded evidence store and models in {load_time:.2f}s")

    print(f"Processing requests from {input_path.name}...")
    proc_start = time.time()
    count = pipeline.run_file(input_path, output_path)
    proc_time = time.time() - proc_start

    print("-" * 70)
    print(f"Successfully processed {count} cases in {proc_time:.2f}s (avg {proc_time/max(1, count)*1000:.1f}ms/case)")
    print(f"Results written to: {output_path.resolve()}")
    print("=" * 70)


if __name__ == "__main__":
    main()
