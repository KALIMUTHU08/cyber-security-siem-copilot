"""
seed_dataset.py — CLI script to stream the Kaggle dataset into the SIEM DB.

Usage (from backend/):
    python seed_dataset.py [--path PATH] [--limit N] [--chunk-size N] [--reset]

    --path        Path to the CSV (default: ../dataset/cybersecurity_threat_detection_logs.csv)
    --limit       Cap on total rows (default: 50000 for demo; 0 = no cap)
    --chunk-size  Rows per pipeline batch (default: 5000)
    --reset       Drop and recreate the database before seeding
"""

import argparse
import sys
import time
import uuid
from pathlib import Path

# Ensure backend/app is on the path
sys.path.insert(0, str(Path(__file__).parent))

from app.database.session import SessionLocal, engine
from app.database.base import Base
from app.ingestion.dataset_adapter import stream_dataset_chunks, get_dataset_info
from app.services.siem_pipeline import run_pipeline_on_records, seed_default_rules_if_empty
from app.services.dataset_status_service import update_persistent_seed_status


def parse_args():
    parser = argparse.ArgumentParser(description="Seed SIEM DB from Kaggle dataset")
    parser.add_argument(
        "--path",
        default=str(Path(__file__).parent.parent / "dataset" / "cybersecurity_threat_detection_logs.csv"),
        help="Path to dataset CSV",
    )
    parser.add_argument("--limit", type=int, default=50_000, help="Max rows (0=all)")
    parser.add_argument("--chunk-size", type=int, default=5_000, help="Rows per batch")
    parser.add_argument("--reset", action="store_true", help="Drop and recreate DB")
    return parser.parse_args()


def main():
    args = parse_args()
    max_rows = args.limit if args.limit > 0 else None
    batch_id = f"cli-{uuid.uuid4().hex[:8]}"

    print(f"\n{'='*60}")
    print("  SIEM Copilot — Dataset Seed Tool")
    print(f"{'='*60}")

    # Dataset info
    info = get_dataset_info(args.path)
    if not info["exists"]:
        print(f"[ERROR] Dataset not found: {args.path}")
        sys.exit(1)

    print(f"[INFO] Dataset : {args.path}")
    print(f"[INFO] Size    : {info['size_mb']} MB")
    print(f"[INFO] Columns : {', '.join(info['columns'])}")
    print(f"[INFO] Limit   : {max_rows or 'ALL'} rows")
    print(f"[INFO] Chunk   : {args.chunk_size} rows/batch")
    print(f"[INFO] Batch ID: {batch_id}")

    # Optionally reset DB
    if args.reset:
        print("\n[RESET] Dropping and recreating all tables...")
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        print("[RESET] Done.")

    # Seed detection rules
    db = SessionLocal()
    try:
        seed_default_rules_if_empty(db)
        update_persistent_seed_status(db, {
            "running": True,
            "done": False,
            "started_at": time.time(),
            "finished_at": None,
            "rows_processed": 0,
            "alerts_generated": 0,
            "incidents_updated": 0,
            "error": None,
            "limit": args.limit,
            "chunk_size": args.chunk_size,
            "batch_id": batch_id,
        })
    finally:
        db.close()

    # Stream and process
    print(f"\n[SEED] Starting ingestion...\n")
    t_start = time.time()
    total_rows = 0
    total_alerts = 0
    total_incidents = 0
    chunk_count = 0
    error_msg = None

    try:
        for chunk, cumulative in stream_dataset_chunks(
            csv_path=args.path,
            chunk_size=args.chunk_size,
            max_rows=max_rows,
        ):
            chunk_count += 1
            db = SessionLocal()
            try:
                stats, alerts = run_pipeline_on_records(db, chunk)
                total_rows += stats.processed
                total_alerts += stats.alerts_generated
                total_incidents += stats.incidents_updated

                update_persistent_seed_status(db, {
                    "rows_processed": total_rows,
                    "alerts_generated": total_alerts,
                    "incidents_updated": total_incidents,
                })
            except Exception as e:
                print(f"[WARN] Chunk {chunk_count} failed: {e}")
                error_msg = str(e)
            finally:
                db.close()

            elapsed = time.time() - t_start
            rate = total_rows / elapsed if elapsed > 0 else 0
            print(
                f"  Chunk {chunk_count:4d} | Rows: {total_rows:8,} | "
                f"Alerts: {total_alerts:6,} | Incidents: {total_incidents:4,} | "
                f"Rate: {rate:6.0f} rows/s"
            )

    except Exception as e:
        error_msg = str(e)
        print(f"[ERROR] Seeding halted: {e}")
    finally:
        final_db = SessionLocal()
        try:
            update_persistent_seed_status(final_db, {
                "running": False,
                "done": True,
                "finished_at": time.time(),
                "error": error_msg,
            })
        finally:
            final_db.close()

    elapsed = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"  SEED COMPLETE")
    print(f"  Total rows    : {total_rows:,}")
    print(f"  Total alerts  : {total_alerts:,}")
    print(f"  Total incidents: {total_incidents:,}")
    print(f"  Time elapsed  : {elapsed:.1f}s")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
