"""
prepare_hdfs_folders.py
=======================
Reads cybersecurity_threat_detection_logs.csv, partitions rows by date,
and uploads them into the correct HDFS folders.

Fixes applied vs original:
  1. Handles BOTH timestamp formats:
       - "2024-05-01T00:00:00"  (your actual CSV format)
       - "2023-10-15 14:23:45"  (original format)
  2. Tracks failed uploads and reports a summary at the end
  3. Removed duplicate/dead subprocess calls in the verification step
  4. Spark will read CSV correctly (files stay .csv — just use
     spark.read().option("header","true").csv(...) in your Spark jobs)

Run INSIDE hadoop-master:
  python3 prepare_hdfs_folders.py

Requirements:
  - CSV file at /home/cybersecurity_threat_detection_logs.csv
  - HDFS must be running  →  hdfs dfsadmin -report
"""

import csv
import os
import subprocess
from collections import defaultdict

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
CSV_PATH  = "/home/cybersecurity_threat_detection_logs.csv"
HDFS_BASE = "/data/cybersecurity/logs"
TMP_DIR   = "/tmp/cyber_partitions"

BATCH_OUTPUT_DIRS = [
    "batch/top_malicious_ips",
    "batch/port_scans",
    "batch/attack_patterns",
    "batch/threat_volume",
    "batch/threat_timeline",
]

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────
def hdfs(cmd: str):
    """Run an 'hdfs dfs <cmd>' shell command.
    Returns (returncode, combined_output_string).
    """
    result = subprocess.run(
        f"hdfs dfs {cmd}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.returncode, (result.stdout + result.stderr).strip()


def parse_date(timestamp: str):
    """
    Extract (year, month, day) from a timestamp string.

    Supported formats:
      - "2024-05-01T00:00:00"   ← your CSV
      - "2023-10-15 14:23:45"   ← original format

    Returns None if the timestamp cannot be parsed.
    """
    ts = timestamp.strip()
    if not ts:
        return None

    # Normalise: replace 'T' separator with a space
    ts = ts.replace("T", " ")

    # Take only the date part (before the space)
    date_part = ts.split(" ")[0]   # e.g. "2024-05-01"
    parts = date_part.split("-")

    if len(parts) != 3:
        return None

    year, month, day = parts

    # Basic sanity checks
    if not (year.isdigit() and month.isdigit() and day.isdigit()):
        return None

    return year, month, day


# ─────────────────────────────────────────────────────────────
# STEP 1 — Read CSV & group rows by date
# ─────────────────────────────────────────────────────────────
print("=" * 60)
print("STEP 1 — Reading CSV and grouping rows by date")
print("=" * 60)

if not os.path.exists(CSV_PATH):
    raise FileNotFoundError(
        f"CSV not found at {CSV_PATH}\n"
        "Copy it into the container first:\n"
        "  docker cp cybersecurity_threat_detection_logs.csv "
        "hadoop-master:/home/"
    )

date_groups  = defaultdict(list)   # (year, month, day) → [rows]
skipped_rows = 0
fieldnames   = None

with open(CSV_PATH, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames          # preserve column order

    for row in reader:
        ts     = row.get("timestamp", "")
        parsed = parse_date(ts)

        if parsed is None:
            skipped_rows += 1
            continue

        date_groups[parsed].append(row)

dates = sorted(date_groups.keys())

print(f"  CSV columns   : {fieldnames}")
print(f"  Unique dates  : {len(dates)}")
print(f"  Skipped rows  : {skipped_rows}  (bad/missing timestamp)")
print()

for d in dates:
    count = len(date_groups[d])
    print(f"  year={d[0]} / month={d[1]} / day={d[2]}  →  {count:,} records")

if not dates:
    raise RuntimeError(
        "No valid dates found in the CSV.\n"
        "Check that the 'timestamp' column exists and is non-empty."
    )

# ─────────────────────────────────────────────────────────────
# STEP 2 — Create HDFS directories
# ─────────────────────────────────────────────────────────────
print()
print("=" * 60)
print("STEP 2 — Creating HDFS directories")
print("=" * 60)

# Batch output dirs (for Spark results)
batch_base = HDFS_BASE.replace("logs", "")   # /data/cybersecurity/
for extra in BATCH_OUTPUT_DIRS:
    path = batch_base + extra
    code, out = hdfs(f"-mkdir -p {path}")
    status = "OK" if code == 0 else f"WARN ({out})"
    print(f"  {status}  →  {path}")

# Per-day partition dirs
dir_errors = []
for (year, month, day) in dates:
    folder = f"{HDFS_BASE}/year={year}/month={month}/day={day}"
    code, out = hdfs(f"-mkdir -p {folder}")
    if code != 0:
        dir_errors.append((folder, out))
        print(f"  ERROR creating {folder}: {out}")
    else:
        print(f"  Created: {folder}")

if dir_errors:
    print(f"\n  ⚠  {len(dir_errors)} directory creation error(s) — check HDFS connectivity.")

# ─────────────────────────────────────────────────────────────
# STEP 3 — Write per-day CSV files and upload to HDFS
# ─────────────────────────────────────────────────────────────
print()
print("=" * 60)
print("STEP 3 — Uploading per-day CSV files to HDFS")
print("=" * 60)

os.makedirs(TMP_DIR, exist_ok=True)

upload_ok     = []   # list of (hdfs_path, row_count)
upload_failed = []   # list of (hdfs_path, error_message)

for (year, month, day) in dates:
    rows        = date_groups[(year, month, day)]
    local_file  = f"{TMP_DIR}/logs_{year}_{month}_{day}.csv"
    hdfs_folder = f"{HDFS_BASE}/year={year}/month={month}/day={day}"
    hdfs_file   = f"{hdfs_folder}/logs.csv"

    # --- Write local temp CSV ---
    try:
        with open(local_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    except OSError as e:
        upload_failed.append((hdfs_file, str(e)))
        print(f"  ERROR writing local file {local_file}: {e}")
        continue

    # --- Remove existing file in HDFS (avoid conflict) ---
    hdfs(f"-rm -f {hdfs_file}")

    # --- Upload to HDFS ---
    code, out = hdfs(f"-put {local_file} {hdfs_file}")

    if code == 0:
        upload_ok.append((hdfs_file, len(rows)))
        print(f"  ✓  {len(rows):>7,} rows  →  {hdfs_file}")
    else:
        upload_failed.append((hdfs_file, out))
        print(f"  ✗  ERROR uploading {hdfs_file}")
        print(f"       {out}")

    # --- Clean up local temp file ---
    try:
        os.remove(local_file)
    except OSError:
        pass   # not critical

# ─────────────────────────────────────────────────────────────
# STEP 4 — Verify HDFS structure
# ─────────────────────────────────────────────────────────────
print()
print("=" * 60)
print("STEP 4 — Verifying HDFS structure")
print("=" * 60)

# List top-level HDFS directory
code, out = hdfs(f"-ls {HDFS_BASE}")
print(out if out else "(no output)")

# Count uploaded day-files (single subprocess call — no duplication)
result = subprocess.run(
    f"hdfs dfs -ls -R {HDFS_BASE} | grep 'logs\\.csv' | wc -l",
    shell=True,
    capture_output=True,
    text=True,
)
file_count = result.stdout.strip()
print(f"\n  Day-files found in HDFS : {file_count}")

# Disk usage
print("\n  Disk usage:")
subprocess.run(f"hdfs dfs -du -h {HDFS_BASE}", shell=True)

# ─────────────────────────────────────────────────────────────
# STEP 5 — Final summary
# ─────────────────────────────────────────────────────────────
print()
print("=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"  Dates processed   : {len(dates)}")
print(f"  Uploads succeeded : {len(upload_ok)}")
print(f"  Uploads failed    : {len(upload_failed)}")

if upload_failed:
    print("\n  Failed uploads:")
    for path, err in upload_failed:
        print(f"    ✗  {path}")
        print(f"       Reason: {err}")
else:
    total_rows = sum(c for _, c in upload_ok)
    print(f"  Total rows uploaded : {total_rows:,}")
    print("\n  ✅ All uploads successful!")

print()
print("  Verify manually with:")
print(f"    hdfs dfs -ls -R {HDFS_BASE} | grep 'day='")
print()
print("  In your Spark batch jobs, read with:")
print(f'    spark.read().option("header","true").csv("{HDFS_BASE}/*/*/*/logs.csv")')
print()
print("Done!")
