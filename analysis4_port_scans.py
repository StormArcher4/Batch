"""
Analysis 4 - Port Scan Detection (5-minute time window)
========================================================
Detects port scanning behaviour by looking for source IPs that
connect to 5 or more distinct destination IPs within any
5-minute tumbling window.

Note on the dataset:
    The CSV has no separate port column, so we use distinct dest_ip
    as the scan indicator. This still correctly flags reconnaissance
    behaviour where an attacker probes multiple targets.

Checkpoint logic:
    Reads /home/checkpoint.json to get last_ingested_timestamp.
    Only processes logs AFTER that timestamp so we never rescan
    data that was already analysed and loaded into HBase.
    New scan events are merged with existing results so scan
    window counts accumulate across runs per source IP.
    The checkpoint itself is updated by hbase_loader.py after
    all analyses finish successfully.

Run:
    spark-submit --master local[*] analysis4_port_scans.py
"""

import json
import subprocess

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, LongType,
)

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------
HDFS_INPUT       = "hdfs://hadoop-master:9000/data/cybersecurity/logs"
HDFS_OUTPUT      = "hdfs://hadoop-master:9000/data/cybersecurity/batch/port_scans"
CHECKPOINT_BATCH = "hdfs:///data/cybersecurity/checkpoint_batch.json"

# ---------------------------------------------------------------------------
# 4. Spark session
# ---------------------------------------------------------------------------
spark = SparkSession.builder \
    .appName("Analysis4_PortScans") \
    .config("spark.sql.legacy.timeParserPolicy", "LEGACY") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")

# ---------------------------------------------------------------------------
# 2. Read checkpoint from HDFS
# ---------------------------------------------------------------------------
last_ts = None

try:
    cp_df = spark.read.text(CHECKPOINT_BATCH)
    raw = "\n".join(r.value for r in cp_df.collect())
    cp = json.loads(raw)
    raw_ts = cp.get("last_ingested_timestamp")
    if raw_ts:
        last_ts = raw_ts
        print(f"\n>>> Checkpoint found: processing logs after {last_ts}")
    else:
        print("\n>>> Checkpoint is null — processing all data.")
except Exception as e:
    print(f"\n>>> No checkpoint_batch found — processing all data. ({e})")

# ---------------------------------------------------------------------------
# 3. Schema definition
# ---------------------------------------------------------------------------
SCHEMA = StructType([
    StructField("timestamp",         StringType(), True),
    StructField("source_ip",         StringType(), True),
    StructField("dest_ip",           StringType(), True),
    StructField("protocol",          StringType(), True),
    StructField("action",            StringType(), True),
    StructField("threat_label",      StringType(), True),
    StructField("log_type",          StringType(), True),
    StructField("bytes_transferred", LongType(),   True),
    StructField("user_agent",        StringType(), True),
    StructField("request_path",      StringType(), True),
])

# ---------------------------------------------------------------------------
# 5. Load and parse timestamps
#    coalesce tries the T-format first, then falls back to space-format.
#    Rows where neither parses are dropped.
# ---------------------------------------------------------------------------
print("\n>>> Loading data from HDFS...")

df = spark.read \
    .option("header", "true") \
    .schema(SCHEMA) \
    .csv(HDFS_INPUT)

df = df.withColumn(
    "timestamp",
    F.coalesce(
        F.to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss"),
        F.to_timestamp("timestamp", "yyyy-MM-dd HH:mm:ss"),
    )
).filter(F.col("timestamp").isNotNull())

# ---------------------------------------------------------------------------
# 6. Apply checkpoint filter
#    Only keep rows strictly after last_ingested_timestamp.
#    If no checkpoint -> skip this and process everything.
# ---------------------------------------------------------------------------
if last_ts:
    df = df.filter(F.col("timestamp") > F.lit(last_ts).cast("timestamp"))
    print(f">>> Filtering logs after: {last_ts}")

# cache after filtering — reused by TCP count and window groupBy
df.cache()

total = df.count()
print(f">>> Records to process: {total:,}")

if total == 0:
    print(">>> No new records since last checkpoint. Nothing to do.")
    spark.stop()
    exit(0)

# ---------------------------------------------------------------------------
# 7. Filter to TCP only
#    Port scans use TCP — UDP and ICMP probes are out of scope here.
# ---------------------------------------------------------------------------
tcp = df.filter(F.col("protocol") == "TCP")
tcp_count = tcp.count()
print(f">>> TCP records: {tcp_count:,}")

if tcp_count == 0:
    print(">>> WARNING: No TCP records found in new data.")
    print("    Protocol distribution:")
    df.groupBy("protocol").count().orderBy(F.col("count").desc()).show()
    df.unpersist()
    spark.stop()
    exit(0)

# ---------------------------------------------------------------------------
# 8. Port scan detection — 5-minute tumbling windows
#    An IP is flagged if it reaches 5+ distinct destination IPs
#    within the same 5-minute window.
#
#    window() returns a struct {start, end} — we flatten it into two
#    plain timestamp columns so the Parquet is readable by hbase_loader.
# ---------------------------------------------------------------------------
SCAN_THRESHOLD = 5

print(f"\n>>> Detecting port scans (threshold: {SCAN_THRESHOLD}+ distinct dest IPs per 5 min)...")

raw_scans = tcp.groupBy(
    "source_ip",
    F.window("timestamp", "5 minutes").alias("time_window"),
).agg(
    F.countDistinct("dest_ip").alias("distinct_targets"),
    F.count("*").alias("total_connections"),
).filter(
    F.col("distinct_targets") >= SCAN_THRESHOLD
)

# flatten the window struct into two plain columns
new_scans = raw_scans.select(
    F.col("source_ip"),
    F.col("distinct_targets"),
    F.col("total_connections"),
    F.col("time_window.start").alias("window_start"),
    F.col("time_window.end").alias("window_end"),
)

scan_count = new_scans.count()
print(f"\n>>> Potential port scan events detected: {scan_count:,}")

# if nothing found, show the actual max so we can tune the threshold
if scan_count == 0:
    print(f">>> INFO: No scans at threshold={SCAN_THRESHOLD} in new data.")
    print("    Max distinct targets seen in any 5-min window:")
    tcp.groupBy(
        "source_ip",
        F.window("timestamp", "5 minutes"),
    ).agg(
        F.countDistinct("dest_ip").alias("distinct_targets")
    ).select(
        F.max("distinct_targets").alias("max_in_any_window")
    ).show()
    df.unpersist()
    spark.stop()
    exit(0)

# ---------------------------------------------------------------------------
# 9. Merge with existing HDFS results
#    New scan windows are appended to existing ones — each window is a
#    unique event (source_ip + window_start) so we just union them.
#    No double counting possible since checkpoint prevents reprocessing.
# ---------------------------------------------------------------------------
existing_check = subprocess.run(
    f"hdfs dfs -test -e {HDFS_OUTPUT}", shell=True
)

if existing_check.returncode == 0:
    print(">>> Merging with existing port_scans results...")
    existing = spark.read.parquet(HDFS_OUTPUT)

    # union old and new — each window_start is a unique point in time
    # so there is no risk of duplicating the same scan event
    scans = existing.unionByName(new_scans, allowMissingColumns=True) \
        .orderBy(F.col("distinct_targets").desc())
else:
    print(">>> No existing results — using new data only.")
    scans = new_scans.orderBy(F.col("distinct_targets").desc())

total_scans = scans.count()
print(f">>> Total scan events (all runs): {total_scans:,}")

# ---------------------------------------------------------------------------
# 10. Show results
# ---------------------------------------------------------------------------
print("\n>>> Top port scan events:")
scans.show(20, truncate=False)

# summary — which IPs opened the most scan windows across all runs
print("\n>>> IPs with most scan windows:")
scans.groupBy("source_ip").agg(
    F.count("*").alias("scan_windows"),
    F.sum("distinct_targets").alias("total_distinct_targets"),
    F.max("window_end").alias("last_seen"),
).orderBy(F.col("scan_windows").desc()).show(10, truncate=False)

# ---------------------------------------------------------------------------
# 11. Save to HDFS as Parquet
#     Window struct is already flattened so hbase_loader can read it
#     without any extra processing.
# ---------------------------------------------------------------------------
scans.write.mode("overwrite").parquet(HDFS_OUTPUT)
print(f"\n>>> Saved to: {HDFS_OUTPUT}")

saved = spark.read.parquet(HDFS_OUTPUT).count()
print(f">>> Rows confirmed in HDFS: {saved}")

df.unpersist()
spark.stop()
print("\n>>> Analysis 4 complete.")
