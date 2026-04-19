"""
Analysis 4 — Port Scan Detection (5-minute time window)
========================================================
A port scan = one source IP connecting to 5+ DIFFERENT destination IPs
within any 5-minute tumbling window.

NOTE on the dataset:
  The CSV has no separate 'port' column.
  We use distinct dest_ip as the scan indicator — this is the correct
  adaptation for this dataset and still flags reconnaissance behaviour.

FIXES vs original:
  1. Replaced inferSchema=True with explicit schema (faster, no double read)
  2. Added df.cache() after timestamp parse — avoids re-reading HDFS
     for both the TCP filter count and the window aggregation
  3. Added guard: if no TCP records found, print protocol distribution
     and exit cleanly instead of crashing on empty DataFrame
  4. Added guard: if no scans detected, lower threshold suggestion printed
  5. Timestamp coalesce kept (handles both T and space formats)
  6. Output columns made explicit — no struct columns left in Parquet
     (window() returns a struct; we extract start/end manually to keep
      the Parquet flat and readable by hbase_loader.py)

Run:
  spark-submit --master local[*] analysis4_port_scans.py
"""

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, LongType
)

# ── Spark session ──────────────────────────────────────────────
spark = SparkSession.builder \
    .appName("Analysis4_PortScans") \
    .config("spark.sql.legacy.timeParserPolicy", "LEGACY") \
    .getOrCreate()
spark.sparkContext.setLogLevel("WARN")

HDFS_INPUT  = "hdfs://hadoop-master:9000/data/cybersecurity/logs/*/*/*/logs.csv"
HDFS_OUTPUT = "hdfs://hadoop-master:9000/data/cybersecurity/batch/port_scans"

# ── FIX 1: Explicit schema ─────────────────────────────────────
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

# ── Load ───────────────────────────────────────────────────────
print("\n>>> Loading data from HDFS...")
df = spark.read \
    .option("header", "true") \
    .schema(SCHEMA) \
    .csv(HDFS_INPUT)

# ── Parse timestamp (handles T and space separator) ────────────
df = df.withColumn(
    "timestamp",
    F.coalesce(
        F.to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss"),
        F.to_timestamp("timestamp", "yyyy-MM-dd HH:mm:ss")
    )
).filter(F.col("timestamp").isNotNull())

# FIX 2: cache after parse — reused by count() + window groupBy
df.cache()

total = df.count()
print(f">>> Total records with valid timestamp: {total:,}")

if total == 0:
    print(">>> ERROR: No records loaded. Check HDFS path.")
    spark.stop()
    exit(1)

# ── Filter to TCP only ─────────────────────────────────────────
tcp = df.filter(F.col("protocol") == "TCP")
tcp_count = tcp.count()
print(f">>> TCP records: {tcp_count:,}")

# FIX 3: guard against no TCP rows
if tcp_count == 0:
    print(">>> WARNING: No TCP records found.")
    print("    Protocol distribution in your dataset:")
    df.groupBy("protocol").count().orderBy(F.col("count").desc()).show()
    df.unpersist()
    spark.stop()
    exit(1)

# ── Port scan detection using 5-min tumbling windows ──────────
# Threshold: 5+ distinct destination IPs from same source in 5 min
SCAN_THRESHOLD = 5

print(f"\n>>> Running port scan detection (threshold: {SCAN_THRESHOLD}+ distinct dest IPs)...")

# FIX 6: extract window struct fields into flat columns
#         window() returns col("time_window.start") and col("time_window.end")
#         keeping the struct in Parquet causes read errors downstream
raw_scans = tcp.groupBy(
    "source_ip",
    F.window("timestamp", "5 minutes").alias("time_window")
).agg(
    F.countDistinct("dest_ip").alias("distinct_targets"),
    F.count("*").alias("total_connections")
).filter(
    F.col("distinct_targets") >= SCAN_THRESHOLD
)

# Flatten the window struct into two plain timestamp columns
scans = raw_scans.select(
    F.col("source_ip"),
    F.col("distinct_targets"),
    F.col("total_connections"),
    F.col("time_window.start").alias("window_start"),
    F.col("time_window.end").alias("window_end"),
).orderBy(F.col("distinct_targets").desc())

scan_count = scans.count()
print(f"\n>>> Detected {scan_count:,} potential port scan events")

# FIX 4: if nothing detected, suggest lowering threshold
if scan_count == 0:
    print(f">>> INFO: No scans found at threshold={SCAN_THRESHOLD}.")
    print("    Checking what the actual max distinct_targets looks like...")
    tcp.groupBy(
        "source_ip",
        F.window("timestamp", "5 minutes")
    ).agg(
        F.countDistinct("dest_ip").alias("distinct_targets")
    ).select(
        F.max("distinct_targets").alias("max_in_any_window")
    ).show()
    print("    Try lowering SCAN_THRESHOLD in the script if max > 0.")
    df.unpersist()
    spark.stop()
    exit(0)   # exit 0 — not an error, just no scans in this dataset

# ── Show results ───────────────────────────────────────────────
print("\n>>> Top port scan events:")
scans.show(20, truncate=False)

# ── Summary: most active scanners ─────────────────────────────
print("\n>>> IPs with most scan windows:")
scans.groupBy("source_ip").agg(
    F.count("*").alias("scan_windows"),
    F.sum("distinct_targets").alias("total_distinct_targets"),
    F.max("window_end").alias("last_seen")
).orderBy(F.col("scan_windows").desc()) \
 .show(10, truncate=False)

# ── Save (flat Parquet — no struct columns) ────────────────────
scans.write.mode("overwrite").parquet(HDFS_OUTPUT)
print(f"\n>>> Saved to: {HDFS_OUTPUT}")

# Verify
saved = spark.read.parquet(HDFS_OUTPUT).count()
print(f">>> Confirmed rows in HDFS: {saved}")

df.unpersist()
spark.stop()

print("\n>>> Analysis 4 complete.")
