"""
Analysis 3 - Attack Pattern Detection
======================================
This script scans network logs stored in HDFS and detects known
web attack patterns by inspecting the request_path and user_agent fields.

Detected attack types (in priority order):
    - SQL_INJECTION     : SQL keywords and injection payloads in request_path
    - XSS_PATTERNS      : Cross-site scripting tags/events in request_path
    - PATH_TRAVERSAL    : Directory traversal attempts in request_path
    - tool_based_attack : Known hacking tools detected in user_agent

Checkpoint logic:
    Reads /home/checkpoint.json to get last_ingested_timestamp.
    Only processes logs AFTER that timestamp so we never rescan
    data that was already analysed and loaded into HBase.
    New hit_counts are merged with existing results so counts
    accumulate across runs per IP and attack type.
    The checkpoint itself is updated by hbase_loader.py after
    all analyses finish successfully.

Run:
    spark-submit --master local[*] analysis3_attack_patterns.py
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
HDFS_OUTPUT      = "hdfs://hadoop-master:9000/data/cybersecurity/batch/attack_patterns"
CHECKPOINT_BATCH = "hdfs:///data/cybersecurity/checkpoint_batch.json"

# ---------------------------------------------------------------------------
# 4. Spark session
# ---------------------------------------------------------------------------
spark = SparkSession.builder \
    .appName("Analysis3_AttackPatterns") \
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
# 5. Load data from HDFS
# ---------------------------------------------------------------------------
print("\n>>> Loading logs from HDFS...")

df = spark.read \
    .option("header", "true") \
    .schema(SCHEMA) \
    .csv(HDFS_INPUT)

# parse timestamp so we can filter by it properly
df = df.withColumn(
    "timestamp",
    F.coalesce(
        F.to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"),
        F.to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss"),
        F.to_timestamp("timestamp", "yyyy-MM-dd HH:mm:ss"),
    )
).filter(F.col("timestamp").isNotNull())

# keep only rows where at least one of the columns we inspect is present
df = df.filter(
    F.col("request_path").isNotNull() | F.col("user_agent").isNotNull()
)

# ---------------------------------------------------------------------------
# 6. Apply checkpoint filter
#    Only keep rows strictly after last_ingested_timestamp.
#    If no checkpoint -> skip this and process everything.
# ---------------------------------------------------------------------------
if last_ts:
    df = df.filter(F.col("timestamp") > F.lit(last_ts).cast("timestamp"))
    print(f">>> Filtering logs after: {last_ts}")

# cache so Spark doesn't re-read HDFS on every action below
df.cache()

total = df.count()
print(f">>> Records to process: {total:,}")

if total == 0:
    print(">>> No new records since last checkpoint. Nothing to do.")
    spark.stop()
    exit(0)

# ---------------------------------------------------------------------------
# 7. Attack signature patterns
#    Each variable is a single regex string (patterns joined with OR '|').
#    These are the same patterns used in the streaming layer (global_vars.py)
#    so batch and real-time detection stay consistent.
# ---------------------------------------------------------------------------

# SQL injection — detects SQL keywords and common bypass techniques
SQL_INJECTION = '|'.join([
    r"(?i)(\bselect\b.*\bfrom\b)",
    r"(?i)(\binsert\b.*\binto\b)",
    r"(?i)(\bupdate\b.*\bset\b)",
    r"(?i)(\bdelete\b.*\bfrom\b)",
    r"(?i)(\bdrop\b.*\b(table|database)\b)",
    r"(?i)(\bcreate\b.*\b(table|database)\b)",
    r"(?i)(\balter\b.*\b(table|database)\b)",
    r"(?i)(\btruncate\b.*\b(table)\b)",
    r"(?i)(or\b.*=.*\b)",           # tautology: OR x=x
    r"(?i)(and\b.*=.*\b)",          # tautology: AND x=x
    r"(?i)(\b1\s*=\s*1\b)",
    r"(?i)(\b1\s*=\s*2\b)",
    r"(?i)(\btrue\b.*\b=true\b)",
    r"(?i)(\bfalse\b.*\b=false\b)",
    r"--+",                          # SQL comment
    r"/\*.*\*/",                     # SQL block comment
    r"(?i)(\b#\b)",                  # MySQL comment
])

# XSS — detects script injection and event-based payloads
XSS_PATTERNS = '|'.join([
    r"<script[^>]*>.*?</script>",
    r"<script[^>]*>",
    r"</script>",
    r"javascript:",
    r"vbscript:",
    r"data:text/html",
])

# Path traversal — detects attempts to navigate outside the web root
# includes plain and URL-encoded variants
PATH_TRAVERSAL = '|'.join([
    r"\.\./",           # ../
    r"\.\.\\",          # ..\
    r"\.\.%2f",         # URL encoded /
    r"\.\.%5c",         # URL encoded \
    r"%2e%2e%2f",       # double encoded ../
    r"%2e%2e%5c",       # double encoded ..\
    r"\.\.%252f",       # double percent encoded
    r"\.\.%255c",
])

# Attack tools — matched against user_agent header
# these tools identify themselves in the user agent string
TOOLS = '|'.join([
    r"(?i)(sqlmap)",        # automated SQL injection tool
    r"(?i)(sqlninja)",      # SQL Server exploitation tool
    r"(?i)(sqldict)",       # SQL dictionary attack tool
    r"(?i)(dirb)",          # web directory brute-forcer
    r"(?i)(gobuster)",      # directory and DNS brute-forcer
    r"(?i)(nikto)",         # web vulnerability scanner
    r"(?i)(nmap.*script)",  # nmap with scripting engine (NSE)
])

# ---------------------------------------------------------------------------
# 8. Tag each row with its attack type
#    Priority order matters: a request matching both SQLi and XSS
#    will be labelled SQL_INJECTION (checked first).
#    Rows that don't match any pattern are dropped (no "Other" label).
# ---------------------------------------------------------------------------
df_tagged = df.withColumn(
    "attack_type",
    F.when(
        F.col("request_path").rlike(SQL_INJECTION),
        F.lit("SQL_INJECTION")
    ).when(
        F.col("request_path").rlike(XSS_PATTERNS),
        F.lit("XSS_PATTERNS")
    ).when(
        F.col("request_path").rlike(PATH_TRAVERSAL),
        F.lit("PATH_TRAVERSAL")
    ).when(
        F.col("user_agent").rlike(TOOLS),
        F.lit("tool_based_attack")
    )
    # no .otherwise() — rows with no match get NULL and are filtered out
).filter(F.col("attack_type").isNotNull())

attack_count = df_tagged.count()
print(f"\n>>> Attack rows detected: {attack_count:,}")

# if nothing matched, print samples to help debug and exit cleanly
if attack_count == 0:
    print(">>> WARNING: No attack patterns matched in new data.")
    print("    Sample request_path values:")
    df.select("request_path").show(10, truncate=False)
    print("    Sample user_agent values:")
    df.select("user_agent").show(10, truncate=False)
    df.unpersist()
    spark.stop()
    exit(0)

# ---------------------------------------------------------------------------
# 9. Summary — attack count per type
# ---------------------------------------------------------------------------
print("\n>>> Attack type breakdown:")
df_tagged.groupBy("attack_type") \
    .count() \
    .orderBy(F.col("count").desc()) \
    .show()

# ---------------------------------------------------------------------------
# 10. Severity assignment
#     Matches the severity levels used in the streaming layer
#     so the dashboard shows consistent levels across both layers.
# ---------------------------------------------------------------------------
df_tagged = df_tagged.withColumn(
    "severity",
    F.when(F.col("attack_type") == "SQL_INJECTION",     F.lit("critical"))
     .when(F.col("attack_type") == "XSS_PATTERNS",      F.lit("high"))
     .when(F.col("attack_type") == "PATH_TRAVERSAL",    F.lit("high"))
     .when(F.col("attack_type") == "tool_based_attack", F.lit("medium"))
     .otherwise(F.lit("low"))
)

# ---------------------------------------------------------------------------
# 11. Aggregation — top source IPs per attack type
#     sample_paths_str stored as plain string — HBase can't store arrays.
# ---------------------------------------------------------------------------
print("\n>>> Top source IPs per attack type:")

new_detailed = (
    df_tagged
    .groupBy("attack_type", "severity", "source_ip")
    .agg(
        F.count("*").alias("hit_count"),
        F.max("timestamp").alias("last_seen"),
        F.concat_ws(" | ", F.collect_list(
            F.substring("request_path", 1, 80)
        )).alias("sample_paths_str"),
    )
)

# ---------------------------------------------------------------------------
# 12. Merge with existing HDFS results
#     Add new hit_counts to existing ones so totals accumulate across runs.
#     last_seen is updated to the most recent timestamp seen.
#     sample_paths_str is refreshed with latest samples.
# ---------------------------------------------------------------------------
existing_check = subprocess.run(
    f"hdfs dfs -test -e {HDFS_OUTPUT}", shell=True
)

if existing_check.returncode == 0:
    print(">>> Merging with existing attack_patterns results...")
    existing = spark.read.parquet(HDFS_OUTPUT)

    detailed = existing.unionByName(new_detailed, allowMissingColumns=True) \
        .groupBy("attack_type", "severity", "source_ip").agg(
            F.sum("hit_count").alias("hit_count"),
            F.max("last_seen").alias("last_seen"),
            # keep latest sample paths from the new run
            F.last("sample_paths_str", ignorenulls=True).alias("sample_paths_str"),
        ).orderBy("attack_type", F.col("hit_count").desc())
else:
    print(">>> No existing results — using new data only.")
    detailed = new_detailed.orderBy("attack_type", F.col("hit_count").desc())

detailed.select(
    "attack_type", "severity", "source_ip", "hit_count", "last_seen"
).show(30, truncate=False)

# ---------------------------------------------------------------------------
# 13. Save results to HDFS as Parquet
#     hbase_loader.py picks this up and loads it into HBase attack_patterns.
# ---------------------------------------------------------------------------
detailed.write.mode("overwrite").parquet(HDFS_OUTPUT)
print(f"\n>>> Results saved to: {HDFS_OUTPUT}")

saved_count = spark.read.parquet(HDFS_OUTPUT).count()
print(f">>> Rows confirmed in HDFS: {saved_count}")

df.unpersist()
spark.stop()
print("\n>>> Analysis 3 complete.")
