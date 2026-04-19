"""
Analysis 3 — SQLi / XSS / Other Attack Patterns in request_path
================================================================
Scans the request_path column for known attack signatures
and classifies them as SQLi, XSS, or Other.

FIXES vs original:
  1. Replaced inferSchema=True with explicit schema (faster + safer)
  2. Added df.cache() — avoids 3 re-reads for count/tag/save
  3. Added check: if 0 attack rows found, print sample paths and exit
     (instead of silently saving an empty Parquet)
  4. collect_list + slice replaced with F.concat_ws for HBase compat
     (arrays can't be stored in HBase — joined string is safer)

Run:
  spark-submit --master local[*] analysis3_attack_patterns.py
"""

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, LongType
)

# ── Spark session ──────────────────────────────────────────────
spark = SparkSession.builder \
    .appName("Analysis3_AttackPatterns") \
    .getOrCreate()
spark.sparkContext.setLogLevel("WARN")

HDFS_INPUT  = "hdfs://hadoop-master:9000/data/cybersecurity/logs/*/*/*/logs.csv"
HDFS_OUTPUT = "hdfs://hadoop-master:9000/data/cybersecurity/batch/attack_patterns"

# ── FIX 1: Explicit schema (no inferSchema scan) ───────────────
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

# Keep only rows with a request_path
df = df.filter(F.col("request_path").isNotNull())

# FIX 2: cache so HDFS is read only once across count + groupBy + write
df.cache()

total = df.count()
print(f">>> Records with request_path: {total:,}")

if total == 0:
    print(">>> ERROR: No records with request_path found. Check HDFS input path.")
    spark.stop()
    exit(1)

# ── Attack signature lists ─────────────────────────────────────
SQLI_PATTERNS = [
    "' or ", "or 1=1", "' --", "union select", "drop table",
    "insert into", "sqlmap", "' and ", "xp_cmdshell",
    "information_schema", "sleep(", "benchmark(",
    "1=1", "' or '1'='1"
]

XSS_PATTERNS = [
    "<script>", "javascript:", "onerror=", "onload=",
    "alert(", "<img src", "document.cookie", "eval(",
    "<iframe", "onmouseover=", "</script>"
]

OTHER_PATTERNS = [
    "nikto", "../", "/etc/passwd", "cmd.exe",
    "/bin/bash", "wget ", "curl ", "base64_decode",
    "nmap", ".php?id=", "../../"
]

def make_filter(patterns):
    """Build an OR condition matching any pattern (case-insensitive)."""
    path = F.lower(F.col("request_path"))
    cond = path.contains(patterns[0].lower())
    for p in patterns[1:]:
        cond = cond | path.contains(p.lower())
    return cond

# ── Tag rows with attack type ──────────────────────────────────
# Priority order: SQLi > XSS > Other
df_tagged = df.withColumn(
    "attack_type",
    F.when(make_filter(SQLI_PATTERNS),  "SQLi")
     .when(make_filter(XSS_PATTERNS),   "XSS")
     .when(make_filter(OTHER_PATTERNS), "Other")
     .otherwise(None)
).filter(F.col("attack_type").isNotNull())

attack_count = df_tagged.count()
print(f"\n>>> Total attack-pattern rows found: {attack_count:,}")

# FIX 3: guard against empty result
if attack_count == 0:
    print(">>> WARNING: No attack patterns found in request_path.")
    print("    Sample paths from your data:")
    df.select("request_path").show(10, truncate=False)
    df.unpersist()
    spark.stop()
    exit(1)

# ── Summary: count per attack_type ────────────────────────────
print("\n>>> Attack type totals:")
df_tagged.groupBy("attack_type") \
    .count() \
    .orderBy(F.col("count").desc()) \
    .show()

# ── Detailed: top IPs per attack type ─────────────────────────
# FIX 4: store sample_paths as a joined string, not an array
#         → arrays cause issues with HBase loader (not serialisable as string)
print("\n>>> Top IPs per attack type:")
detailed = df_tagged.groupBy("attack_type", "source_ip").agg(
    F.count("*").alias("hit_count"),
    F.max("timestamp").alias("last_seen"),
    F.concat_ws(" | ", F.collect_list(
        F.substring("request_path", 1, 80)   # cap each path at 80 chars
    )).alias("sample_paths_str")              # plain string, HBase-safe
).orderBy("attack_type", F.col("hit_count").desc())

detailed.select("attack_type", "source_ip", "hit_count", "last_seen") \
    .show(30, truncate=False)

# ── Save ───────────────────────────────────────────────────────
detailed.write.mode("overwrite").parquet(HDFS_OUTPUT)
print(f"\n>>> Saved to: {HDFS_OUTPUT}")

# Verify
saved = spark.read.parquet(HDFS_OUTPUT).count()
print(f">>> Confirmed rows in HDFS: {saved}")

df.unpersist()
spark.stop()

print("\n>>> Analysis 3 complete.")
