"""
Analysis 2 — Bytes Transferred per Threat Label
=================================================
Correlates bytes_transferred with threat_label.
Gives avg, total, max, min, and p95 per label,
and also a breakdown by protocol inside each label.

Fixes vs original:
  1. df.cache() added — avoids 3x re-reads from HDFS
  2. Null bytes_transferred filtered before aggregation
  3. Null threat_label filtered before groupBy
  4. inferSchema disabled — schema defined manually, faster load

Run:
  spark-submit --master local[*] analysis2_threat_volume.py
"""

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StructType, StructField, StringType, LongType

# ── Spark session ──────────────────────────────────────────────
spark = SparkSession.builder \
    .appName("Analysis2_ThreatVolume") \
    .getOrCreate()
spark.sparkContext.setLogLevel("WARN")

HDFS_INPUT   = "hdfs://hadoop-master:9000/data/cybersecurity/logs/*/*/*/logs.csv"
HDFS_OUTPUT  = "hdfs://hadoop-master:9000/data/cybersecurity/batch/threat_volume"
HDFS_OUTPUT2 = "hdfs://hadoop-master:9000/data/cybersecurity/batch/threat_volume_by_protocol"

# ── Define schema manually (faster than inferSchema) ──────────
# FIX 4: no inferSchema scan — we declare types directly
schema = StructType([
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
    .schema(schema) \
    .csv(HDFS_INPUT)

# FIX 3: remove rows with no threat_label
# FIX 2: remove rows with null bytes_transferred
df = df.filter(
    F.col("threat_label").isNotNull() &
    F.col("bytes_transferred").isNotNull()
)

# FIX 1: cache so HDFS is only read once
df.cache()

total = df.count()
print(f">>> Total clean records: {total:,}")

# ── Check what threat labels exist ────────────────────────────
print("\n>>> Distinct threat_label values in dataset:")
df.select("threat_label").distinct().show()

# ── Aggregation 1: by threat_label ────────────────────────────
print("\n>>> Computing bytes by threat_label...")
threat_volume = df.groupBy("threat_label").agg(
    F.count("*").alias("event_count"),
    F.sum("bytes_transferred").alias("total_bytes"),
    F.round(F.avg("bytes_transferred"), 2).alias("avg_bytes"),
    F.max("bytes_transferred").alias("max_bytes"),
    F.min("bytes_transferred").alias("min_bytes"),
    F.percentile_approx("bytes_transferred", 0.95).alias("p95_bytes")
).orderBy("threat_label")

print("\n>>> Bytes by threat label:")
threat_volume.show(truncate=False)

# ── Aggregation 2: by threat_label + protocol ─────────────────
print("\n>>> Computing bytes by threat_label + protocol...")
protocol_volume = df.groupBy("threat_label", "protocol").agg(
    F.count("*").alias("event_count"),
    F.sum("bytes_transferred").alias("total_bytes"),
    F.round(F.avg("bytes_transferred"), 2).alias("avg_bytes")
).orderBy("threat_label", F.col("total_bytes").desc())

print("\n>>> Bytes by threat_label + protocol:")
protocol_volume.show(40, truncate=False)

# ── Save ───────────────────────────────────────────────────────
threat_volume.write.mode("overwrite").parquet(HDFS_OUTPUT)
protocol_volume.write.mode("overwrite").parquet(HDFS_OUTPUT2)

print(f"\n>>> Saved to: {HDFS_OUTPUT}")
print(f">>> Saved to: {HDFS_OUTPUT2}")

df.unpersist()
spark.stop()
