"""
Analysis 2 - Bytes Transferred per Threat Label
=================================================
Correlates bytes_transferred with threat_label to understand
how much data each threat category moves through the network.

Produces two aggregations:
    - Per threat_label: count, total, avg, max, min, p95 bytes
    - Per threat_label + protocol: breakdown of traffic by protocol

Checkpoint logic:
    Reads /home/checkpoint.json to get last_ingested_timestamp.
    Only processes logs AFTER that timestamp so we never rescan
    data that was already analysed and loaded into HBase.
    The checkpoint itself is updated by hbase_loader.py after
    all analyses finish successfully.

Run:
    spark-submit --master local[*] analysis2_threat_volume.py
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
HDFS_INPUT       = "hdfs://hadoop-master:9000/data/cybersecurity/logs/*/*/*/logs.csv"
HDFS_OUTPUT      = "hdfs://hadoop-master:9000/data/cybersecurity/batch/threat_volume"
HDFS_OUTPUT2     = "hdfs://hadoop-master:9000/data/cybersecurity/batch/threat_volume_by_protocol"
CHECKPOINT_BATCH = "hdfs:///data/cybersecurity/checkpoint_batch.json"

# ---------------------------------------------------------------------------
# 4. Spark session
# ---------------------------------------------------------------------------
spark = SparkSession.builder \
    .appName("Analysis2_ThreatVolume") \
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
print("\n>>> Loading data from HDFS...")

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

# drop rows where key columns are missing — they can't be aggregated
df = df.filter(
    F.col("threat_label").isNotNull() &
    F.col("bytes_transferred").isNotNull()
)

# ---------------------------------------------------------------------------
# 6. Apply checkpoint filter
#    Only keep rows strictly after last_ingested_timestamp.
#    If no checkpoint -> skip this and process everything.
# ---------------------------------------------------------------------------
if last_ts:
    df = df.filter(F.col("timestamp") > F.lit(last_ts).cast("timestamp"))
    print(f">>> Filtering logs after: {last_ts}")

# cache so HDFS is read only once across both aggregations
df.cache()

total = df.count()
print(f">>> Records to process: {total:,}")

if total == 0:
    print(">>> No new records since last checkpoint. Nothing to do.")
    spark.stop()
    exit(0)

# show what labels are present — useful to verify the data looks right
print("\n>>> Distinct threat_label values:")
df.select("threat_label").distinct().show()

# ---------------------------------------------------------------------------
# 7. Aggregation 1 — bytes stats per threat_label
#    p95 gives a better picture of heavy transfers than max alone
#    since max can be a one-off outlier.
# ---------------------------------------------------------------------------
print("\n>>> Computing bytes by threat_label...")

new_threat_volume = df.groupBy("threat_label").agg(
    F.count("*").alias("event_count"),
    F.sum("bytes_transferred").alias("total_bytes"),
    F.max("bytes_transferred").alias("max_bytes"),
    F.min("bytes_transferred").alias("min_bytes"),
    F.percentile_approx("bytes_transferred", 0.95).alias("p95_bytes"),
)

# ---------------------------------------------------------------------------
# 8. Merge aggregation 1 with existing HDFS results
#    Combine old and new counts so totals accumulate across runs.
#    avg_bytes is recomputed from merged total_bytes / event_count.
# ---------------------------------------------------------------------------
existing_check = subprocess.run(
    f"hdfs dfs -test -e {HDFS_OUTPUT}", shell=True
)

if existing_check.returncode == 0:
    print(">>> Merging with existing threat_volume results...")
    existing = spark.read.parquet(HDFS_OUTPUT).drop("avg_bytes")

    threat_volume = existing.unionByName(new_threat_volume, allowMissingColumns=True) \
        .groupBy("threat_label").agg(
            F.sum("event_count").alias("event_count"),
            F.sum("total_bytes").alias("total_bytes"),
            F.max("max_bytes").alias("max_bytes"),
            F.min("min_bytes").alias("min_bytes"),
            F.max("p95_bytes").alias("p95_bytes"),
        ).withColumn(
            "avg_bytes",
            F.round(F.col("total_bytes") / F.col("event_count"), 2)
        ).orderBy("threat_label")
else:
    print(">>> No existing results — using new data only.")
    threat_volume = new_threat_volume.withColumn(
        "avg_bytes",
        F.round(F.col("total_bytes") / F.col("event_count"), 2)
    ).orderBy("threat_label")

print("\n>>> Bytes by threat label:")
threat_volume.show(truncate=False)

# ---------------------------------------------------------------------------
# 9. Aggregation 2 — bytes per threat_label + protocol
#    Shows which protocol carries the most data for each threat type.
# ---------------------------------------------------------------------------
print("\n>>> Computing bytes by threat_label + protocol...")

new_protocol_volume = df.groupBy("threat_label", "protocol").agg(
    F.count("*").alias("event_count"),
    F.sum("bytes_transferred").alias("total_bytes"),
)

# ---------------------------------------------------------------------------
# 10. Merge aggregation 2 with existing HDFS results
# ---------------------------------------------------------------------------
existing_check2 = subprocess.run(
    f"hdfs dfs -test -e {HDFS_OUTPUT2}", shell=True
)

if existing_check2.returncode == 0:
    print(">>> Merging with existing threat_volume_by_protocol results...")
    existing2 = spark.read.parquet(HDFS_OUTPUT2).drop("avg_bytes")

    protocol_volume = existing2.unionByName(new_protocol_volume, allowMissingColumns=True) \
        .groupBy("threat_label", "protocol").agg(
            F.sum("event_count").alias("event_count"),
            F.sum("total_bytes").alias("total_bytes"),
        ).withColumn(
            "avg_bytes",
            F.round(F.col("total_bytes") / F.col("event_count"), 2)
        ).orderBy("threat_label", F.col("total_bytes").desc())
else:
    print(">>> No existing results — using new data only.")
    protocol_volume = new_protocol_volume.withColumn(
        "avg_bytes",
        F.round(F.col("total_bytes") / F.col("event_count"), 2)
    ).orderBy("threat_label", F.col("total_bytes").desc())

print("\n>>> Bytes by threat_label + protocol:")
protocol_volume.show(40, truncate=False)

# ---------------------------------------------------------------------------
# 11. Save both results to HDFS
# ---------------------------------------------------------------------------
threat_volume.write.mode("overwrite").parquet(HDFS_OUTPUT)
protocol_volume.write.mode("overwrite").parquet(HDFS_OUTPUT2)

print(f"\n>>> Saved to: {HDFS_OUTPUT}")
print(f">>> Saved to: {HDFS_OUTPUT2}")

df.unpersist()
spark.stop()
print("\n>>> Analysis 2 complete.")
