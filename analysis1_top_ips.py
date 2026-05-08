"""
Analysis 1 - Top 10 Malicious Source IPs
=========================================
Reads network logs from HDFS, filters suspicious and malicious events,
computes a weighted threat score per source IP, and saves the top 10.

Threat score = (malicious_count * 2) + suspicious_count
Malicious events are weighted double since they are more severe.

Checkpoint logic:
    Reads /home/checkpoint.json to get last_ingested_timestamp.
    Only processes logs AFTER that timestamp so we never rescan
    data that was already analysed and loaded into HBase.
    The checkpoint itself is updated by hbase_loader.py after
    all analyses finish successfully.

Run:
    spark-submit --master local[*] analysis1_top_ips.py
"""

import json
import subprocess

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, IntegerType,
)

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------
HDFS_INPUT       = "hdfs://hadoop-master:9000/data/cybersecurity/logs/*/*/*/logs.csv"
HDFS_OUTPUT      = "hdfs://hadoop-master:9000/data/cybersecurity/batch/top_malicious_ips"
CHECKPOINT_BATCH = "hdfs:///data/cybersecurity/checkpoint_batch.json"

# ---------------------------------------------------------------------------
# 4. Spark session
# ---------------------------------------------------------------------------
spark = SparkSession.builder \
    .appName("Analysis1_TopMaliciousIPs") \
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
    StructField("timestamp",         StringType(),  True),
    StructField("source_ip",         StringType(),  True),
    StructField("dest_ip",           StringType(),  True),
    StructField("protocol",          StringType(),  True),
    StructField("action",            StringType(),  True),
    StructField("threat_label",      StringType(),  True),
    StructField("log_type",          StringType(),  True),
    StructField("bytes_transferred", IntegerType(), True),
    StructField("user_agent",        StringType(),  True),
    StructField("request_path",      StringType(),  True),
])

# ---------------------------------------------------------------------------
# 5. Load data from HDFS
# ---------------------------------------------------------------------------
print("\n>>> Loading data from HDFS...")

df = spark.read \
    .schema(SCHEMA) \
    .option("header", "true") \
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

# ---------------------------------------------------------------------------
# 6. Apply checkpoint filter
#    Only keep rows strictly after last_ingested_timestamp.
#    If no checkpoint -> skip this and process everything.
# ---------------------------------------------------------------------------
if last_ts:
    df = df.filter(F.col("timestamp") > F.lit(last_ts).cast("timestamp"))
    print(f">>> Filtering logs after: {last_ts}")

# cache so HDFS is read only once across count + groupBy
df.cache()

total = df.count()
print(f">>> Records to process: {total:,}")

if total == 0:
    print(">>> No new records since last checkpoint. Nothing to do.")
    spark.stop()
    exit(0)

# ---------------------------------------------------------------------------
# 7. Filter — keep only suspicious and malicious rows
# ---------------------------------------------------------------------------
threats = df.filter(
    F.col("threat_label").isin("suspicious", "malicious")
)

threat_count = threats.count()
print(f">>> Threat records found: {threat_count:,}")

if threat_count == 0:
    print(">>> WARNING: No suspicious/malicious records in new data.")
    df.unpersist()
    spark.stop()
    exit(0)

# ---------------------------------------------------------------------------
# 8. Aggregation — one groupBy to get everything we need per IP
#
#    Single groupBy instead of two passes — a second groupBy would lose
#    the threat_label column making when() conditions return nulls silently.
#
#    Score formula: malicious counts double, suspicious counts once.
# ---------------------------------------------------------------------------
new_scores = threats.groupBy("source_ip").agg(

    F.count("*").alias("total_events"),

    F.sum(
        F.when(F.col("threat_label") == "malicious", 1).otherwise(0)
    ).alias("malicious_count"),

    F.sum(
        F.when(F.col("threat_label") == "suspicious", 1).otherwise(0)
    ).alias("suspicious_count"),

    F.max("timestamp").alias("last_seen"),
    F.first("protocol").alias("main_protocol"),
    F.first("log_type").alias("log_source"),

).withColumn(
    "threat_score",
    (F.col("malicious_count") * 2) + F.col("suspicious_count")
)

# ---------------------------------------------------------------------------
# 9. Merge with existing HDFS results
#    If previous results exist -> load and combine with new scores so
#    each IP accumulates its counts across all runs.
#    If no previous results -> use new scores directly.
# ---------------------------------------------------------------------------
existing_check = subprocess.run(
    f"hdfs dfs -test -e {HDFS_OUTPUT}",
    shell=True
)

if existing_check.returncode == 0:
    print("\n>>> Merging with existing results from previous runs...")
    existing = spark.read.parquet(HDFS_OUTPUT)

    combined = existing.unionByName(new_scores, allowMissingColumns=True) \
        .groupBy("source_ip").agg(
            F.sum("total_events").alias("total_events"),
            F.sum("malicious_count").alias("malicious_count"),
            F.sum("suspicious_count").alias("suspicious_count"),
            F.max("last_seen").alias("last_seen"),
            F.first("main_protocol").alias("main_protocol"),
            F.first("log_source").alias("log_source"),
        ).withColumn(
            "threat_score",
            (F.col("malicious_count") * 2) + F.col("suspicious_count")
        )
else:
    print("\n>>> No existing results — using new data only.")
    combined = new_scores

# take top 10 after merge
top_ips = combined.orderBy(F.col("threat_score").desc()).limit(10)

# ---------------------------------------------------------------------------
# 10. Show results
# ---------------------------------------------------------------------------
print("\n>>> Top 10 malicious source IPs:")
top_ips.show(truncate=False)

scores = top_ips.select(
    F.max("threat_score").alias("max_score"),
    F.min("threat_score").alias("min_score")
).collect()[0]
print(f">>> Score range: {scores['min_score']} – {scores['max_score']}")

# ---------------------------------------------------------------------------
# 11. Save to HDFS as Parquet
#     Overwrites previous top 10 with the newly merged results.
# ---------------------------------------------------------------------------
top_ips.write \
    .mode("overwrite") \
    .parquet(HDFS_OUTPUT)

print(f"\n>>> Saved to: {HDFS_OUTPUT}")

saved_count = spark.read.parquet(HDFS_OUTPUT).count()
print(f">>> Rows confirmed in HDFS: {saved_count}")

df.unpersist()
spark.stop()
print("\n>>> Analysis 1 complete.")
