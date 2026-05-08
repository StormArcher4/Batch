"""
Analysis 1 - Top 10 Malicious Source IPs
=========================================
Reads network logs from HDFS, filters suspicious and malicious events,
computes a weighted threat score per source IP, and saves the top 10.

Threat score = (malicious_count * 2) + suspicious_count
Malicious events are weighted double since they are more severe.

Checkpoint logic:
    Reads checkpoint_batch.json to get last_ingested_timestamp.
    If not found -> creates it with null, processes all data.
    After saving results, updates checkpoint with latest timestamp.

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
# 2. Spark session
# ---------------------------------------------------------------------------
spark = SparkSession.builder \
    .appName("Analysis1_TopMaliciousIPs") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")


# ---------------------------------------------------------------------------
# 3. Read checkpoint — create with null if missing
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
    print(f"\n>>> No checkpoint_batch found — creating it with null. ({e})")
    try:
        _data = json.dumps({"last_ingested_timestamp": None})
        _jvm  = spark.sparkContext._jvm
        _conf = spark.sparkContext._jsc.hadoopConfiguration()
        _fs   = _jvm.org.apache.hadoop.fs.FileSystem.get(_conf)
        _path = _jvm.org.apache.hadoop.fs.Path(CHECKPOINT_BATCH)
        _out  = _fs.create(_path, True)
        _out.write(bytearray(_data.encode("utf-8")))
        _out.close()
        print(">>> Created checkpoint_batch.json with null.")
    except Exception as e2:
        print(f">>> WARN: could not create checkpoint: {e2}")

# ---------------------------------------------------------------------------
# 5. Schema definition
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
# 6. Load data from HDFS
# ---------------------------------------------------------------------------
print("\n>>> Loading data from HDFS...")

df = spark.read \
    .schema(SCHEMA) \
    .option("header", "true") \
    .csv(HDFS_INPUT)

df = df.withColumn(
    "timestamp",
    F.coalesce(
        F.to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"),
        F.to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss"),
        F.to_timestamp("timestamp", "yyyy-MM-dd HH:mm:ss"),
    )
).filter(F.col("timestamp").isNotNull())

# ---------------------------------------------------------------------------
# 7. Apply checkpoint filter
# ---------------------------------------------------------------------------
if last_ts:
    df = df.filter(F.col("timestamp") > F.lit(last_ts).cast("timestamp"))
    print(f">>> Filtering logs after: {last_ts}")

df.cache()

total = df.count()
print(f">>> Records to process: {total:,}")

if total == 0:
    print(">>> No new records since last checkpoint. Nothing to do.")
    spark.stop()
    exit(0)

# ---------------------------------------------------------------------------
# 8. Filter — keep only suspicious and malicious rows
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
# 9. Aggregation
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
# 10. Merge with existing HDFS results
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

top_ips = combined.orderBy(F.col("threat_score").desc()).limit(10)

# ---------------------------------------------------------------------------
# 11. Show results
# ---------------------------------------------------------------------------
print("\n>>> Top 10 malicious source IPs:")
top_ips.show(truncate=False)

scores = top_ips.select(
    F.max("threat_score").alias("max_score"),
    F.min("threat_score").alias("min_score")
).collect()[0]
print(f">>> Score range: {scores['min_score']} – {scores['max_score']}")

# ---------------------------------------------------------------------------
# 12. Save to HDFS
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
