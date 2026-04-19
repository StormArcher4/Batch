"""
Analysis 1 — Top 10 Malicious Source IPs
=========================================
Filters rows where threat_label is 'suspicious' or 'malicious',
computes a weighted threat score per source IP, and saves top 10.

Threat score = (malicious_count * 2) + suspicious_count
  → malicious events are weighted double

Run inside hadoop-master:
  spark-submit --master local[*] analysis1_top_ips.py
"""

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, IntegerType
)

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
HDFS_INPUT  = "hdfs://hadoop-master:9000/data/cybersecurity/logs/*/*/*/logs.csv"
HDFS_OUTPUT = "hdfs://hadoop-master:9000/data/cybersecurity/batch/top_malicious_ips"

# ─────────────────────────────────────────────────────────────
# SCHEMA — explicit so Spark doesn't read the file twice
# (inferSchema does a full pass just to guess types — slow)
# ─────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────
# SPARK SESSION
# ─────────────────────────────────────────────────────────────
spark = SparkSession.builder \
    .appName("Analysis1_TopMaliciousIPs") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")

print("=" * 60)
print("ANALYSIS 1 — Top 10 Malicious Source IPs")
print("=" * 60)

# ─────────────────────────────────────────────────────────────
# STEP 1 — Load data from HDFS
# ─────────────────────────────────────────────────────────────
print("\n>>> Loading data from HDFS...")

df = spark.read \
    .schema(SCHEMA) \
    .option("header", "true") \
    .csv(HDFS_INPUT)

total = df.count()
print(f">>> Total records loaded : {total:,}")

if total == 0:
    print(">>> ERROR: No records loaded. Check HDFS path and that the upload script ran.")
    spark.stop()
    exit(1)

# ─────────────────────────────────────────────────────────────
# STEP 2 — Filter: keep only suspicious + malicious rows
# ─────────────────────────────────────────────────────────────
threats = df.filter(
    F.col("threat_label").isin("suspicious", "malicious")
)

threat_count = threats.count()
print(f">>> Threat records found : {threat_count:,}")

if threat_count == 0:
    print(">>> WARNING: No suspicious/malicious records found.")
    print("    Check the threat_label values in your CSV:")
    df.select("threat_label").distinct().show()
    spark.stop()
    exit(1)

# ─────────────────────────────────────────────────────────────
# STEP 3 — Aggregate in a single groupBy
#
# WHY single groupBy:
#   If we group twice (first by source_ip + threat_label, then
#   again by source_ip), the threat_label column is gone in the
#   second pass and the when() conditions silently return nulls.
#   Doing everything in one pass avoids that bug entirely.
#
# Threat score formula:
#   malicious events count double (more severe)
#   suspicious events count once
#   score = (malicious_count * 2) + suspicious_count
# ─────────────────────────────────────────────────────────────
top_ips = threats.groupBy("source_ip").agg(

    F.count("*").alias("total_events"),

    F.sum(
        F.when(F.col("threat_label") == "malicious", 1).otherwise(0)
    ).alias("malicious_count"),

    F.sum(
        F.when(F.col("threat_label") == "suspicious", 1).otherwise(0)
    ).alias("suspicious_count"),

    F.max("timestamp").alias("last_seen"),

    # most common protocol used by this IP
    F.first("protocol").alias("main_protocol"),

    # most common log_type (firewall / ids / application)
    F.first("log_type").alias("log_source"),

).withColumn(
    "threat_score",
    (F.col("malicious_count") * 2) + F.col("suspicious_count")
).orderBy(
    F.col("threat_score").desc()
).limit(10)

# ─────────────────────────────────────────────────────────────
# STEP 4 — Show results in console
# ─────────────────────────────────────────────────────────────
print("\n>>> Top 10 malicious source IPs:")
print("-" * 60)
top_ips.show(truncate=False)

# Quick sanity: print the score range
scores = top_ips.select(
    F.max("threat_score").alias("max_score"),
    F.min("threat_score").alias("min_score")
).collect()[0]
print(f">>> Score range : {scores['min_score']} – {scores['max_score']}")

# ─────────────────────────────────────────────────────────────
# STEP 5 — Save to HDFS as Parquet
#
# Parquet is used (not CSV) because:
#   - The HBase loader and dashboard query layer expect Parquet
#   - It is columnar and much faster for downstream reads
#   - mode("overwrite") makes reruns safe
# ─────────────────────────────────────────────────────────────
print(f"\n>>> Saving results to HDFS: {HDFS_OUTPUT}")

top_ips.write \
    .mode("overwrite") \
    .parquet(HDFS_OUTPUT)

print(">>> Save complete.")

# ─────────────────────────────────────────────────────────────
# STEP 6 — Verify by reading back
# ─────────────────────────────────────────────────────────────
print("\n>>> Verifying saved output...")
verify = spark.read.parquet(HDFS_OUTPUT)
saved_count = verify.count()
print(f">>> Records confirmed in HDFS : {saved_count}")

print("\n" + "=" * 60)
print("DONE — Analysis 1 complete.")
print(f"  Output : {HDFS_OUTPUT}")
print("  Next   : run analysis2_port_scans.py")
print("=" * 60)

spark.stop()
