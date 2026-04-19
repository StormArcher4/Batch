"""
hbase_loader.py
===============
Reads the 4 Parquet batch outputs from HDFS and loads them into
3 HBase tables required by the project spec:

  ip_reputation   → Score + history per source IP
  attack_patterns → SQLi / XSS / Other patterns + top IPs
  threat_timeline → Malicious/suspicious counts per hour

HOW IT WORKS:
  - Uses happybase (Python Thrift client) to talk to HBase
  - Reads Parquet with PySpark, then collects() to driver
    (results are already small — top 10 IPs, aggregated counts)
  - Each row key is designed for fast lookup from the serving layer

Prerequisites inside hadoop-master:
  pip3 install happybase
  hbase thrift start &          ← must be running on port 9090

Run:
  spark-submit --master local[*] hbase_loader.py

Table schemas created here:
  ip_reputation
    row key : source_ip  (e.g. "192.168.1.45")
    cf:info  → threat_score, malicious_count, suspicious_count,
               total_events, last_seen, main_protocol, log_source

  attack_patterns
    row key : attack_type#source_ip  (e.g. "SQLi#10.0.0.5")
    cf:info  → hit_count, last_seen, attack_type, source_ip

  threat_timeline
    row key : YYYY-MM-DD-HH  (e.g. "2024-05-01-14")
    cf:counts → malicious, suspicious, benign, total
"""

import happybase
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

# ─────────────────────────────────────────────────────────────
# CONFIG — adjust if your Thrift host/port differs
# ─────────────────────────────────────────────────────────────
HBASE_HOST   = "localhost"
HBASE_PORT   = 9090

HDFS_BASE    = "hdfs://hadoop-master:9000/data/cybersecurity/batch"
HDFS_LOGS    = "hdfs://hadoop-master:9000/data/cybersecurity/logs/*/*/*/logs.csv"

# ─────────────────────────────────────────────────────────────
# SPARK SESSION
# ─────────────────────────────────────────────────────────────
spark = SparkSession.builder \
    .appName("HBase_Loader") \
    .getOrCreate()
spark.sparkContext.setLogLevel("WARN")

# ─────────────────────────────────────────────────────────────
# HELPER — connect + create tables safely
# ─────────────────────────────────────────────────────────────
def get_connection():
    """Returns a happybase Connection. Retries once on failure."""
    try:
        conn = happybase.Connection(HBASE_HOST, port=HBASE_PORT)
        conn.open()
        return conn
    except Exception as e:
        raise RuntimeError(
            f"Cannot connect to HBase Thrift at {HBASE_HOST}:{HBASE_PORT}\n"
            f"Make sure you ran: hbase thrift start\n"
            f"Error: {e}"
        )


def ensure_table(conn, table_name: str, families: dict):
    """Create HBase table if it doesn't already exist."""
    existing = [t.decode() for t in conn.tables()]
    if table_name not in existing:
        conn.create_table(table_name, families)
        print(f"  → Created table: {table_name}")
    else:
        print(f"  → Table already exists (skipping create): {table_name}")


def to_bytes(value) -> bytes:
    """Convert any value to UTF-8 bytes for HBase storage."""
    if value is None:
        return b""
    return str(value).encode("utf-8")


# ─────────────────────────────────────────────────────────────
# CONNECT TO HBASE + CREATE TABLES
# ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 1 — Connecting to HBase and creating tables")
print("=" * 60)

conn = get_connection()
print(f"Connected to HBase at {HBASE_HOST}:{HBASE_PORT}")

ensure_table(conn, "ip_reputation",   {"cf": dict()})
ensure_table(conn, "attack_patterns", {"cf": dict()})
ensure_table(conn, "threat_timeline", {"cf": dict()})


# ─────────────────────────────────────────────────────────────
# TABLE 1 — ip_reputation
# Source: analysis1 Parquet (top_malicious_ips)
# Row key: source_ip
# ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 2 — Loading ip_reputation")
print("=" * 60)

try:
    top_ips = spark.read.parquet(f"{HDFS_BASE}/top_malicious_ips")
    rows = top_ips.collect()
    print(f"  Records to write: {len(rows)}")

    table = conn.table("ip_reputation")
    batch = table.batch()

    for row in rows:
        row_key = to_bytes(row["source_ip"])
        batch.put(row_key, {
            b"cf:threat_score":      to_bytes(row["threat_score"]),
            b"cf:malicious_count":   to_bytes(row["malicious_count"]),
            b"cf:suspicious_count":  to_bytes(row["suspicious_count"]),
            b"cf:total_events":      to_bytes(row["total_events"]),
            b"cf:last_seen":         to_bytes(row["last_seen"]),
            b"cf:main_protocol":     to_bytes(row["main_protocol"]),
            b"cf:log_source":        to_bytes(row["log_source"]),
        })
        print(f"  Queued: {row['source_ip']}  score={row['threat_score']}")

    batch.send()
    print(f"  ✅ ip_reputation — {len(rows)} rows written")

except Exception as e:
    print(f"  ❌ ip_reputation failed: {e}")
    print("     → Make sure analysis1_top_ips.py ran successfully first")


# ─────────────────────────────────────────────────────────────
# TABLE 2 — attack_patterns
# Source: analysis3 Parquet (attack_patterns)
# Row key: attack_type#source_ip  (hash separator for range scans)
# ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 3 — Loading attack_patterns")
print("=" * 60)

try:
    patterns = spark.read.parquet(f"{HDFS_BASE}/attack_patterns")

    # Take top 50 per attack type to keep HBase reasonable
    from pyspark.sql.window import Window
    w = Window.partitionBy("attack_type").orderBy(F.col("hit_count").desc())
    top_patterns = patterns \
        .withColumn("rank", F.row_number().over(w)) \
        .filter(F.col("rank") <= 50) \
        .drop("rank", "sample_paths")   # drop array column (not HBase-friendly)

    rows = top_patterns.collect()
    print(f"  Records to write: {len(rows)}")

    table = conn.table("attack_patterns")
    batch = table.batch()

    for row in rows:
        # Row key: "SQLi#192.168.1.5" — groupable by attack type prefix
        row_key = to_bytes(f"{row['attack_type']}#{row['source_ip']}")
        batch.put(row_key, {
            b"cf:attack_type": to_bytes(row["attack_type"]),
            b"cf:source_ip":   to_bytes(row["source_ip"]),
            b"cf:hit_count":   to_bytes(row["hit_count"]),
            b"cf:last_seen":   to_bytes(row["last_seen"]),
        })

    batch.send()
    print(f"  ✅ attack_patterns — {len(rows)} rows written")

except Exception as e:
    print(f"  ❌ attack_patterns failed: {e}")
    print("     → Make sure analysis3_attack_patterns.py ran successfully first")


# ─────────────────────────────────────────────────────────────
# TABLE 3 — threat_timeline
# Source: raw logs (aggregated per hour)
# Row key: YYYY-MM-DD-HH
# ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 4 — Building and loading threat_timeline")
print("=" * 60)

try:
    # Read raw logs to build the hourly timeline
    # (not stored as its own Parquet yet — built here on the fly)
    from pyspark.sql.types import StructType, StructField, StringType, LongType

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

    df = spark.read \
        .option("header", "true") \
        .schema(schema) \
        .csv(HDFS_LOGS)

    # Parse timestamp to extract hour bucket
    df = df.withColumn(
        "ts",
        F.coalesce(
            F.to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss"),
            F.to_timestamp("timestamp", "yyyy-MM-dd HH:mm:ss")
        )
    ).filter(F.col("ts").isNotNull())

    df = df.withColumn(
        "hour_bucket",
        F.date_format("ts", "yyyy-MM-dd-HH")   # e.g. "2024-05-01-14"
    )

    timeline = df.groupBy("hour_bucket").agg(
        F.sum(F.when(F.col("threat_label") == "malicious",  1).otherwise(0)).alias("malicious"),
        F.sum(F.when(F.col("threat_label") == "suspicious", 1).otherwise(0)).alias("suspicious"),
        F.sum(F.when(F.col("threat_label") == "benign",     1).otherwise(0)).alias("benign"),
        F.count("*").alias("total")
    ).orderBy("hour_bucket")

    rows = timeline.collect()
    print(f"  Hour buckets to write: {len(rows)}")

    table = conn.table("threat_timeline")
    batch = table.batch()

    for row in rows:
        row_key = to_bytes(row["hour_bucket"])
        batch.put(row_key, {
            b"cf:malicious":  to_bytes(row["malicious"]),
            b"cf:suspicious": to_bytes(row["suspicious"]),
            b"cf:benign":     to_bytes(row["benign"]),
            b"cf:total":      to_bytes(row["total"]),
        })

    batch.send()
    print(f"  ✅ threat_timeline — {len(rows)} rows written")

    # Also save as Parquet for dashboard queries
    timeline.write \
        .mode("overwrite") \
        .parquet(f"{HDFS_BASE}/threat_timeline")
    print(f"  ✅ Also saved to HDFS: {HDFS_BASE}/threat_timeline")

except Exception as e:
    print(f"  ❌ threat_timeline failed: {e}")


# ─────────────────────────────────────────────────────────────
# STEP 5 — Verify: scan a few rows from each table
# ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 5 — Verification (first 3 rows per table)")
print("=" * 60)

for table_name in ["ip_reputation", "attack_patterns", "threat_timeline"]:
    print(f"\n  [{table_name}]")
    try:
        table = conn.table(table_name)
        count = 0
        for key, data in table.scan():
            print(f"    key={key.decode()}  →  {len(data)} columns")
            count += 1
            if count >= 3:
                break
        if count == 0:
            print("    ⚠ Table is empty — check the steps above for errors")
    except Exception as e:
        print(f"    ❌ Could not scan {table_name}: {e}")


conn.close()
spark.stop()

print("\n" + "=" * 60)
print("DONE — HBase Loader complete.")
print("  Batch layer is now fully loaded.")
print("  Next: run the Speed Layer (Kafka + Spark Streaming)")
print("=" * 60)
