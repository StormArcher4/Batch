"""
hbase_loader.py - Batch Results Loader into HBase
===================================================
Reads the Parquet outputs from the 4 analysis scripts and loads
them into 3 HBase tables required by the project:

    ip_reputation   — threat score and history per source IP
    attack_patterns — detected attack types and top offending IPs
    threat_timeline — malicious/suspicious event counts per hour

Write strategy:
    Analysis scripts (1-4) already handle merging old + new data
    in their Parquet outputs. So hbase_loader simply overwrites
    each HBase row with the already-merged value from Parquet.
    No double counting possible.

Checkpoint update:
    After all tables are loaded successfully, finds the latest
    last_seen timestamp across all results and writes it to
    /home/checkpoint.json as last_ingested_timestamp.
    The next run of all scripts will use this to skip already
    processed data.

HBase row key design:
    ip_reputation   -> source_ip              (e.g. "192.168.1.45")
    attack_patterns -> attack_type#source_ip  (e.g. "SQL_INJECTION#10.0.0.5")
    threat_timeline -> YYYY-MM-DD-HH          (e.g. "2024-05-01-14")

Prerequisites:
    pip3 install happybase
    hbase thrift start &    (must be running on port 9090)

Run:
    spark-submit --master local[*] hbase_loader.py
"""

import json
import os
from datetime import datetime

import happybase
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.window import Window
from pyspark.sql.types import (
    StructType, StructField,
    StringType, LongType,
)

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------
HBASE_HOST        = "localhost"
HBASE_PORT        = 9090
CHECKPOINT_BATCH  = "hdfs:///data/cybersecurity/checkpoint_batch.json"

HDFS_BASE = "hdfs://hadoop-master:9000/data/cybersecurity/batch"
HDFS_LOGS = "hdfs://hadoop-master:9000/data/cybersecurity/logs"

# ---------------------------------------------------------------------------
# 2. Spark session
# ---------------------------------------------------------------------------
spark = SparkSession.builder \
    .appName("HBase_Loader") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")

# ---------------------------------------------------------------------------
# 3. Helper functions
# ---------------------------------------------------------------------------

def get_connection():
    """Open a happybase connection to HBase Thrift server."""
    try:
        conn = happybase.Connection(HBASE_HOST, port=HBASE_PORT)
        conn.open()
        return conn
    except Exception as e:
        raise RuntimeError(
            f"Cannot connect to HBase at {HBASE_HOST}:{HBASE_PORT}. "
            f"Make sure 'hbase thrift start' is running. Error: {e}"
        )


def ensure_table(conn, table_name: str, families: dict):
    """Create the HBase table only if it doesn't already exist."""
    existing = [t.decode() for t in conn.tables()]
    if table_name not in existing:
        conn.create_table(table_name, families)
        print(f"  Created table: {table_name}")
    else:
        print(f"  Table already exists: {table_name}")


def to_bytes(value) -> bytes:
    """Convert any value to UTF-8 bytes for HBase storage."""
    if value is None:
        return b""
    return str(value).encode("utf-8")


# track the latest timestamp seen across all tables for checkpoint update
latest_ts = None

def update_latest(ts_value):
    """Keep track of the most recent timestamp seen across all tables."""
    global latest_ts
    if ts_value is None:
        return
    ts_str = str(ts_value)
    if latest_ts is None or ts_str > latest_ts:
        latest_ts = ts_str

# ---------------------------------------------------------------------------
# 4. Connect to HBase and create tables
# ---------------------------------------------------------------------------
print("\n>>> Connecting to HBase...")
conn = get_connection()
print(f">>> Connected at {HBASE_HOST}:{HBASE_PORT}")

ensure_table(conn, "ip_reputation",   {"cf": dict()})
ensure_table(conn, "attack_patterns", {"cf": dict()})
ensure_table(conn, "threat_timeline", {"cf": dict()})

# ---------------------------------------------------------------------------
# 5. Load ip_reputation
#    Source: analysis1 Parquet — already contains merged counts from all runs.
#    We simply overwrite each HBase row with the correct merged value.
#    Row key: source_ip
# ---------------------------------------------------------------------------
print("\n>>> Loading ip_reputation...")
ip_rep_ok = False

try:
    top_ips = spark.read.parquet(f"{HDFS_BASE}/top_malicious_ips")
    rows = top_ips.collect()
    print(f"  Records: {len(rows)}")

    table = conn.table("ip_reputation")
    batch = table.batch()

    for row in rows:
        row_key   = to_bytes(row["source_ip"])
        last_seen = str(row["last_seen"]) if row["last_seen"] else ""
        update_latest(last_seen)

        # analysis1 already merged old + new — just write directly
        batch.put(row_key, {
            b"cf:threat_score":     to_bytes(row["threat_score"]),
            b"cf:malicious_count":  to_bytes(row["malicious_count"]),
            b"cf:suspicious_count": to_bytes(row["suspicious_count"]),
            b"cf:total_events":     to_bytes(row["total_events"]),
            b"cf:last_seen":        to_bytes(last_seen),
            b"cf:main_protocol":    to_bytes(row["main_protocol"]),
            b"cf:log_source":       to_bytes(row["log_source"]),
        })
        print(f"  Writing: {row['source_ip']}  score={row['threat_score']}")

    batch.send()
    print(f"  Done — {len(rows)} rows written to ip_reputation")
    ip_rep_ok = True

except Exception as e:
    print(f"  Failed: {e}")
    print("  Make sure analysis1_top_ips.py ran successfully first.")

# ---------------------------------------------------------------------------
# 6. Load attack_patterns
#    Source: analysis3 Parquet — already contains merged hit_counts.
#    Row key: attack_type#source_ip
#    Keep top 50 per attack type to keep HBase size reasonable.
# ---------------------------------------------------------------------------
print("\n>>> Loading attack_patterns...")
atk_ok = False

try:
    patterns = spark.read.parquet(f"{HDFS_BASE}/attack_patterns")

    # rank IPs within each attack type by hit count, keep top 50
    w = Window.partitionBy("attack_type").orderBy(F.col("hit_count").desc())
    top_patterns = patterns \
        .withColumn("rank", F.row_number().over(w)) \
        .filter(F.col("rank") <= 50) \
        .drop("rank", "sample_paths_str")

    rows = top_patterns.collect()
    print(f"  Records: {len(rows)}")

    table = conn.table("attack_patterns")
    batch = table.batch()

    for row in rows:
        row_key   = to_bytes(f"{row['attack_type']}#{row['source_ip']}")
        last_seen = str(row["last_seen"]) if row["last_seen"] else ""
        update_latest(last_seen)

        # analysis3 already merged old + new hit_counts — just write directly
        batch.put(row_key, {
            b"cf:attack_type": to_bytes(row["attack_type"]),
            b"cf:source_ip":   to_bytes(row["source_ip"]),
            b"cf:hit_count":   to_bytes(row["hit_count"]),
            b"cf:last_seen":   to_bytes(last_seen),
            b"cf:severity":    to_bytes(row["severity"]),
        })

    batch.send()
    print(f"  Done — {len(rows)} rows written to attack_patterns")
    atk_ok = True

except Exception as e:
    print(f"  Failed: {e}")
    print("  Make sure analysis3_attack_patterns.py ran successfully first.")

# ---------------------------------------------------------------------------
# 7. Build and load threat_timeline
#    Built here from raw logs grouped by hour bucket.
#    Applies checkpoint filter so only new logs are processed.
#    Row key: YYYY-MM-DD-HH — sorts chronologically in HBase.
#    Simple overwrite per hour bucket — timeline Parquet from previous
#    runs already has correct accumulated counts per hour.
# ---------------------------------------------------------------------------
print("\n>>> Building and loading threat_timeline...")
timeline_ok = False

try:
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

    # read checkpoint_batch from HDFS to only process new logs
    last_ts = None
    try:
        cp_df = spark.read.text(CHECKPOINT_BATCH)
        raw = "\n".join(r.value for r in cp_df.collect())
        cp = json.loads(raw)
        raw_ts = cp.get("last_ingested_timestamp")
        if raw_ts:
            last_ts = raw_ts
            print(f"  Checkpoint found: processing logs after {last_ts}")
    except Exception:
        print("  No checkpoint_batch found — processing all logs.")

    df = spark.read \
        .option("header", "true") \
        .schema(SCHEMA) \
        .csv(HDFS_LOGS)

    df = df.withColumn(
        "ts",
        F.coalesce(
            F.to_timestamp("timestamp", "yyyy-MM-dd'T'HH:mm:ss"),
            F.to_timestamp("timestamp", "yyyy-MM-dd HH:mm:ss"),
        )
    ).filter(F.col("ts").isNotNull())

    # apply checkpoint filter — only new logs
    if last_ts:
        df = df.filter(F.col("ts") > F.lit(last_ts).cast("timestamp"))

    df = df.withColumn(
        "hour_bucket",
        F.date_format("ts", "yyyy-MM-dd-HH"),
    )

    # aggregate new logs by hour
    new_timeline = df.groupBy("hour_bucket").agg(
        F.sum(F.when(F.col("threat_label") == "malicious",  1).otherwise(0)).alias("malicious"),
        F.sum(F.when(F.col("threat_label") == "suspicious", 1).otherwise(0)).alias("suspicious"),
        F.sum(F.when(F.col("threat_label") == "benign",     1).otherwise(0)).alias("benign"),
        F.count("*").alias("total"),
    ).orderBy("hour_bucket")

    # merge with existing timeline Parquet so hour buckets accumulate
    import subprocess
    existing_check = subprocess.run(
        f"hdfs dfs -test -e {HDFS_BASE}/threat_timeline", shell=True
    )

    if existing_check.returncode == 0:
        print("  Merging with existing threat_timeline...")
        existing_timeline = spark.read.parquet(f"{HDFS_BASE}/threat_timeline")
        timeline = existing_timeline.unionByName(new_timeline) \
            .groupBy("hour_bucket").agg(
                F.sum("malicious").alias("malicious"),
                F.sum("suspicious").alias("suspicious"),
                F.sum("benign").alias("benign"),
                F.sum("total").alias("total"),
            ).orderBy("hour_bucket")
    else:
        print("  No existing timeline — using new data only.")
        timeline = new_timeline

    rows = timeline.collect()
    print(f"  Hour buckets: {len(rows)}")

    table = conn.table("threat_timeline")
    batch = table.batch()

    for row in rows:
        row_key = to_bytes(row["hour_bucket"])
        update_latest(row["hour_bucket"])

        # write the correctly merged value directly
        batch.put(row_key, {
            b"cf:malicious":  to_bytes(row["malicious"]),
            b"cf:suspicious": to_bytes(row["suspicious"]),
            b"cf:benign":     to_bytes(row["benign"]),
            b"cf:total":      to_bytes(row["total"]),
        })

    batch.send()
    print(f"  Done — {len(rows)} rows written to threat_timeline")

    # save updated timeline Parquet for next run merge + dashboard queries
    timeline.write \
        .mode("overwrite") \
        .parquet(f"{HDFS_BASE}/threat_timeline")
    print(f"  Also saved to HDFS: {HDFS_BASE}/threat_timeline")
    timeline_ok = True

except Exception as e:
    print(f"  Failed: {e}")

# ---------------------------------------------------------------------------
# 8. Verification — scan first 3 rows of each table
# ---------------------------------------------------------------------------
print("\n>>> Verifying HBase tables...")

for table_name in ["ip_reputation", "attack_patterns", "threat_timeline"]:
    print(f"\n  [{table_name}]")
    try:
        table = conn.table(table_name)
        count = 0
        for key, data in table.scan():
            print(f"    key={key.decode()}  columns={len(data)}")
            count += 1
            if count >= 3:
                break
        if count == 0:
            print("    Table is empty — check the steps above for errors.")
    except Exception as e:
        print(f"    Could not scan {table_name}: {e}")

conn.close()

# ---------------------------------------------------------------------------
# 9. Update checkpoint
#    Only update if ALL three tables loaded successfully.
#    If any step failed -> checkpoint stays at old value -> next run
#    reprocesses the same data safely without skipping anything.
# ---------------------------------------------------------------------------
print("\n>>> Updating checkpoint...")

if ip_rep_ok and atk_ok and timeline_ok:
    if latest_ts:
        try:
            checkpoint = {
                "last_ingested_timestamp": latest_ts,
                "last_run_timestamp": datetime.now().isoformat(),
                "updated_by": "hbase_loader.py"
            }
            json_str = json.dumps(checkpoint, indent=2)
            jvm  = spark.sparkContext._jvm
            conf = spark.sparkContext._jsc.hadoopConfiguration()
            fs   = jvm.org.apache.hadoop.fs.FileSystem.get(conf)
            path = jvm.org.apache.hadoop.fs.Path(CHECKPOINT_BATCH)
            out  = fs.create(path, True)
            out.write(bytearray(json_str.encode("utf-8")))
            out.close()
            print(f"  checkpoint_batch updated to: {latest_ts}")
            print(f"  Next run will process logs after: {latest_ts}")
        except Exception as e:
            print(f"  WARNING: checkpoint write failed: {e}")
    else:
        print("  WARNING: No timestamp found in results — checkpoint not updated.")
else:
    print("  WARNING: One or more tables failed.")
    print("  Checkpoint NOT updated — next run will reprocess the same data.")

spark.stop()
print("\n>>> HBase loader complete.")
