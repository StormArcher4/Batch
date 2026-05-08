# kafka_to_hdfs.py
from pyspark.sql import SparkSession
import pyspark.sql.functions as func
from pyspark.sql.types import StructType, StructField, StringType
import time
import json
from datetime import datetime
import global_vars as glob

# schema
log_schema = StructType(
    [
        StructField("timestamp",         StringType()),
        StructField("source_ip",         StringType()),
        StructField("dest_ip",           StringType()),
        StructField("protocol",          StringType()),
        StructField("action",            StringType()),
        StructField("threat_label",      StringType()),
        StructField("log_type",          StringType()),
        StructField("bytes_transferred", StringType()),
        StructField("user_agent",        StringType()),
        StructField("request_path",      StringType()),
    ]
)

# ---------------------------------------------------------------------------
# Checkpoint paths (both on HDFS)
# ---------------------------------------------------------------------------
CHECKPOINT_INGEST = "hdfs:///data/cybersecurity/checkpoint_ingest.json"
CHECKPOINT_BATCH  = "hdfs:///data/cybersecurity/checkpoint_batch.json"
HDFS_BASE         = "hdfs://hadoop-master:9000/data/cybersecurity/logs"

# ---------------------------------------------------------------------------
# Spark session
# ---------------------------------------------------------------------------
spark_session = (
    SparkSession.builder.appName("kafka_to_hdfs")
    .config("spark.sql.shuffle.partitions", "2")
    .config("spark.ui.enabled", "false")
    .getOrCreate()
)
spark_session.sparkContext.setLogLevel("ERROR")


# ---------------------------------------------------------------------------
# HDFS helpers
# ---------------------------------------------------------------------------
def hdfs_file_exists(path: str) -> bool:
    try:
        jvm  = spark_session.sparkContext._jvm
        conf = spark_session.sparkContext._jsc.hadoopConfiguration()
        fs   = jvm.org.apache.hadoop.fs.FileSystem.get(conf)
        return fs.exists(jvm.org.apache.hadoop.fs.Path(path))
    except Exception:
        return False


def hdfs_write_json(path: str, data: dict):
    jvm  = spark_session.sparkContext._jvm
    conf = spark_session.sparkContext._jsc.hadoopConfiguration()
    fs   = jvm.org.apache.hadoop.fs.FileSystem.get(conf)
    out  = fs.create(jvm.org.apache.hadoop.fs.Path(path), True)
    out.write(bytearray(json.dumps(data, indent=2).encode("utf-8")))
    out.close()


def create_checkpoints_if_missing():
    """Creates both checkpoint files on HDFS if they don't exist yet."""
    if not hdfs_file_exists(CHECKPOINT_INGEST):
        print("  Creating checkpoint_ingest.json on HDFS...")
        hdfs_write_json(CHECKPOINT_INGEST, {
            "last_offset":        -1,
            "updated_by":         None,
            "last_run_timestamp": None,
            "rows_ingested":      0,
        })
        print("  ✓ checkpoint_ingest.json created")
    else:
        print("  checkpoint_ingest.json already exists")

    if not hdfs_file_exists(CHECKPOINT_BATCH):
        print("  Creating checkpoint_batch.json on HDFS...")
        hdfs_write_json(CHECKPOINT_BATCH, {
            "last_ingested_timestamp": None,
            "updated_by":              None,
            "last_run_timestamp":      None,
        })
        print("  ✓ checkpoint_batch.json created")
    else:
        print("  checkpoint_batch.json already exists")


def read_checkpoint() -> int:
    """Returns last processed offset, or -1 if no checkpoint exists."""
    try:
        df = spark_session.read.text(CHECKPOINT_INGEST)
        raw = "\n".join(r.value for r in df.collect())
        cp = json.loads(raw)
        offset = cp.get("last_offset", -1)
        if offset is None:
            return -1
        return int(offset)
    except Exception:
        return -1


def write_checkpoint(last_offset: int, rows: int):
    try:
        hdfs_write_json(CHECKPOINT_INGEST, {
            "last_offset":        last_offset,
            "updated_by":         "kafka_to_hdfs",
            "last_run_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "rows_ingested":      rows,
        })
        print(f"  Checkpoint written: last_offset={last_offset}, rows={rows}")
    except Exception as e:
        print(f"  WARN: checkpoint write failed: {e}")


# ---------------------------------------------------------------------------
# Ensure both checkpoints exist on HDFS (first run only)
# ---------------------------------------------------------------------------
print("\n>>> Checking checkpoints...")
create_checkpoints_if_missing()

# ---------------------------------------------------------------------------
# Read last offset
# ---------------------------------------------------------------------------
last_offset = read_checkpoint()
print(f"\n  Last processed offset: {last_offset}")

# ---------------------------------------------------------------------------
# Build startingOffsets JSON for Kafka
# offset -1 means never ran -> read from earliest
# otherwise start from last_offset + 1
# ---------------------------------------------------------------------------
if last_offset == -1:
    starting_offsets = "earliest"
    print("  First run — reading from earliest offset.")
else:
    # Kafka startingOffsets expects JSON: {"topic": {"partition": offset}}
    # We start from last_offset + 1 to skip already processed messages
    starting_offsets = json.dumps({
        glob.TOPIC: {"0": last_offset + 1}
    })
    print(f"  Resuming from offset {last_offset + 1}")

# ---------------------------------------------------------------------------
# Read from Kafka
# ---------------------------------------------------------------------------
raw_data_frame = (
    spark_session.read.format("kafka")
    .option("kafka.bootstrap.servers", glob.BOOTSTRAP_SERVERS)
    .option("subscribe",               glob.TOPIC)
    .option("startingOffsets",         starting_offsets)
    .option("endingOffsets",           "latest")
    .option("kafka.group.id",          "hdfs-batch-ingester")
    .option("failOnDataLoss",          "false")
    .load()
)

total_raw = raw_data_frame.count()
print(f"  New Kafka messages: {total_raw:,}")

if total_raw == 0:
    print("\n  ✅ No new messages since last offset. Nothing to write.")
    spark_session.stop()
    exit(0)

# ---------------------------------------------------------------------------
# Parse messages
# ---------------------------------------------------------------------------
data_frame = (
    raw_data_frame
    .select(
        func.col("offset"),                                     # keep offset for checkpoint
        func.col("value").cast("string").alias("log_fragment")
    )
    .filter(func.col("log_fragment").isNotNull())
    .select(
        func.col("offset"),
        func.from_json(func.col("log_fragment"), log_schema).alias("threat_log")
    )
    .select("offset", "threat_log.*")
    .filter(func.col("timestamp").isNotNull())
    .withColumn(
        "timestamp_clean",
        func.regexp_replace(func.col("timestamp"), "[^0-9-T:]", "")
    )
    .withColumn(
        "timestamp",
        func.to_timestamp(func.col("timestamp_clean"), "yyyy-MM-dd'T'HH:mm:ss"),
    )
    .drop("timestamp_clean")
    .filter(func.col("timestamp").isNotNull())
    .withColumn("year",  func.year("timestamp"))
    .withColumn("month", func.month("timestamp"))
    .withColumn("day",   func.dayofmonth("timestamp"))
)

data_frame.cache()

row_count = data_frame.count()
print(f"  Rows after parsing : {row_count:,}")

if row_count == 0:
    print("\n  ✅ No valid rows after parsing. Nothing to write.")
    data_frame.unpersist()
    spark_session.stop()
    exit(0)

# ---------------------------------------------------------------------------
# Show sample + partition breakdown
# ---------------------------------------------------------------------------
print("\n--- Sample of received data ---")
data_frame.select("timestamp", "source_ip", "action", "request_path").show(3, truncate=False)

print("\n--- Partition breakdown ---")
data_frame.groupBy("year", "month", "day").count().orderBy("year", "month", "day").show(50, truncate=False)

# ---------------------------------------------------------------------------
# Write to HDFS partitioned by date
# ---------------------------------------------------------------------------
t_write = time.time()
try:
    (
        data_frame
        .drop("offset")                                         # don't store offset in HDFS files
        .write.mode("append")
        .partitionBy("year", "month", "day")
        .option("header", "true")
        .csv(HDFS_BASE)
    )
    write_elapsed = time.time() - t_write
    print(f"\n  Write time : {write_elapsed:.4f}s")
    print(f"  HDFS path  : {HDFS_BASE}")
    print(f"  ✓ Written successfully")
except Exception as e:
    print(f"\n  ✗ WRITE FAILED: {e}")
    data_frame.unpersist()
    spark_session.stop()
    exit(1)

# ---------------------------------------------------------------------------
# Update checkpoint with max offset seen in this batch
# ---------------------------------------------------------------------------
max_offset = data_frame.agg(func.max("offset").alias("max_offset")).collect()[0]["max_offset"]
write_checkpoint(int(max_offset), row_count)

data_frame.unpersist()
spark_session.stop()
print("\nDone! Next step → run analysis scripts then hbase_loader.py")
