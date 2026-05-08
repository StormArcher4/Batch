# kafka_to_hdfs.py
from pyspark.sql import SparkSession
import pyspark.sql.functions as func
from pyspark.sql.types import StructType, StructField, StringType
import time
import json
from datetime import datetime
import global_vars as glob


# schema — same as consumer_stream_fixed.py
log_schema = StructType(
    [
        StructField("timestamp", StringType()),
        StructField("source_ip", StringType()),
        StructField("dest_ip", StringType()),
        StructField("protocol", StringType()),
        StructField("action", StringType()),
        StructField("threat_label", StringType()),
        StructField("log_type", StringType()),
        StructField("bytes_transferred", StringType()),
        StructField("user_agent", StringType()),
        StructField("request_path", StringType()),
    ]
)

# opening spark session
spark_session = (
    SparkSession.builder.appName("kafka_to_hdfs")
    .config("spark.sql.shuffle.partitions", "2")
    .config("spark.ui.enabled", "false")
    .getOrCreate()
)
spark_session.sparkContext.setLogLevel("ERROR")

CHECKPOINT_JSON = "hdfs:///data/cybersecurity/checkpoint.json"
HDFS_BASE = "hdfs://hadoop-master:9000/data/cybersecurity/logs"


def read_checkpoint() -> int:
    try:
        df = spark_session.read.text(CHECKPOINT_JSON)
        raw = "\n".join(r.value for r in df.collect())
        cp = json.loads(raw)
        offset = cp.get("last_offset", -1)
        return int(offset) if offset is not None else -1
    except Exception:
        return -1


def write_checkpoint(last_offset: int, rows: int):
    try:
        data = {
            "last_offset": last_offset,
            "updated_by": "kafka_to_hdfs",
            "last_run_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "rows_ingested": rows,
        }
        json_str = json.dumps(data)

        jvm = spark_session.sparkContext._jvm
        conf = spark_session.sparkContext._jsc.hadoopConfiguration()
        fs = jvm.org.apache.hadoop.fs.FileSystem.get(conf)
        path = jvm.org.apache.hadoop.fs.Path(CHECKPOINT_JSON)

        out = fs.create(path, True)
        out.write(bytearray(json_str.encode("utf-8")))
        out.close()

        print(f"  Checkpoint written: last_offset={last_offset}")
    except Exception as e:
        print(f"  WARN: checkpoint write failed: {e}")


last_offset = read_checkpoint()
print(f"\n  Last processed offset: {last_offset}")

# create checkpoint file on HDFS if it didn't exist
if last_offset == -1:
    write_checkpoint(-1, 0)


if last_offset == -1:
    starting_offsets = "earliest"
else:
    starting_offsets = json.dumps({glob.TOPIC: {"0": last_offset + 1}})

raw_data_frame = (
    spark_session.read.format("kafka")
    .option("kafka.bootstrap.servers", glob.BOOTSTRAP_SERVERS)
    .option("subscribe", glob.TOPIC)
    .option("startingOffsets", starting_offsets)
    .option("endingOffsets", "latest")
    .option("kafka.group.id", "hdfs-batch-ingester")
    .option("failOnDataLoss", "false")
    .load()
)

data_frame = (
    raw_data_frame.select(
        func.col("offset"),
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
        "timestamp_clean", func.regexp_replace(func.col("timestamp"), "[^0-9-T:]", "")
    )
    .withColumn(
        "timestamp",
        func.to_timestamp(func.col("timestamp_clean"), "yyyy-MM-dd'T'HH:mm:ss"),
    )
    .drop("timestamp_clean")
    .filter(func.col("timestamp").isNotNull())
    .withColumn("year", func.year("timestamp"))
    .withColumn("month", func.month("timestamp"))
    .withColumn("day", func.dayofmonth("timestamp"))
)

data_frame.cache()


def process_batch(batch_df, batch_id):
    if batch_df.isEmpty():
        print(f"[Batch {batch_id}] No new data after checkpoint filter.")
        return

    t_batch_start = time.time()
    row_count = batch_df.count()

    print(f"\n{'=' * 60}")
    print(f"  Batch ID        : {batch_id}")
    print(f"  Rows received   : {row_count}")
    print(f"{'=' * 60}")

    print("\n--- Sample of received data ---")
    batch_df.select("timestamp", "source_ip", "action", "request_path").show(
        3, truncate=False
    )

    print("\n--- Partition breakdown ---")
    batch_df.groupBy("year", "month", "day").count().orderBy(
        "year", "month", "day"
    ).show(50, truncate=False)

    t_write = time.time()
    try:
        batch_df.drop("offset").write.mode("append").partitionBy("year", "month", "day").option(
            "header", "true"
        ).csv(HDFS_BASE)
        write_elapsed = time.time() - t_write
        print(f"\n  Write time      : {write_elapsed:.4f}s")
        print(f"  HDFS path       : {HDFS_BASE}")
        print(f"  ✓ Written successfully")
    except Exception as e:
        print(f"\n  ✗ WRITE FAILED  : {e}")
        return

    t_cp = time.time()
    max_offset = batch_df.agg(func.max("offset").alias("max_offset")).collect()[0]["max_offset"]
    write_checkpoint(int(max_offset), row_count)
    cp_elapsed = time.time() - t_cp
    print(f"  Checkpoint time : {cp_elapsed:.4f}s")
    print(f"  Checkpoint → last_offset = {max_offset}")

    total_elapsed = time.time() - t_batch_start
    print(f"  Total batch time: {total_elapsed:.4f}s")
    print(f"{'─' * 60}\n")


total_raw = raw_data_frame.count()
print(f"  Raw Kafka messages  : {total_raw:,}")

if data_frame.count() == 0:
    print("\n  ✅ No new data since last checkpoint. Nothing to write.")
else:
    process_batch(data_frame, batch_id=0)

data_frame.unpersist()

print("\n  Next step → run spark_batch_analysis.py")
print(f"    It will read from offset > {last_offset}")
print("\nDone!")

spark_session.stop()
