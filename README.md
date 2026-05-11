# 🛡️ Threat Detector — Batch Layer

> **Lambda Architecture · Batch Processing Pipeline**
> Ingests raw network logs from Kafka, archives them to HDFS, runs four deep-analysis Spark jobs, and loads historical threat intelligence into HBase — giving the system its long-term memory.

---

## Architecture Overview

```
[Kafka Topic: threat_scan]
          │
          ▼
 ┌─────────────────────┐
 │   kafka_to_hdfs.py  │   Consumes raw logs from Kafka
 │   (Spark Batch)     │   Archives to HDFS partitioned by date
 └─────────┬───────────┘
           │  writes
           ▼
   HDFS: /data/cybersecurity/logs/
       year=YYYY/month=MM/day=DD/logs.csv
           │
           │  checkpoint.json tracks last ingested timestamp
           │  → incremental runs skip already-processed data
           │
  ┌────────┴────────────────────────────────────┐
  │              Spark Batch Analyses            │
  ├──────────────────────────────────────────────┤
  │  analysis1_top_ips.py      → Top 10 malicious source IPs          │
  │  analysis2_threat_volume.py → Bytes transferred per threat type   │
  │  analysis3_attack_patterns.py → SQLi / XSS / Path Traversal / Tools │
  │  analysis4_port_scans.py   → Port scan detection (5-min windows)  │
  └────────┬────────────────────────────────────┘
           │  Parquet results
           ▼
   HDFS: /data/cybersecurity/batch/
       top_malicious_ips/
       threat_volume/
       threat_volume_by_protocol/
       attack_patterns/
       port_scans/
       threat_timeline/
           │
           ▼
 ┌─────────────────────┐
 │   hbase_loader.py   │   Reads Parquet → loads HBase tables
 └─────────┬───────────┘
           │
           ▼
      HBase Tables
  ┌─────────────────────────────────────────────┐
  │  ip_reputation    │ Threat score per IP      │
  │  attack_patterns  │ Top offending IPs by type│
  │  threat_timeline  │ Hourly threat counts      │
  └─────────────────────────────────────────────┘
```

---

## Project Structure

```
batch/
├── kafka_to_hdfs.py             # Step 1 — Kafka consumer → HDFS archival
├── analysis1_top_ips.py         # Step 2a — Top 10 malicious source IPs
├── analysis2_threat_volume.py   # Step 2b — Bytes transferred per threat label
├── analysis3_attack_patterns.py # Step 2c — SQLi / XSS / traversal / tool detection
├── analysis4_port_scans.py      # Step 2d — Port scan detection via time windows
├── hbase_loader.py              # Step 3 — Load Parquet results into HBase
└── checkpoint.json              # Runtime — tracks last processed timestamp
```

---

## What Each Script Does

### `kafka_to_hdfs.py` — Log Archival
Consumes messages from the `threat_scan` Kafka topic using Spark Structured Streaming and writes them to HDFS partitioned by date:
```
/data/cybersecurity/logs/year=2024/month=05/day=15/logs.csv
```
- Writes a `checkpoint.json` after each micro-batch so reruns never reprocess the same data
- Handles the `2024-03-26T00:00:00.000Z` ISO 8601 timestamp format from the dataset
- Runs until manually stopped (continuous ingestion mode)

---

### `analysis1_top_ips.py` — Top 10 Malicious IPs
Reads logs from HDFS, filters `suspicious` and `malicious` events, and ranks source IPs by a weighted threat score:

```
threat_score = (malicious_count × 2) + suspicious_count
```

Malicious events are weighted double because they represent confirmed attacks vs. suspicious activity.

**Output:** Top 10 IPs with score, event count, last seen timestamp, and protocol.

---

### `analysis2_threat_volume.py` — Data Volume Analysis
Correlates `bytes_transferred` with `threat_label` to understand how much data each threat category moves through the network.

Produces two aggregations:
- Per `threat_label`: total, average, max, min, and 95th-percentile bytes
- Per `threat_label + protocol`: breakdown of which protocols carry the most traffic per threat type

**Why p95?** The maximum alone can be a one-off outlier — the 95th percentile gives a better picture of typical heavy transfers.

---

### `analysis3_attack_patterns.py` — Attack Signature Detection
Scans `request_path` and `user_agent` fields against regex signatures to detect known web attack types:

| Attack Type | Detection Method | Severity |
|---|---|---|
| SQL Injection | SQL keywords, tautologies, comment sequences in request path | Critical |
| XSS | `<script>` tags, `javascript:`, event handlers in request path | High |
| Path Traversal | `../`, `..%2f`, double-encoded variants in request path | High |
| Tool-Based Attack | Known tool signatures in user-agent (`sqlmap`, `nikto`, `gobuster`, `nmap`) | Medium |

Priority order matters: a request matching both SQLi and XSS is labelled `SQL_INJECTION` (more severe). Rows matching no pattern are silently dropped.

**Output:** Top offending IPs per attack type with hit count, severity, last seen, and sample paths.

---

### `analysis4_port_scans.py` — Port Scan Detection
Uses Spark's `window()` function to detect reconnaissance behaviour: source IPs that connect to **5 or more distinct destination IPs within any 5-minute tumbling window**.

```
source_ip → [dest1, dest2, dest3, dest4, dest5] within 5 minutes → FLAGGED
```

> **Note on the dataset:** The CSV has no separate port column, so `distinct dest_ip` is used as the scan indicator. This still correctly flags wide-net reconnaissance where an attacker probes multiple targets.

---

### `hbase_loader.py` — HBase Ingestion
Reads all Parquet outputs from the four analyses and loads them into three HBase tables designed for fast point lookups by the serving layer:

| Table | Row Key | Contents |
|---|---|---|
| `ip_reputation` | `source_ip` | Threat score, malicious/suspicious counts, last seen |
| `attack_patterns` | `attack_type#source_ip` | Hit count, severity, last seen (prefix scan by type) |
| `threat_timeline` | `YYYY-MM-DD-HH` | Malicious / suspicious / benign counts per hour |

The `attack_type#source_ip` composite key allows HBase range scans to efficiently retrieve all offenders for a given attack type (e.g. all `SQL_INJECTION#*` rows).

The `threat_timeline` table sorts chronologically because HBase rows are lexicographically ordered — `2024-01-01-00` always comes before `2024-12-31-23`.

---

## Checkpoint System

The batch layer uses a lightweight `checkpoint.json` to avoid reprocessing historical data on every run:

```json
{
  "last_ingested_timestamp": "2024-12-30T00:00:00.000000",
  "last_run_timestamp": "2026-05-11T20:14:45.123456",
  "updated_by": "analysis1_top_ips"
}
```

**How it works:**
1. `kafka_to_hdfs.py` writes the checkpoint after each HDFS flush
2. On the next run, each analysis script reads the checkpoint and determines which HDFS day folders to scan:
   - **Checkpoint day folder** (e.g. `day=15`): scanned with a row-level timestamp filter — only rows with `timestamp > last_ingested_timestamp` are kept. This correctly handles files from the same second (e.g. `22:02:45` vs `22:02:58`)
   - **New day folders** (e.g. `day=16`, `day=17`): fully scanned, no filter needed
3. Only `analysis1` updates the checkpoint after a successful run — the other analyses read it but never write it

---

## HBase Table Design

### `ip_reputation`
```
Row key: "192.168.1.45"
cf:threat_score     → "4"
cf:malicious_count  → "2"
cf:suspicious_count → "0"
cf:total_events     → "2"
cf:last_seen        → "2024-11-21 00:00:00"
cf:main_protocol    → "TCP"
cf:log_source       → "application"
```

### `attack_patterns`
```
Row key: "SQL_INJECTION#10.0.0.5"
cf:attack_type → "SQL_INJECTION"
cf:source_ip   → "10.0.0.5"
cf:hit_count   → "12"
cf:last_seen   → "2024-10-03 00:00:00"
cf:severity    → "critical"
```

### `threat_timeline`
```
Row key: "2024-05-15-14"
cf:malicious  → "18"
cf:suspicious → "42"
cf:benign     → "210"
cf:total      → "270"
```

---

## Prerequisites

- Docker + Docker Swarm
- Apache Hadoop 3.3.x (HDFS + YARN)
- Apache Kafka running on `hadoop-master:9092`
- Apache HBase 2.5.x with Thrift server running (`hbase thrift start`)
- Apache Spark 3.5.x (with YARN)
- Python 3.x + `happybase`, `pyspark`
- Cybersecurity log dataset: [Kaggle — cybersecurity-threat-detection-logs](https://www.kaggle.com/datasets/aryan208/cybersecurity-threat-detection-logs)

---

## Setup

### 1. Start the cluster
```bash
docker start hadoop-master hadoop-worker1 hadoop-worker2
docker exec -it hadoop-master bash
./start-hadoop.sh
./start-kafka-zookeeper.sh
/usr/local/hbase/bin/start-hbase.sh
hbase thrift start &
```

### 2. Create Kafka topic
```bash
/usr/local/kafka/bin/kafka-topics.sh \
  --create --topic threat_scan \
  --bootstrap-server localhost:9092 \
  --partitions 1 --replication-factor 1
```

### 3. Create HDFS structure
```bash
hdfs dfs -mkdir -p /data/cybersecurity/logs
```

---

## Running the Pipeline

Run each step in order and wait for it to finish before starting the next.

```bash
# Step 1 — Ingest Kafka messages into HDFS
spark-submit --master yarn \
  --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0 \
  kafka_to_hdfs.py

# Step 2 — Run all four analyses
spark-submit --master yarn \
  --conf spark.sql.legacy.timeParserPolicy=LEGACY \
  analysis1_top_ips.py

spark-submit --master yarn \
  --conf spark.sql.legacy.timeParserPolicy=LEGACY \
  analysis2_threat_volume.py

spark-submit --master yarn \
  --conf spark.sql.legacy.timeParserPolicy=LEGACY \
  analysis3_attack_patterns.py

spark-submit --master yarn \
  --conf spark.sql.legacy.timeParserPolicy=LEGACY \
  analysis4_port_scans.py

# Step 3 — Load results into HBase
spark-submit --master yarn \
  --conf spark.sql.legacy.timeParserPolicy=LEGACY \
  hbase_loader.py
```

> **Why `--conf spark.sql.legacy.timeParserPolicy=LEGACY`?**
> The dataset timestamps use ISO 8601 format with milliseconds and timezone (`2024-03-26T00:00:00.000Z`). Spark 3.x's new strict parser rejects the `Z` suffix — LEGACY mode restores the flexible pre-3.0 behaviour.

---

## Verifying Results

### Check HDFS
```bash
# Confirm day folders exist
hdfs dfs -ls -R /data/cybersecurity/logs/

# Check file sizes
hdfs dfs -du -h /data/cybersecurity/logs/

# Peek at raw data
hdfs dfs -cat /data/cybersecurity/logs/year=2024/month=05/day=15/logs.csv | head -5

# Check batch outputs exist
hdfs dfs -ls /data/cybersecurity/batch/
```

### Check checkpoint
```bash
cat /home/checkpoint.json
```

### Check HBase
```bash
/usr/local/hbase/bin/hbase shell <<EOF
count 'ip_reputation'
count 'attack_patterns'
count 'threat_timeline'
scan 'ip_reputation', {LIMIT => 3}
scan 'threat_timeline', {LIMIT => 5}
EOF
```

**Expected results with the full Kaggle dataset:**
| Table | Expected rows |
|---|---|
| `ip_reputation` | 10 |
| `attack_patterns` | up to 50 per attack type |
| `threat_timeline` | one row per hour in the dataset |

---

## Threat Score Formula

```
threat_score = (malicious_count × 2) + (suspicious_count × 1)
```

Malicious events are weighted double because they represent confirmed attacks, while suspicious events are anomalies that require further investigation. This weighted scoring ensures that an IP with two confirmed attacks ranks higher than one with four suspicious-only events.

---

## Integration with the Speed Layer

The HBase tables produced by this batch layer are the **historical backbone** of the Lambda Architecture. The Speed Layer (Kafka → Spark Streaming → Cassandra) handles real-time detection with low latency but limited history. A serving API merges both:

```
GET /threats/ip/192.168.1.45
→ {
    "historical_score":   4,          ← from HBase (batch layer)
    "active_threats":     [...],      ← from Cassandra (speed layer)
    "recommendation":     "BLOCK"
  }
```

The batch layer reprocesses the full history periodically to correct any errors the speed layer may have made under load — this is the core guarantee of the Lambda Architecture.

---

## Dataset

| Field | Description | Example |
|---|---|---|
| `timestamp` | Event datetime (ISO 8601) | `2024-03-26T00:00:00.000Z` |
| `source_ip` | Origin IP address | `192.168.1.45` |
| `dest_ip` | Destination IP address | `10.0.0.100` |
| `protocol` | Network protocol | `HTTP`, `TCP`, `SSH` |
| `action` | Firewall action | `allowed`, `blocked` |
| `threat_label` | Ground truth classification | `benign`, `suspicious`, `malicious` |
| `log_type` | Log source system | `firewall`, `ids`, `application` |
| `bytes_transferred` | Data volume in bytes | `1542` |
| `user_agent` | HTTP client identifier | `sqlmap/1.7`, `Mozilla/5.0` |
| `request_path` | HTTP request path | `/admin/login.php` |

Source: [Kaggle — Cybersecurity Threat Detection Logs](https://www.kaggle.com/datasets/aryan208/cybersecurity-threat-detection-logs)
