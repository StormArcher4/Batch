# Batch Layer — Cybersecurity Threat Detection

## Pipeline Overview

```
kafka_to_hdfs.py
    → creates checkpoint_ingest.json + checkpoint_batch.json on HDFS (first run only)
    → reads last_offset from checkpoint_ingest.json
    → pulls only NEW messages from Kafka (offset-based, no duplicates)
    → writes raw logs to HDFS partitioned by date
    → updates checkpoint_ingest.json with max offset

analysis1_top_ips.py
analysis2_threat_volume.py
analysis3_attack_patterns.py        (run in any order or in parallel)
analysis4_port_scans.py
    → each reads last_ingested_timestamp from checkpoint_batch.json (HDFS)
    → filters HDFS logs to only new data
    → merges with existing Parquet results (no double counting)
    → saves merged results back to HDFS as Parquet

hbase_loader.py
    → reads merged Parquet outputs from analysis scripts
    → writes results into 3 HBase tables
    → builds threat_timeline from raw logs
    → updates checkpoint_batch.json with latest timestamp processed
```

---

## Run Order

```bash
# 1. Ingest new Kafka messages to HDFS
python3 /home/kafka_to_hdfs.py

# 2. Run analyses (order doesn't matter between them)
spark-submit --master local[*] /home/analysis1_top_ips.py
spark-submit --master local[*] /home/analysis2_threat_volume.py
spark-submit --master local[*] /home/analysis3_attack_patterns.py
spark-submit --master local[*] /home/analysis4_port_scans.py

# 3. Load into HBase and update checkpoint
spark-submit --master local[*] /home/hbase_loader.py
```

**kafka_to_hdfs must run first. hbase_loader must run last.**

---

## Checkpoints (both on HDFS)

| File | Path | Owner | Tracks |
|------|------|-------|--------|
| `checkpoint_ingest.json` | `hdfs:///data/cybersecurity/checkpoint_ingest.json` | `kafka_to_hdfs.py` | Last Kafka offset processed |
| `checkpoint_batch.json` | `hdfs:///data/cybersecurity/checkpoint_batch.json` | `hbase_loader.py` | Last timestamp fully loaded into HBase |

- Both files are **created automatically** by `kafka_to_hdfs.py` on first run
- If `hbase_loader` fails → `checkpoint_batch` is NOT updated → next run safely reprocesses same data
- Kafka skipping is **offset-based** (not timestamp) → guaranteed no duplicates or gaps

---

## HDFS Structure

| Path | Content | Written by |
|------|---------|------------|
| `/data/cybersecurity/logs/year=.../month=.../day=.../` | Raw partitioned logs (CSV) | `kafka_to_hdfs.py` |
| `/data/cybersecurity/batch/top_malicious_ips` | Top 10 malicious IPs (Parquet) | `analysis1` |
| `/data/cybersecurity/batch/threat_volume` | Bytes per threat label (Parquet) | `analysis2` |
| `/data/cybersecurity/batch/threat_volume_by_protocol` | Bytes per label+protocol (Parquet) | `analysis2` |
| `/data/cybersecurity/batch/attack_patterns` | Attack pattern counts (Parquet) | `analysis3` |
| `/data/cybersecurity/batch/port_scans` | Port scan events (Parquet) | `analysis4` |
| `/data/cybersecurity/batch/threat_timeline` | Hourly threat counts (Parquet) | `hbase_loader` |
| `/data/cybersecurity/checkpoint_ingest.json` | Kafka offset checkpoint | `kafka_to_hdfs.py` |
| `/data/cybersecurity/checkpoint_batch.json` | Batch processing checkpoint | `hbase_loader.py` |

---

## HBase Tables

| Table | Row Key | Purpose |
|-------|---------|---------|
| `ip_reputation` | `source_ip` | Threat score + history per attacker IP |
| `attack_patterns` | `attack_type#source_ip` | Top offending IPs per attack type |
| `threat_timeline` | `YYYY-MM-DD-HH` | Hourly evolution of threats |

---

## Analysis Scripts Summary

| Script | What it detects | Output |
|--------|----------------|--------|
| `analysis1_top_ips.py` | Top 10 malicious IPs by weighted score `(malicious×2 + suspicious)` | `top_malicious_ips` Parquet |
| `analysis2_threat_volume.py` | Bytes transferred per threat label + protocol | `threat_volume` + `threat_volume_by_protocol` Parquet |
| `analysis3_attack_patterns.py` | SQLi, XSS, Path Traversal, Tool-based attacks in request_path/user_agent | `attack_patterns` Parquet |
| `analysis4_port_scans.py` | IPs hitting 5+ distinct dest IPs in 5-min TCP windows | `port_scans` Parquet |

---

## Prerequisites

```bash
# Inside hadoop-master container
pip3 install happybase kafka-python pyspark

# Services that must be running
./start-hadoop.sh
start-hbase.sh
hbase thrift start &
./start-kafka-zookeeper.sh
```

---

## Automated Runs (every 10 minutes)

```bash
crontab -e
# add:
*/10 * * * * /home/RUN_BATCH.sh >> /home/batch_run.log 2>&1
```

`RUN_BATCH.sh` should run the scripts in the order shown above.
