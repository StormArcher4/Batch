#!/usr/bin/env bash
# =============================================================
# BATCH LAYER — MASTER RUN GUIDE
# =============================================================
# Run this INSIDE hadoop-master container:
#   docker exec -it hadoop-master bash
# =============================================================


# ─────────────────────────────────────────────────────────────
# ENVIRONMENT PREP  (do this once before anything else)
# ─────────────────────────────────────────────────────────────

# 1. Start Hadoop
./start-hadoop.sh

# 2. Verify HDFS is up
hdfs dfsadmin -report | head -20

# 3. Copy your CSV into the container (run from your HOST machine)
#    docker cp cybersecurity_threat_detection_logs.csv hadoop-master:/home/

# 4. Install Python dependency for HBase loader
pip3 install happybase

# 5. Start HBase + Thrift server (needed for hbase_loader.py)
start-hbase.sh
hbase thrift start &
#   Wait ~10 seconds, then verify port 9090 is listening:
#   netstat -tlnp | grep 9090


# ─────────────────────────────────────────────────────────────
# EXECUTION ORDER — run scripts in this exact sequence
# ─────────────────────────────────────────────────────────────

# STEP 0 — Copy scripts into container (from HOST)
# docker cp prepare_hdfs_folders.py  hadoop-master:/home/
# docker cp analysis1_top_ips.py     hadoop-master:/home/
# docker cp analysis2_threat_volume.py hadoop-master:/home/
# docker cp analysis3_attack_patterns.py hadoop-master:/home/
# docker cp analysis4_port_scans.py  hadoop-master:/home/
# docker cp hbase_loader.py          hadoop-master:/home/

# STEP 1 — Partition CSV and upload to HDFS
python3 /home/prepare_hdfs_folders.py

# Quick check — should see year= folders:
hdfs dfs -ls /data/cybersecurity/logs/

# STEP 2 — Run the 4 Spark analyses (order doesn't matter)
spark-submit --master local[*] /home/analysis1_top_ips.py
spark-submit --master local[*] /home/analysis2_threat_volume.py
spark-submit --master local[*] /home/analysis3_attack_patterns.py
spark-submit --master local[*] /home/analysis4_port_scans.py

# Quick check — all 4 folders should exist:
hdfs dfs -ls /data/cybersecurity/batch/

# STEP 3 — Load everything into HBase
spark-submit --master local[*] /home/hbase_loader.py

# Quick HBase verify:
hbase shell <<EOF
list
count 'ip_reputation'
count 'attack_patterns'
count 'threat_timeline'
scan 'ip_reputation', {LIMIT => 3}
EOF


# ─────────────────────────────────────────────────────────────
# QUICK TROUBLESHOOTING
# ─────────────────────────────────────────────────────────────

# Problem: "No records loaded" in any analysis script
# → Check prepare step ran and files exist:
#   hdfs dfs -ls -R /data/cybersecurity/logs | grep logs.csv

# Problem: HBase Thrift connection refused
# → Port 9090 not open → run:  hbase thrift start &

# Problem: happybase not found
# → pip3 install happybase

# Problem: Spark "java.io.IOException: No FileSystem for scheme"
# → HDFS not started → ./start-hadoop.sh
