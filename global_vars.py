BOOTSTRAP_SERVERS = "hadoop-master:9092"

TOPIC = "threat_scan"

CYBER_PACKETS = "cybersecurity_threat_detection_logs.csv"

BRUTE_FORCE_THRESHOLD = 5

SQL_INJECTION = "|".join(
    [
        r"(?i)(\bselect\b.*\bfrom\b)",
        r"(?i)(\binsert\b.*\binto\b)",
        r"(?i)(\bupdate\b.*\bset\b)",
        r"(?i)(\bdelete\b.*\bfrom\b)",
        r"(?i)(\bdrop\b.*\b(table|database)\b)",
        r"(?i)(\bcreate\b.*\b(table|database)\b)",
        r"(?i)(\balter\b.*\b(table|database)\b)",
        r"(?i)(\btruncate\b.*\b(table)\b)",
        r"(?i)(or\b.*=.*\b)",
        r"(?i)(and\b.*=.*\b)",
        r"(?i)(\b1\s*=\s*1\b)",
        r"(?i)(\b1\s*=\s*2\b)",
        r"(?i)(\btrue\b.*\b=true\b)",
        r"(?i)(\bfalse\b.*\b=false\b)",
        r"--+",
        r"/\*.*\*/",
        r"(?i)(\b#\b)",
    ]
)

XSS_PATTERNS = "|".join(
    [
        r"<script[^>]*>.*?</script>",
        r"<script[^>]*>",
        r"</script>",
        r"javascript:",
        r"vbscript:",
        r"data:text/html",
    ]
)

TOOLS = "|".join(
    [
        r"(?i)(sqlmap)",
        r"(?i)(sqlninja)",
        r"(?i)(sqldict)",
        r"(?i)(dirb)",
        r"(?i)(gobuster)",
        r"(?i)(nikto)",
        r"(?i)(nmap.*script)",
    ]
)

PATH_TRAVERSAL = "|".join(
    [
        r"\.\./",
        r"\.\.\\",
        r"\.\.%2f",
        r"\.\.%5c",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"\.\.%252f",
        r"\.\.%255c",
    ]
)

VOLUME_THRESHOLD = 10 * 1024 * 1024

METRICS = {"critical": 20, "high": 10, "medium": 5, "low": 2}

CASSANDRA_HOST = "cassandra"
CASSANDRA_KEYSPACE = "threat_detection"
CASSANDRA_TABLE_METADATA = "threats_metadata"
CASSANDRA_TABLE_LIVE_THREAT = "threats_now"
CASSANDRA_TABLE_COUNTERS = "threats_counters"
