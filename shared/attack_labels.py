# shared/attack_labels.py
# All canonical attack labels used across the system.

CICIDS2017_LABELS = [
    "BENIGN",
    "DDoS",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "PortScan",
    "FTP-Patator",
    "SSH-Patator",
    "Bot",
    "Web Attack-Brute Force",
    "Web Attack-XSS",
    "Web Attack-SQL Injection",
    "Infiltration",
    "Heartbleed",
    "UNKNOWN_MALICIOUS",
]

# Map label → severity for alert generation
LABEL_SEVERITY_MAP = {
    "BENIGN":                   None,          # no alert
    # DDoS / DoS
    "DDoS":                     "CRITICAL",
    "DoS Hulk":                 "HIGH",
    "DoS GoldenEye":            "HIGH",
    "DoS slowloris":            "HIGH",
    "DoS Slowhttptest":         "HIGH",
    # Scanning
    "PortScan":                 "MEDIUM",
    # Brute force
    "FTP-Patator":              "MEDIUM",
    "SSH-Patator":              "MEDIUM",
    # Web attacks
    "Web Attack-Brute Force":   "HIGH",
    "Web Attack-XSS":           "MEDIUM",
    "Web Attack-SQL Injection":  "CRITICAL",
    # Advanced
    "Bot":                      "CRITICAL",
    "Infiltration":             "CRITICAL",
    "Heartbleed":               "CRITICAL",
    # Unknown — always treated as a real alert
    "UNKNOWN_MALICIOUS":        "HIGH",
}
