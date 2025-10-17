import re
import pandas as pd

# -----------------------------
# Step 3: Parse Apache Log File
# -----------------------------

# Regular expression pattern for Apache logs
apache_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<date>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<size>\S+)'
)

def parse_apache_log(filepath):
    """Read and parse Apache log file into a DataFrame"""
    data = []
    with open(filepath, 'r') as file:
        for line in file:
            match = apache_pattern.search(line)
            if match:
                data.append(match.groupdict())
    return pd.DataFrame(data)

if __name__ == "__main__":
    df_apache = parse_apache_log("apache.log")
    print("=== Apache Log Parsed Data ===")
    print(df_apache.head())
# -----------------------------
# Step 4: Parse SSH Log File
# -----------------------------

# Regex pattern for SSH logs
ssh_pattern = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+sshd\[\d+\]:\s+(?P<message>.*)'
)

def parse_ssh_log(filepath):
    """Read and parse SSH log file into a DataFrame"""
    data = []
    with open(filepath, 'r') as file:
        for line in file:
            match = ssh_pattern.search(line)
            if match:
                data.append(match.groupdict())
    return pd.DataFrame(data)

# Test both parsers
if __name__ == "__main__":
    print("=== Apache Log Parsed Data ===")
    df_apache = parse_apache_log("apache.log")
    print(df_apache.head())

    print("\n=== SSH Log Parsed Data ===")
    df_ssh = parse_ssh_log("ssh.log")
    print(df_ssh.head())
# ====================================
# BRUTE-FORCE ATTACK DETECTION (SSH)
# ====================================

def detect_bruteforce(df):
    # Filter only "Failed password" entries
    failed = df[df['message'].str.contains("Failed password", case=False, na=False)]

    # Extract IP address from message text
    failed.loc[:, 'ip'] = failed['message'].str.extract(r'from (\d+\.\d+\.\d+\.\d+)')


    # Count how many times each IP failed
    brute_force = failed['ip'].value_counts()

    # Flag IPs with more than 3 failed attempts
    suspicious_ips = brute_force[brute_force >= 2]  # detect if 2 or more failed attempts


    print("\n=== Possible Brute-force Attempts ===")
    print(suspicious_ips)
    return suspicious_ips
# ====================================
# DOS ATTACK DETECTION (APACHE)
# ====================================

def detect_dos(df):
    # Count number of requests per IP
    ip_counts = df['ip'].value_counts()

    # Consider more than 3 requests in short time as suspicious (for demo)
    dos_ips = ip_counts[ip_counts >= 2]


    print("\n=== Possible DoS / Scanning Activity ===")
    print(dos_ips)
    return dos_ips
if __name__ == "__main__":
    print("=== Log File Analyzer ===")

    # Parse logs
    df_apache = parse_apache_log("apache.log")
    df_ssh = parse_ssh_log("ssh.log")

    # Detect threats
    brute_force_ips = detect_bruteforce(df_ssh)
    dos_ips = detect_dos(df_apache)

# ====================================
# VISUALIZATION SECTION
# ====================================
import matplotlib.pyplot as plt
import os

def plot_top_ips(df, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)

    top_ips = df['ip'].value_counts().head(5)
    plt.figure(figsize=(7,4))
    top_ips.plot(kind='bar')
    plt.title("Top 5 IPs by Request Count (Apache Logs)")
    plt.xlabel("IP Address")
    plt.ylabel("Number of Requests")
    plt.tight_layout()

    filepath = os.path.join(output_dir, "top_ips.png")
    plt.savefig(filepath)
    plt.close()
    print(f"[+] Visualization saved as {filepath}")

# ====================================
# BLACKLIST CHECKING
# ====================================
def check_blacklist(df, blacklist_file="blacklist.txt"):
    try:
        with open(blacklist_file, 'r') as f:
            blacklisted_ips = {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        print("⚠️ Blacklist file not found.")
        return pd.DataFrame()

    flagged = df[df['ip'].isin(blacklisted_ips)]

    if not flagged.empty:
        print("\n=== Blacklisted IPs Detected ===")
        print(flagged['ip'].unique())
    else:
        print("\nNo blacklisted IPs found.")
    return flagged
# ====================================
# EXPORT INCIDENT REPORT
# ====================================
def export_alerts(brute_force_ips, dos_ips, blacklist_hits, output_file="output/alerts.csv"):
    import os
    import pandas as pd
    os.makedirs("output", exist_ok=True)

    # Create a combined report
    data = []

    for ip, count in brute_force_ips.items():
        data.append({"Type": "Brute-force", "IP": ip, "Count": int(count)})

    for ip, count in dos_ips.items():
        data.append({"Type": "DoS / Scanning", "IP": ip, "Count": int(count)})

    for ip in blacklist_hits['ip'].unique() if not blacklist_hits.empty else []:
        data.append({"Type": "Blacklisted", "IP": ip, "Count": "N/A"})

    df = pd.DataFrame(data)
    df.to_csv(output_file, index=False)
    print(f"[+] Incident report exported to {output_file}")

if __name__ == "__main__":
    print("=== Log File Analyzer ===")

    # Parse logs
    df_apache = parse_apache_log("apache.log")
    df_ssh = parse_ssh_log("ssh.log")

    # Detect threats
    brute_force_ips = detect_bruteforce(df_ssh)
    dos_ips = detect_dos(df_apache)

    # Visualization
    plot_top_ips(df_apache)

    # Check blacklist
    flagged = check_blacklist(df_apache, "blacklist.txt")

    # Export report
    export_alerts(brute_force_ips, dos_ips, flagged)

