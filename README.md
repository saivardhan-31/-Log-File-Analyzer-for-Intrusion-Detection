# Log File Analyzer for Intrusion Detection

## Overview
This Python project analyzes server log files (Apache and SSH) to detect suspicious activity such as brute-force login attempts, scanning, and potential DoS attacks. It also visualizes top IPs and checks against known blacklisted IPs.

## Features
- Parses Apache access logs and SSH authentication logs
- Detects brute-force attacks and DoS/scanning attempts
- Visualizes top IPs by request count
- Cross-references detected IPs against a blacklist
- Exports incident reports (CSV) and visualization charts

## Tools Used
- Python
- Pandas
- Matplotlib
- Regex
- Requests (for fetching blacklists)

## How to Run
1. Clone the repository:
   ```bash
   git clone https://github.com/saivardhan-31/-Log-File-Analyzer-for-Intrusion-Detection.git
##Navigate to the project folder:

cd log_analyzer


##Install dependencies:

pip install pandas matplotlib requests


##Run the analyzer:

python analyzer.py
