Security Event Analyzer
Python
Pandas
License

Overview
- A Python-based security analysis tool that processes system event data (processes, network, files, and registry) to detect malicious activity patterns. The tool:
- Cleans and normalizes raw security event data
- Identifies process relationships and anomalies
- Generates detailed reports on suspicious activity
- Creates a unified event timeline

Features
Data Processing Pipeline

- Handles missing/corrupted data
- Standardizes timestamps and paths
- Detects process cycles and orphaned processes
- Analysis Capabilities
- Process tree visualization
Event correlation by process ID

Malicious pattern detection

Reporting

Markdown reports with process hierarchies

Associated event timelines

Data quality documentation

- File Structure
security-analyzer/
├── datasets/                  
│   ├── process_events.csv
│   ├── network_events.csv
│   ├── file_events.csv
│   └── registry_events.csv
├── src/
│   ├── security_analyzer.py   # Main analysis script
│   └── tests/                 # Unit tests
│       └── test_security_analyzer.py
├── data/                      # Generated outputs
│   └── unified_events.csv
├── reports/                   # Analysis reports
│   └── process_tree_*.md
├── requirements.txt           # Dependencies
└── README.md

Quick Start
1. Installation
bash
Copy
# Clone repository
git clone {repository}
cd security-analyzer

# Create virtual environment (recommended)
`python -m venv venv`
`source venv/bin/activate`  
`venv\Scripts\activate`     

# Install dependencies
`pip install -r requirements.txt`

2. Prepare Data
Place the CSV files in the datasets/ folder:
process_events.csv
network_events.csv
file_events.csv
registry_events.csv

3. Run Analysis
bash
Copy
# Basic analysis (default PID 15150)
`python src/security_analyzer.py --data-dir datasets`

# Analyze specific process ID
`python src/security_analyzer.py --data-dir datasets --pid 4022`

4. View Results
Outputs will be generated in:

data/unified_events.csv - Consolidated event data

reports/process_tree_[PID].md - Detailed analysis report

Advanced Usage
Run Tests
bash
Copy
# Run all tests
`python -m pytest src/tests/ -v`

# Run tests with coverage report
`python -m pytest src/tests/ --cov=src`

Custom Configuration
Modify these parameters in security_analyzer.py:

MAX_RECURSION_DEPTH - Controls process tree depth (default: 5)

TIME_FORMAT - Change datetime formatting

Example Report
markdown
Copy
# Process Tree Analysis for Malicious Process 15150

- Process ID: 15150
  - Executable: C:/Users/Admin/Downloads/image_resizer.exe
  - User: admin
  - Start Time: 2025-03-01 09:00:21
  - Children:
    - Process ID: 15151
      - Executable: C:/Users/Admin/AppData/Local/Temp/system_update.exe
      - User: admin
      - Start Time: 2025-03-01 09:00:41

## Associated Events

- file event at 2025-03-01 09:00:22
  - File: C:/Users/Admin/AppData/Local/Temp/system_update.exe
  - Operation: write

- registry event at 2025-03-01 09:01:30
  - Registry Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  - Operation: create
  - Value Name: MaliciousApp
  - Value Data: C:/Users/Admin/notepad.exe
Troubleshooting
Common Issues:

Missing Data Files

Verify CSV files exist in datasets/

Check filenames are exact matches

Permission Errors

Run as administrator if needed

Ensure output directories are writable

Test Failures

Run with --pdb flag to debug:

bash
Copy
`python -m pytest src/tests/ -v --pdb`