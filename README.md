***NHL-Scanner***
Overview
NHL-Scanner is a powerful, flexible, and easy-to-use web vulnerability scanner built in Python. It leverages predefined templates (signatures) to identify vulnerabilities in web applications. The tool is ideal for security researchers and penetration testers seeking to automate vulnerability detection.

With NHL-Scanner, you can:

Scan individual or multiple URLs for vulnerabilities.
Use specific templates or scan with all available templates in bulk.
Output results in color-coded terminal output and log them into an SQLite database.
Operate in a "Lite" mode for concise, match-only results.
Export detailed scan reports in HTML format for specific scan IDs or targets.

**Features**
Flexible Target Input:
Scan a single URL (-t) or multiple URLs from a file (-T).
Signature-Based Scanning:
Use specific signature files (-s) or scan with all available signatures (-S).

Lite Mode:
Output only matches for a cleaner, concise report (-L).
Database Logging:
Automatically logs all scan results into an SQLite database for future analysis.
Report Export:
Generate HTML reports by scan ID or target for easy sharing and documentation.

**Requirements**
Python 3.6+
Required Python Libraries:
requests
colorama
sqlite3 (Standard Python Library)
AND MORE...



Here’s the complete README file in plain text:

NHL-Scanner
Overview
NHL-Scanner is a powerful, flexible, and easy-to-use web vulnerability scanner built in Python. It leverages predefined templates (signatures) to identify vulnerabilities in web applications. The tool is ideal for security researchers and penetration testers seeking to automate vulnerability detection.

With NHL-Scanner, you can:

Scan individual or multiple URLs for vulnerabilities.
Use specific templates or scan with all available templates in bulk.
Output results in color-coded terminal output and log them into an SQLite database.
Operate in a "Lite" mode for concise, match-only results.
Export detailed scan reports in HTML format for specific scan IDs or targets.
Features
Flexible Target Input:
Scan a single URL (-t) or multiple URLs from a file (-T).
Signature-Based Scanning:
Use specific signature files (-s) or scan with all available signatures (-S).
Color-Coded Output:
Green: Vulnerabilities found (MATCH).
Yellow: No vulnerabilities found (NOT MATCH).
Red: Errors encountered during scanning (ERROR).
Lite Mode:
Output only matches for a cleaner, concise report (-L).
Database Logging:
Automatically logs all scan results into an SQLite database for future analysis.
Report Export:
Generate HTML reports by scan ID or target for easy sharing and documentation.
Requirements
Python 3.6+
Required Python Libraries:
requests
colorama
sqlite3 (Standard Python Library)
Install the required libraries using:

**install**
pip install -r requirements.txt

**run**
Run the scanner:
python NHL-Scanner.py

Usage
Command-Line Arguments
python NHL-Scanner.py [OPTIONS]
Options:
Flag	Description
-t, --target	Specify a single target URL.
-T, --targets	File containing multiple target URLs (one per line).
-s, --signature	Use a specific signature file (e.g., -s picker.json).
-S, --all_signatures	Use all signatures in the signatures folder.
-L, --lite	Lite mode: Print only matches.
--export-report	Export a report by scan-id or target to HTML format.
-h, --help	Display the help message and usage instructions.

python NHL-Scanner.py -t https://example.com -S
