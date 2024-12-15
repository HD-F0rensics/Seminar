import argparse
import requests
import json
import os
import sqlite3
from datetime import datetime
from colorama import Fore, Style, init
import uuid  # For generating scan-id

# start colorama
init(autoreset=True)

# start or connect to SQLite database
def initialize_db(db_name="scan_results_v2.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results_v2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            signature TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            status TEXT NOT NULL,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            scan_id TEXT NOT NULL
        )
    """)
    # CONN: sqlite3 scan_results_v2.db --> SELECT * FROM scan_results_v2;
    conn.commit()
    return conn


# Function to save results to the database
def save_result_to_db(conn, target, signature, severity, status, message, scan_id):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_results_v2 (target, signature, severity, status, message, scan_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (target, signature, severity, status, message, scan_id))
    conn.commit()

# Function to export report
# Export report as an HTML file
# Function to export report with statistics and details
def export_report(conn, scan_id=None, target=None):
    import os
    script_location = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(script_location, "Files", "NHL-LOGO.jpg")

    cursor = conn.cursor()

    # Query results based on scan_id or target
    if scan_id:
        cursor.execute("SELECT * FROM scan_results_v2 WHERE scan_id = ?", (scan_id,))
        report_name = "NHL_Scanner_Report_" + scan_id + ".html"
    elif target:
        cursor.execute("SELECT * FROM scan_results_v2 WHERE target = ?", (target,))
        domain = target.split("//")[-1].split("/")[0]
        report_name = "NHL_Scanner_Report_" + domain + ".html"
    else:
        print(f"{Fore.RED}[!] Error: You must specify either a scan-id or a target for the report.")
        return

    results = cursor.fetchall()
    if not results:
        print(f"{Fore.YELLOW}[!] No results found for the given criteria.")
        return

    # Prepare data for statistics, including only entries with MATCH status
    severity_count = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    matches_by_target = {}
    for row in results:
        target, severity, status = row[1], row[3].lower(), row[4].upper()
        if status == "MATCH":
            if severity in severity_count:
                severity_count[severity] += 1
            matches_by_target[target] = matches_by_target.get(target, 0) + 1

    # Sort matches by the highest number
    sorted_matches = sorted(matches_by_target.items(), key=lambda x: x[1], reverse=True)
    highest_match_count = sorted_matches[0][1] if sorted_matches else 0

    # Ensure the reports directory exists
    reports_folder = "reports"
    if not os.path.exists(reports_folder):
        os.makedirs(reports_folder)

    # Full path for the report file
    output_file = os.path.join(reports_folder, report_name)

    # Generate HTML content
    html_content = f"""
    <html>
    <head>
        <title>NHL Scanner Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #d3d3d3; /* Light gray background */
                color: #333;
            }}
            header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 2px solid #555;
                padding-bottom: 10px;
                margin-bottom: 20px;
            }}
            header img {{
                height: 500px; /* Larger logo size */
                width: 500px;
                object-fit: cover; /* Ensures proper scaling */
            }}
            header h1 {{
                font-size: 130px; /* Proportionally larger title */
                color: #222;
                margin: 0;
                text-align: left;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin-top: 20px;
                background-color: #fff;
                box-shadow: 0px 2px 5px rgba(0, 0, 0, 0.1);
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 10px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
                color: #222;
                font-size: 14px;
            }}
            tr:hover {{
                background-color: #f9f9f9;
            }}
            .box {{
                display: inline-block;
                width: 150px;
                height: 150px;
                margin: 10px;
                color: white;
                font-size: 20px;
                font-weight: bold;
                text-align: center;
                line-height: 1.5; /* Center align title and numbers */
                border-radius: 8px;
                position: relative;
                vertical-align: middle;
            }}
            .critical-box {{ background-color: darkred; }}
            .high-box {{ background-color: red; }}
            .medium-box {{ background-color: orange; }}
            .low-box {{ background-color: lightgreen; color: black; }}
            .info-box {{ background-color: blue; }}
            .box p {{
                margin: 0;
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                text-align: center;
            }}
            .box-title {{
                font-size: 18px;
                font-weight: bold;
                margin: 0;
            }}
            .box-number {{
                font-size: 32px;
                margin: 0;
            }}
            .highlight {{
                background-color: red; 
                color: white; 
                font-weight: bold;
            }}
            .match-text {{ color: green; font-weight: bold; }}
            .not-match-text {{ color: orange; font-weight: bold; }}
        </style>
    </head>
    <body>
        <header>
            <h1>NHL Scanner Report</h1>
            <img src="{logo_path}" alt="NHL Scanner Logo">
        </header>
        <p>Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <!-- Page 1: Statistics -->
        <h2>Vulnerable Targets Statistics</h2>
        <div style="display: flex; justify-content: space-around; margin-top: 20px;">
            <div class="box critical-box">
                <p>
                    <span class="box-title">Critical</span><br>
                    <span class="box-number">{severity_count['critical']}</span>
                </p>
            </div>
            <div class="box high-box">
                <p>
                    <span class="box-title">High</span><br>
                    <span class="box-number">{severity_count['high']}</span>
                </p>
            </div>
            <div class="box medium-box">
                <p>
                    <span class="box-title">Medium</span><br>
                    <span class="box-number">{severity_count['medium']}</span>
                </p>
            </div>
            <div class="box low-box">
                <p>
                    <span class="box-title">Low</span><br>
                    <span class="box-number">{severity_count['low']}</span>
                </p>
            </div>
            <div class="box info-box">
                <p>
                    <span class="box-title">Info</span><br>
                    <span class="box-number">{severity_count['info']}</span>
                </p>
            </div>
        </div>

        <!-- Matches by Target -->
        <h2 style="margin-top: 40px;">Matches by Target</h2>
        <table>
            <tr>
                <th>Target</th>
                <th>Matches</th>
            </tr>
    """

    # Populate Matches by Target
    for target, match_count in sorted_matches:
        row_style = "highlight" if match_count == highest_match_count else ""
        html_content += f"""
            <tr class="{row_style}">
                <td>{target}</td>
                <td style="text-align: center;">{match_count}</td>
            </tr>
        """

    # Page 2 - Details
    html_content += """
        </table>
        <h2>Detailed Results</h2>
        <table>
            <tr>
                <th>Target</th>
                <th>Signature</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Message</th>
                <th>Timestamp</th>
                <th>Scan ID</th>
            </tr>
    """

    # Populate Detailed Results
    for row in results:
        target, signature, severity, status, message, timestamp, scan_id = row[1:]
        severity_class = severity.lower()
        status_class = "match-text" if status == "MATCH" else "not-match-text"

        html_content += f"""
            <tr>
                <td>{target}</td>
                <td>{signature}</td>
                <td class="{status_class}">{status}</td>
                <td class="{severity_class}">{severity.capitalize()}</td>
                <td>{message}</td>
                <td>{timestamp}</td>
                <td>{scan_id}</td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    # Save the report
    with open(output_file, "w") as file:
        file.write(html_content)

    print(f"{Fore.GREEN}[+] Report successfully generated: {output_file}")









# Function to run the CVE signature
def run_sig(signature_name, target):
    file_path = os.path.join("signatures", signature_name)

    if not os.path.exists(file_path):
        return {
            "status": "ERROR",
            "message": f"{Fore.RED}The file '{file_path}' does not exist."
        }

    try:
        with open(file_path, 'r') as file:
            json_data = file.read()
        parsed_json = json.loads(json_data)
    except json.JSONDecodeError as e:
        return {
            "status": "ERROR",
            "message": f"{Fore.RED}Error parsing JSON file '{file_path}': {e}"
        }

    try:
        http_method = parsed_json['http'][0]['method']
        path = parsed_json['http'][0]['path'][0].replace("{{BaseURL}}", target)
        sig_id = parsed_json['id']
        severity = parsed_json['info'].get('severity', 'info')
        

        match_parameter = None
        match_parameter_type = None
        if parsed_json['http'][0]['matchers'][0]['type'] == "word":
            match_parameter = parsed_json['http'][0]['matchers'][0]['word']
            match_parameter_type = "word"
        elif parsed_json['http'][0]['matchers'][0]['type'] == "status":
            match_parameter = parsed_json['http'][0]['matchers'][0]['status']
            match_parameter_type = "status"
    except (KeyError, IndexError) as e:
        return {
            "status": "ERROR",
            "message": f"{Fore.RED}Error extracting details from signature: {e}"
        }

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
        }

        response = requests.request(http_method, path, headers=headers)

        if match_parameter_type == "word" and match_parameter in response.text:
            return {
                "status": "MATCH",
                "message": f"{Fore.GREEN}[*] MATCH - [{match_parameter}] - {target} may be vulnerable to {sig_id}",
                "severity": severity
            }
        elif match_parameter_type == "status" and match_parameter == response.status_code:
            return {
                "status": "MATCH",
                "message": f"{Fore.GREEN}[*] MATCH - [{match_parameter}] - {target} may be vulnerable to {sig_id}",
                "severity": severity
            }
        else:
            return {
                "status": "NOT MATCH",
                "message": f"[-] NOT MATCH - [{match_parameter}] - {target} not vulnerable to {sig_id}",
                "severity": severity
            }
    except requests.RequestException as e:
        return {
            "status": "ERROR",
            "message": f"{Fore.RED}An error occurred: {e}",
            "severity": severity
        }


# Function to create a custom signature by user
def create_signature():
    print(f"{Fore.BLUE}[+] Let's create a custom signature.")
    # Collect general signature info
    custom_sig_name = str(input("Enter the name of the json file (e.g. picker): ").strip())
    sig_id = input("Enter the ID for this signature (e.g., CVE-2023-0001): ").strip()
    name = input("Enter the name of the vulnerability (e.g., Example Vulnerability): ").strip()
    author = input("Enter author name: ").strip()
    # Choose severity level
    print("\nChoose severity level:")
    print("[1] High")
    print("[2] Medium")
    print("[3] Low")
    while True:
        severity_choice = input("Enter your choice (1, 2, or 3): ").strip()
        if severity_choice == "1":
            severity = "high"
            break
        elif severity_choice == "2":
            severity = "medium"
            break
        elif severity_choice == "3":
            severity = "low"
            break
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please enter 1, 2, or 3.")    
    
    description = input("Enter a description of the vulnerability: ").strip()
    tags = input("Enter tags (comma-separated, e.g., tech,example,vuln): ").strip().split(',')

    # Collect HTTP request info
    method = input("Enter the HTTP method (e.g., GET, POST): ").strip()
    path = str(input("Enter the URL path (e.g., /example/path): ").strip())

    # Choose matcher type
    print("\nChoose matcher type:")
    print("[1] status")
    print("[2] word")
    while True:
        matcher_choice = input("Enter your choice (1 or 2): ").strip()
        if matcher_choice == "1":
            matcher_type = "status"
            match_value = int(input("Enter the expected status code (e.g., 200): "))
            break
        elif matcher_choice == "2":
            matcher_type = "word"
            match_value = str(input("Enter the expected word/phrase in the response (e.g., Example phrase): ".strip()))
            break
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please enter 1 or 2.")


    # Build the JSON structure
    signature = {
        "id": sig_id,
        "info": {
            "name": "CUSTOM_" + name,
            "author": author,
            "severity": severity,
            "description": description,
            "metadata": {
                "max-request": 1
            },
            "tags": tags
        },
        "http": [
            {
                "method": method,
                "path": ["{{BaseURL}}/" + path],
                "matchers": [
                    {
                        "type": matcher_type,
                        matcher_type: match_value
                    }
                ]
            }
        ]
    }

    # Save the signature to the signatures folder
    signatures_folder = "signatures"
    if not os.path.exists(signatures_folder):
        os.makedirs(signatures_folder)
    
    signature_file = os.path.join(signatures_folder, f"CUSTOM_{custom_sig_name}.json")
    with open(signature_file, "w") as file:
        json.dump(signature, file, indent=4)
    
    print(f"{Fore.GREEN}[+] Signature saved successfully: {signature_file}")




def main():
    # Created with text2art("NHL   Scanner")
    logo = fr"""{Fore.CYAN}
 _   _  _   _  _         ____
| \ | || | | || |       / ___|   ___   __ _  _ __   _ __    ___  _ __
|  \| || |_| || |       \___ \  / __| / _` || '_ \ | '_ \  / _ \| '__|
| |\  ||  _  || |___     ___) || (__ | (_| || | | || | | ||  __/| |
|_| \_||_| |_||_____|   |____/  \___| \__,_||_| |_||_| |_| \___||_| v1.0
                                                                         BY NOFAR HILA LIRON @
@HD-F0rensics - github.com/HD-F0rensics/Seminar
"""
    print(logo)
    parser = argparse.ArgumentParser(description="Web vulnerability scanner using CVE signatures.")
    # Arguments for run new scan
    parser.add_argument("-t", "--target", help="Specify a single target URL", type=str)
    parser.add_argument("-T", "--targets", help="File containing multiple target URLs", type=str)
    parser.add_argument("-S", "--all_signatures", help="Use all signatures in the 'signatures' folder", action="store_true")
    parser.add_argument("-s", "--signature", help="Use a specific signature file", type=str)
    parser.add_argument("-L", "--lite", help="Lite mode: print only matches", action="store_true")
    
    # Argument for report
    parser.add_argument("--export-report", help="Export a report by scan-id or target. Use 'scan-id:<id>' or 'target:<target>", type=str)

    # Argument for custom CVE signature
    parser.add_argument("--create-sig", help="Create a custom signature", action="store_true")

    args = parser.parse_args()

    conn = initialize_db()


    # Custom signature creation
    if args.create_sig:
        create_signature()
        return

    # Export report 
    if args.export_report:
        if args.export_report.startswith("scan-id:"):
            scan_id = args.export_report.split("scan-id:")[1]
            export_report(conn, scan_id=scan_id)
        elif args.export_report.startswith("target:"):
            target = args.export_report.split("target:")[1]
            export_report(conn, target=target)
        else:
            print(f"{Fore.RED}[!] Invalid --export-report format. Use 'scan-id:<id>' or 'target:<target>'")
        return

    # New scan
    if not args.target and not args.targets:
        print(f"{Fore.RED}[!] Error: You must specify either a single target (-t) or a targets file (-T).")
        parser.print_help()
        return

    if args.all_signatures and args.signature:
        print(f"{Fore.RED}[!] Error: You cannot use both '-S' (all signatures) and '-s' (single signature) at the same time.")
        parser.print_help()
        return

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.targets:
        if os.path.exists(args.targets):
            with open(args.targets, 'r') as file:
                # Clean (strip) and stores (readlines) each line from the input file as a list of targets
                targets = [line.strip() for line in file.readlines()]
        else:
            print(f"{Fore.RED}[!] Error: The file '{args.targets}' does not exist.")
            return

    if args.all_signatures:
        signatures_folder = "signatures"
        if os.path.exists(signatures_folder):
            signatures = [f for f in os.listdir(signatures_folder) if f.endswith('.json')]
        else:
            print(f"{Fore.RED}[!] Error: The signatures folder '{signatures_folder}' does not exist.")
            return
    elif args.signature:
        if os.path.exists(os.path.join("signatures", args.signature)):
            signatures = [args.signature]
        else:
            print(f"{Fore.RED}[!] Error: The signature file '{args.signature}' does not exist.")
            return
    else:
        print(f"{Fore.RED}[!] Error: You must specify either '-S' (all signatures) or '-s' (single signature).")
        parser.print_help()
        return

    # Generate a unique scan ID
    scan_id = str(uuid.uuid4())
    
    for target in targets:
        for signature in signatures:
            print(f"Scanning {target} with signature {signature}...")
            result = run_sig(signature, target)
            save_result_to_db(conn, target, signature, result["severity"], result["status"], result["message"], scan_id)
            if args.lite:
                if result["status"] == "MATCH":
                    print(result["message"])
            else:
                print(result["message"])

    conn.close()

    print(f"\nScan ID: {scan_id}")

if __name__ == "__main__":
    main()
