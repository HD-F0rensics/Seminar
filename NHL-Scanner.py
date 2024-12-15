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
def save_result_to_db(conn, target, signature, status, message, scan_id):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_results_v2 (target, signature, status, message, scan_id)
        VALUES (?, ?, ?, ?, ?)
    """, (target, signature, status, message, scan_id))
    conn.commit()

# Function to export report
def export_report(conn, scan_id=None, target=None):
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
            body {{ font-family: Arial, sans-serif; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            tr:hover {{ background-color: #f5f5f5; }}
            .match {{ color: green; }}
            .not-match {{ color: orange; }}
            .error {{ color: red; }}
        </style>
    </head>
    <body>
        <h1>NHL Scanner Report</h1>
        <p>Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    """

    if scan_id:
        html_content += f"<p>Scan ID: {scan_id}</p>"
    elif target:
        html_content += f"<p>Target: {target}</p>"

    html_content += """
        <table>
            <tr>
                <th>Target</th>
                <th>Signature</th>
                <th>Status</th>
                <th>Message</th>
                <th>Timestamp</th>
                <th>Scan ID</th>
            </tr>
    """

    for row in results:
        target, signature, status, message, timestamp, scan_id = row[1:]
        status_class = "match" if status == "MATCH" else "not-match" if status == "NOT MATCH" else "error"
        html_content += f"""
            <tr>
                <td>{target}</td>
                <td>{signature}</td>
                <td class="{status_class}">{status}</td>
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

    # Save HTML file
    
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
                "message": f"{Fore.GREEN}[*] MATCH - [{match_parameter}] - {target} may be vulnerable to {sig_id}"
            }
        elif match_parameter_type == "status" and match_parameter == response.status_code:
            return {
                "status": "MATCH",
                "message": f"{Fore.GREEN}[*] MATCH - [{match_parameter}] - {target} may be vulnerable to {sig_id}"
            }
        else:
            return {
                "status": "NOT MATCH",
                "message": f"[-] NOT MATCH - [{match_parameter}] - {target} not vulnerable to {sig_id}"
            }
    except requests.RequestException as e:
        return {
            "status": "ERROR",
            "message": f"{Fore.RED}An error occurred: {e}"
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
            save_result_to_db(conn, target, signature, result["status"], result["message"], scan_id)
            if args.lite:
                if result["status"] == "MATCH":
                    print(result["message"])
            else:
                print(result["message"])

    conn.close()

    print(f"\nScan ID: {scan_id}")

if __name__ == "__main__":
    main()
