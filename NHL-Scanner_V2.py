import argparse
import requests
import json
import os
import sqlite3
from datetime import datetime
from colorama import Fore, Style, init
import uuid  # For generating scan-id

# Initialize colorama
init(autoreset=True)

# Initialize or connect to SQLite database
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
            match_parameter = parsed_json['http'][0]['matchers'][0]['words']
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


def export_report(conn, scan_id=None, target=None):
    cursor = conn.cursor()

    # Query results based on scan_id or target
    if scan_id:
        cursor.execute("SELECT * FROM scan_results_v2 WHERE scan_id = ?", (scan_id,))
    elif target:
        cursor.execute("SELECT * FROM scan_results_v2 WHERE target = ?", (target,))
    else:
        print(f"{Fore.RED}[!] Error: You must specify either a scan-id or a target for the report.")
        return

    results = cursor.fetchall()
    if not results:
        print(f"{Fore.YELLOW}[!] No results found for the given criteria.")
        return

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
    output_file = "NHL_Scanner_Report.html"
    with open(output_file, "w") as file:
        file.write(html_content)

    print(f"{Fore.GREEN}[+] Report successfully generated: {output_file}")


def main():
    # Display logo
    logo = fr"""{Fore.BLUE}
 _   _  _   _  _         ____                      
| \ | || | | || |       / ___|   ___   __ _  _ __   
|  \| || |_| || |       \___ \  / __| / _` || '_ \  
| |\  ||  _  || |___     ___) || (__ | (_| || | | | 
|_| \_||_| |_||_____|   |____/  \___| \__,_||_| |_| 
    v1.0    BY NOFAR HILA LIRON
"""
    print(logo)

    # Set up argument parser
    parser = argparse.ArgumentParser(description="Web vulnerability scanner using predefined signatures.")
    parser.add_argument("-t", "--target", help="Specify a single target URL", type=str)
    parser.add_argument("-T", "--targets", help="File containing multiple target URLs", type=str)
    parser.add_argument("-S", "--all_signatures", help="Use all signatures in the 'signatures' folder", action="store_true")
    parser.add_argument("-s", "--signature", help="Use a specific signature file", type=str)
    parser.add_argument("-L", "--lite", help="Lite mode: print only matches", action="store_true")
    parser.add_argument("--export-report", help="Export a report by scan-id or target", type=str)
    args = parser.parse_args()

    conn = initialize_db()

    # Export report if requested
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

    # The rest of the scanning logic remains unchanged
    # ...

    conn.close()


if __name__ == "__main__":
    main()
