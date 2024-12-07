import argparse
import requests
import json
import os


def run_sig(signature_name, target):
    # Define the path to the JSON file
    file_path = os.path.join("signatures", signature_name)

    # Check if the file exists
    if not os.path.exists(file_path):
        return f"[!] The file '{file_path}' does not exist."

    # Read and parse the JSON file
    try:
        with open(file_path, 'r') as file:
            json_data = file.read()
        parsed_json = json.loads(json_data)
    except json.JSONDecodeError as e:
        return f"[!] Error parsing JSON file '{file_path}': {e}"

    # Extract details from the signature
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
        return f"[!] Error extracting details from signature: {e}"

    # Perform the HTTP request
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
        }

        response = requests.request(http_method, path, headers=headers)

        if match_parameter_type == "word" and match_parameter in response.text:
            return f"[*] MATCH - [{match_parameter}] - {target} may be vulnerable to {sig_id}"
        elif match_parameter_type == "status" and match_parameter == response.status_code:
            return f"[*] MATCH - [{match_parameter}] - {target} may be vulnerable to {sig_id}"
        else:
            return f"[-] NOT MATCH - [{match_parameter}] - {target} not vulnerable to {sig_id}"
    except requests.RequestException as e:
        return f"[!] An error occurred: {e}"


def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description="Web vulnerability scanner using predefined signatures.")
    parser.add_argument("-t", "--target", help="Specify a single target URL", type=str)
    parser.add_argument("-T", "--targets", help="File containing multiple target URLs", type=str)
    parser.add_argument("-S", "--all_signatures", help="Use all signatures in the 'signatures' folder", action="store_true")
    parser.add_argument("-s", "--signature", help="Use a specific signature file", type=str)
    parser.add_argument("-L", "--lite", help="Lite mode: print only matches", action="store_true")

    # Parse arguments
    args = parser.parse_args()

    # Validate input
    if not args.target and not args.targets:
        print("Error: You must specify either a single target (-t) or a targets file (-T).")
        parser.print_help()
        return

    if args.all_signatures and args.signature:
        print("Error: You cannot use both '-S' (all signatures) and '-s' (single signature) at the same time.")
        parser.print_help()
        return

    # Determine targets
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.targets:
        if os.path.exists(args.targets):
            with open(args.targets, 'r') as file:
                targets = [line.strip() for line in file.readlines()]
        else:
            print(f"Error: The file '{args.targets}' does not exist.")
            return

    # Determine signatures
    if args.all_signatures:
        signatures_folder = "signatures"
        if os.path.exists(signatures_folder):
            signatures = [f for f in os.listdir(signatures_folder) if f.endswith('.json')]
        else:
            print(f"Error: The signatures folder '{signatures_folder}' does not exist.")
            return
    elif args.signature:
        if os.path.exists(os.path.join("signatures", args.signature)):
            signatures = [args.signature]
        else:
            print(f"Error: The signature file '{args.signature}' does not exist.")
            return
    else:
        print("Error: You must specify either '-S' (all signatures) or '-s' (single signature).")
        parser.print_help()
        return

    # Run scanner for each target and signature
    for target in targets:
        for signature in signatures:
            print(f"Scanning {target} with signature {signature}...")
            result = run_sig(signature, target)
            if args.lite:
                # Print only matches in Lite mode
                if "[*] MATCH" in result:
                    print(result)
            else:
                # Print all results in normal mode
                print(result)


if __name__ == "__main__":
    main()
