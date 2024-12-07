from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def run_sig(signature_name, target):
    file_path = os.path.join("signatures", signature_name)

    if not os.path.exists(file_path):
        return {
            "status": "ERROR",
            "message": f"{Fore.RED}[!] The file '{file_path}' does not exist."
        }

    try:
        with open(file_path, 'r') as file:
            json_data = file.read()
        parsed_json = json.loads(json_data)
    except json.JSONDecodeError as e:
        return {
            "status": "ERROR",
            "message": f"{Fore.RED}[!] Error parsing JSON file '{file_path}': {e}"
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
            "message": f"{Fore.RED}[!] Error extracting details from signature: {e}"
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
                "message": f"{Fore.YELLOW}[-] NOT MATCH - [{match_parameter}] - {target} not vulnerable to {sig_id}"
            }
    except requests.RequestException as e:
        return {
            "status": "ERROR",
            "message": f"{Fore.RED}[!] An error occurred: {e}"
        }


def main():
    parser = argparse.ArgumentParser(description="Web vulnerability scanner using predefined signatures.")
    parser.add_argument("-t", "--target", help="Specify a single target URL", type=str)
    parser.add_argument("-T", "--targets", help="File containing multiple target URLs", type=str)
    parser.add_argument("-S", "--all_signatures", help="Use all signatures in the 'signatures' folder", action="store_true")
    parser.add_argument("-s", "--signature", help="Use a specific signature file", type=str)
    parser.add_argument("-L", "--lite", help="Lite mode: print only matches", action="store_true")
    args = parser.parse_args()

    if not args.target and not args.targets:
        print("Error: You must specify either a single target (-t) or a targets file (-T).")
        parser.print_help()
        return

    if args.all_signatures and args.signature:
        print("Error: You cannot use both '-S' (all signatures) and '-s' (single signature) at the same time.")
        parser.print_help()
        return

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.targets:
        if os.path.exists(args.targets):
            with open(args.targets, 'r') as file:
                targets = [line.strip() for line in file.readlines()]
        else:
            print(f"{Fore.RED}Error: The file '{args.targets}' does not exist.")
            return

    if args.all_signatures:
        signatures_folder = "signatures"
        if os.path.exists(signatures_folder):
            signatures = [f for f in os.listdir(signatures_folder) if f.endswith('.json')]
        else:
            print(f"{Fore.RED}Error: The signatures folder '{signatures_folder}' does not exist.")
            return
    elif args.signature:
        if os.path.exists(os.path.join("signatures", args.signature)):
            signatures = [args.signature]
        else:
            print(f"{Fore.RED}Error: The signature file '{args.signature}' does not exist.")
            return
    else:
        print(f"{Fore.RED}Error: You must specify either '-S' (all signatures) or '-s' (single signature).")
        parser.print_help()
        return

    for target in targets:
        for signature in signatures:
            print(f"Scanning {target} with signature {signature}...")
            result = run_sig(signature, target)
            if args.lite:
                if result["status"] == "MATCH":
                    print(result["message"])
            else:
                print(result["message"])


if __name__ == "__main__":
    main()
