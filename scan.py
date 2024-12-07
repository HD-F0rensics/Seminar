import requests
import json
import os


def run_sig(signature_name, target):
  # Define the path to the JSON file
  file_path = os.path.join("signatures", signature_name)

  # Check if the file exists
  if os.path.exists(file_path):
      # Read the JSON data from the file
      with open(file_path, 'r') as file:
          json_data = file.read()
  else:
      print(f"The file '{file_path}' does not exist.")
      exit()

  # Parse the JSON
  parsed_json = json.loads(json_data)

  # Extract the HTTP method, path, base URL and ID
  http_method = parsed_json['http'][0]['method']
  path = parsed_json['http'][0]['path'][0].replace("{{BaseURL}}", target)
  id = parsed_json['id']

  #print(parsed_json['http'][0]['matchers'][0]['type'])
  #print(id)

  # Extract the match parameter from the JSON
  if parsed_json['http'][0]['matchers'][0]['type'] == "word":
    match_parameter = parsed_json['http'][0]['matchers'][0]['words']
    match_parameter_type = "word"
  elif parsed_json['http'][0]['matchers'][0]['type'] == "status":
    match_parameter = parsed_json['http'][0]['matchers'][0]['status']
    match_parameter_type = "status"
  
  try:
    # Define headers of normal browser
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
      }
    
    # Perform the request
    response = requests.request(http_method, path, headers=headers)
    #print(response.status_code)

    if match_parameter_type == "word":
      # Check if the match parameter is in the response
      if match_parameter in response.text:
          print(f"[*] MATCH - [{match_parameter}] - {target} may vulnerable to {id}")
      else:
          print(f"NOT MATCH - [{match_parameter}] - {target} not vulnerable to {id}")
    
    elif match_parameter_type == "status":
      # Check if the match parameter equal to response code
      if match_parameter == response.status_code:
          print(f"[*] MATCH - [{match_parameter}] - {target} may vulnerable to {id}")
      else:
          print(f"NOT MATCH - Status [{match_parameter}] - {target} not vulnerable to {id}")
  
  except requests.RequestException as e:
        print(f"An error occurred: {e}")



signature_name = input("Signature file: ")
target = input("Target: ")
run_sig(signature_name, target)

run_sig("Telerik.json", "http://example.com")
run_sig("Picker.json", "https://brendaabbott.net") # Work