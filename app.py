import os
import subprocess
import json
import requests

# Mandatory Environment Variables
# TRIVY_SECURITY  (see below)
# IMAGE  eg. 'IMAGE=nginx'
# TAG    eg. 'TAG=1.21.1'
# METRICS_ENDPOINT eg. METRICS_ENDPOINT=https://abc123.live.dynatrace.com
# METRICS_API_TOKEN eg. METRICS_API_TOKEN=dtc01.***
#
# Usage
# Security levels are case sensitive. 'critical' != 'CRITICAL'
# If nothing is provided, all security levels are checked: 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL'
# TRIVY_SECURITY=HIGH,CRITICAL IMAGE=nginx TAG=1.21.1 METRICS_ENDPOINT=https://abc123.live.dynatrace.com METRICS_API_TOKEN=dtc01.*** python3 app.py

# This script assumes the new Trivy JSON schema is used
# Hardcode it to be sure (and remove a param so the user doesn't need to set it)
# https://github.com/aquasecurity/trivy/discussions/1050
os.environ["TRIVY_NEW_JSON_SCHEMA"] = "true"

TRIVY_SECURITY = os.getenv('TRIVY_SECURITY', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL')
IMAGE = os.getenv('IMAGE')
TAG = os.getenv('TAG')
METRICS_ENDPOINT = os.getenv('METRICS_ENDPOINT','')
METRICS_API_TOKEN = os.getenv('METRICS_API_TOKEN','')
DEBUG = os.getenv('DEBUG', False)

if IMAGE == None or TAG == None:
  print('IMAGE and / or TAG environment variables not provided. Please set and re-run.')
  exit()
if METRICS_ENDPOINT == '' or METRICS_API_TOKEN == '':
  print('METRICS_ENDPOINT and/or METRICS_API_TOKEN environment variables not set. Tool will still work but metrics will not be pushed to a backend.')

if DEBUG:
  print(TRIVY_SECURITY)
  print(IMAGE)
  print(TAG)
  print(METRICS_ENDPOINT)

security_levels_array = TRIVY_SECURITY.split(',')

print('Checking ' + str(len(security_levels_array)) + ' security levels: ' + str(security_levels_array))

# Build List of dictionaries to hold vuln count for each severity level
security_items = list()
for level in security_levels_array:
    level_dict = {
        "level": level,
        "vulnerabilities": 0
    }
    security_items.append(level_dict)

#trivy_command_line_severity = "--severity=" + 
#trivy_command_line_image_tag = IMAGE + ":" + TAG
#trivy_command_line = f"./trivy image --no-progress --format=json {trivy_command_line_severity} {trivy_command_line_image_tag}"
trivy_command_line = f"./trivy --cache-dir=/tmp/trivycache image --no-progress --format=json --severity={TRIVY_SECURITY} {IMAGE}:{TAG}"

if DEBUG:
  print(trivy_command_line)

# Run trivy and capture std output. Then transform stdout into JSON object trivy_results_json
# eg. ./trivy image --format=json --output=trivy_output_tmp.json --severity=CRITICAL nginx:1.21.1
#print('./trivy image --no-progress --format=json' + trivy_command_line_severity + " - " + trivy_command_line_image_tag)
trivy_output = subprocess.run([trivy_command_line], capture_output=True, shell=True)

# This is the JSON result but includes some irrelevant lines at the top
stdout_as_str = trivy_output.stdout.decode("utf-8")
if DEBUG:
  print(stdout_as_str)

if '{' not in stdout_as_str:
  exit()

# substring to remove irrelevant details
index_of_opening_curly_brace = stdout_as_str.index('{')
json_output = stdout_as_str[index_of_opening_curly_brace:]
trivy_results_json = json.loads(json_output)

# Get number of vulnerabilities
total_vulns_count = 0

# Loop through results and get number of vulnerabilities for each result
results = trivy_results_json['Results']

if DEBUG:
  print('Number of results: ' + str(len(results)))

for result in results:
  for item in security_items:
    level_to_check = item['level']
    vuln_count = item['vulnerabilities']
    if DEBUG:
      print("Counting" + level_to_check + "Vulnerabilities")

    for vuln in result['Vulnerabilities']:
      #print(vuln['Severity'])
      if vuln['Severity'] == level_to_check:
        # Increment count for this level AND
        # Increment the running total of the total_vulns
        vuln_count += 1
        total_vulns_count += 1
    # Update the vulnerability count for this level and store in list of dictionaries
    item['vulnerabilities'] = vuln_count

print('Finished. Total Vulnerability Count: ' + str(total_vulns_count))
if DEBUG:
  for item in security_items:
    print(item)

# Output result to monitoring provider
if DEBUG:
  print(METRICS_ENDPOINT)

if METRICS_ENDPOINT != None and METRICS_API_TOKEN != None:
  metrics_endpoint = METRICS_ENDPOINT+"/api/v2/metrics/ingest"

  if DEBUG:
    print(metrics_endpoint)

  headers = {
    "Authorization": "Api-Token " + METRICS_API_TOKEN
  }

  # Build payload
  # Loop through each vuln and add a new line for it
  # We will push all metrics onto the same key and split by a dimension

  # First push the total
  payload = "trivy.vulnerabilities.total,image="+IMAGE+",tag="+TAG+" " + str(total_vulns_count) + "\n"

  # Now add severities one by one
  for item in security_items:
    severity = item['level']
    vuln_count = item['vulnerabilities']

    payload += "trivy.vulnerabilities."+severity+",image="+IMAGE+",tag="+TAG+" " + str(vuln_count) + "\n"

  if DEBUG:
    print(payload)

  response = requests.post(url=metrics_endpoint, headers=headers, data=payload)
  print(response.status_code)
else:
  print('METRICS_ENDPOINT and/or METRICS_API_TOKEN not set. Tool will still work but metrics will not be pushed to a backend.')