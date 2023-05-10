# PatchReview
# Copyright (C) 2023 Kevin Breen, Immersive Labs
# https://github.com/Immersive-Labs-Sec/msrc-api
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
This script fetches and analyzes data from Microsoft's Security Response Center (MSRC) API. 

It takes a date string for a security update (in the format 'YYYY-mmm') as a command-line argument. The script then sends a GET request to the MSRC API to fetch a list of all vulnerabilities from the security update.

The fetched data is parsed and the script outputs statistics about the vulnerabilities, including:

- The total number of vulnerabilities
- The number of each type of vulnerability, where types include 'Elevation of Privilege', 'Security Feature Bypass', 'Remote Code Execution', 'Information Disclosure', 'Denial of Service', 'Spoofing', and 'Edge - Chromium'
- The number of vulnerabilities that have been exploited, along with their details
- The number of vulnerabilities that are more likely to be exploited, along with their details

The script includes error handling for the GET request and checks the format of the input date string.

Usage:
    python patch_review.py <security_update>

    where <security_update> is a date string in the format 'YYYY-mmm'.

Example:
    python patch_review.py 2023-Jan

Requires:
    requests: To send the GET request to the MSRC API.

Note:
    This script is intended to be run as a standalone Python program, and not in a Jupyter notebook, as it makes use of argparse for command line arguments.
"""
import argparse
import requests
import re

# Constants
BASE_URL = 'https://api.msrc.microsoft.com/cvrf/v2.0/'
HEADERS = {'Accept': 'application/json'}

VULN_TYPES = [
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',
    'Spoofing',
    'Edge - Chromium'
]

def count_type(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 0:
                if search_type == "Edge - Chromium":
                    if threat['ProductID'][0] == '11655':
                        counter += 1
                        break
                elif threat['Description'].get('Value') == search_type:
                    if threat['ProductID'][0] == '11655':
                        break
                    counter += 1
                    break
    return counter

def count_exploited(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if cvss_sets:
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)

        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if 'Exploited:Yes' in description:
                    counter += 1
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}

def exploitation_likely(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if 'Exploitation More Likely'.lower() in description.lower():
                    counter += 1
                    cves.append(f'{vuln["CVE"]} -- {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}

def check_data_format(date_string):
    date_pattern = r'\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
    return bool(re.match(date_pattern, date_string, re.IGNORECASE))

def print_header(title):
    print("[+] Microsoft Patch Tuesday Stats")
    print("[+] https://github.com/Immersive-Labs-Sec/msrc-api")
    print(f"[+] {title}")

def fetch_vulnerabilities(security_update):
    try:
        get_sec_release = requests.get(f'{BASE_URL}cvrf/{security_update}', headers=HEADERS)
        get_sec_release.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred: {err}")
        return None
    except Exception as err:
        print(f"An error occurred: {err}")
        return None

    release_json = get_sec_release.json()
    return release_json

def parse_vulnerabilities(release_json):
    title = release_json.get('DocumentTitle', 'Release not found').get('Value')
    all_vulns = release_json.get('Vulnerability', [])

    return title, all_vulns

def print_vulnerability_stats(title, all_vulns):
    len_vuln = len(all_vulns)

    print_header(title)
    print(f'[+] Found a total of {len_vuln} vulnerabilities')

    for vuln_type in VULN_TYPES:
        count = count_type(vuln_type, all_vulns)
        print(f'  [-] {count} {vuln_type} Vulnerabilities')

    exploited = count_exploited(all_vulns)
    print(f'[+] Found {exploited["counter"]} exploited in the wild')
    for cve in exploited['cves']:
        print(f'  [-] {cve}')

    base_score = 8.0
    print('[+] Highest Rated Vulnerabilities')
    for vuln in all_vulns:
        title = vuln.get('Title', {'Value': 'Not Found'}).get('Value')
        cve_id = vuln.get('CVE', '')
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if cvss_sets:
            cvss_score = cvss_sets[0].get('BaseScore', 0)
            if cvss_score >= base_score:
                print(f'  [-] {cve_id} - {cvss_score} - {title}')

    exploitation = exploitation_likely(all_vulns)
    print(f'[+] Found {exploitation["counter"]} vulnerabilities more likely to be exploited')
    for cve in exploitation['cves']:
        print(f'  [-] {cve} - https://www.cve.org/CVERecord?id={cve.split()[0]}')

def main():
    parser = argparse.ArgumentParser(description='Read vulnerability stats for a patch Tuesday release.')
    parser.add_argument('security_update', help="Date string for the report query in format 'YYYY-mmm'")
    args = parser.parse_args()

    if not check_data_format(args.security_update):
        print("[!] Invalid date format please use 'yyyy-mmm'")
        return

    release_json = fetch_vulnerabilities(args.security_update)
    if release_json is None:
        print("[!] No vulnerability data fetched.")
        return

    title, all_vulns = parse_vulnerabilities(release_json)

    print_vulnerability_stats(title, all_vulns)

if __name__ == "__main__":
    main()

