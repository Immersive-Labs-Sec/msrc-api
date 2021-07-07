# PatchReview
# Copyright (C) 2021 Kevin Breen, Immersive Labs
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

import argparse

import requests

base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/'

headers = {'Accept': 'application/json'}

vuln_types = [
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',
    'Spoofing',
    ]


def count_type(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 0:
                if threat['Description'].get('Value') == search_type:
                    counter += 1
                    break
    return counter


def count_exploited(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 1:
                description = threat['Description']['Value']
                if 'Exploited:Yes' in description:
                    counter += 1
                    cves.append(f'{vuln["CVE"]} -- {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read vulnerability stats for a patch tuesday release.')
    parser.add_argument('security_update', help="Date string for the report query in format YYYY-mmm")

    args = parser.parse_args()


    # Get the list of all vulns
    get_sec_release = requests.get(f'{base_url}cvrf/{args.security_update}', headers=headers)

    release_json = get_sec_release.json()

    title = release_json.get('DocumentTitle', 'Release not found').get('Value')

    all_vulns = release_json.get('Vulnerability', [])

    len_vuln = len(all_vulns)

    print(title)

    print(f'[+] Found a total of {len_vuln} vulnerabilities')

    for vuln_type in vuln_types:

        count = count_type(vuln_type, all_vulns)
        print(f'  [-] {count} {vuln_type} Vulnerabilities')

    exploited = count_exploited(all_vulns)
    print(f'[+] Found {exploited["counter"]} exploited in the wild')
    for cve in exploited['cves']:
        print(f'  [-] {cve}')
