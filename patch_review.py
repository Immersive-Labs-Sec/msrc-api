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
        print(f'  [-] ]{count} {vuln_type} Vulnerabilities')

    exploited = count_exploited(all_vulns)
    print(f'[+] Found {exploited["counter"]} exploited in the wild')
    for cve in exploited['cves']:
        print(f'  [-] {cve}')
