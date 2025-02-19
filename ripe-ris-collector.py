import requests
import pandas as pd
import ipaddress
from datetime import datetime
import whois
import time
import socket
import subprocess
import re

# File paths and configuration
INPUT_FILE = 'unique-ips.log'
OUTPUT_FILE_PREFIX = 'ripe_ris_data_full'
RATE_LIMIT_DELAY = 300  # Delay in milliseconds between API calls

# Comprehensive list of RIR and regional routing data APIs
ROUTING_APIS = {
    'RIPE': [
        "https://stat.ripe.net/data/prefix-overview/data.json",
        "https://stat.ripe.net/data/routing-status/data.json",
        "https://stat.ripe.net/data/ris-prefixes/data.json"
    ],
    'LACNIC': [
        "https://rdap.lacnic.net/rdap/ip/",
        "https://stat.lacnic.net/data/prefix-overview/"
    ],
    'APNIC': [
        "https://rdap.apnic.net/rdap/ip/",
        "https://stat.apnic.net/data/prefix-overview/"
    ],
    'AFRINIC': [
        "https://rdap.afrinic.net/rdap/ip/",
        "https://stat.afrinic.net/data/prefix-overview/"
    ],
    'ARIN': [
        "https://rdap.arin.net/registry/ip/",
        "https://whois.arin.net/rest/ip/"
    ]
}

def query_cymru_dns(ip):
    reversed_ip = '.'.join(reversed(ip.split('.')))
    
    cmd = f"dig +short {reversed_ip}.origin.asn.cymru.com TXT"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if not result.stdout:
        return None, None
    
    asn = result.stdout.split('|')[0].strip().strip('"')
    
    cmd = f"dig +short AS{asn}.asn.cymru.com TXT"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if not result.stdout:
        return None, None
    
    parts = result.stdout.strip().strip('"').split('|')
    asn_desc = parts[4].strip() if len(parts) > 4 else ''
    
    return asn, f'"{asn_desc}"'

def query_team_cymru(subnet):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('whois.cymru.com', 43))
        s.send(f'begin\nverbose\n{subnet}\nend\n'.encode())
        response = s.recv(1024).decode()
        s.close()
        
        for line in response.split('\n'):
            if '|' in line and not line.startswith('Bulk'):
                parts = line.split('|')
                return {
                    'data': {
                        'asns': [{
                            'asn': parts[0].strip(),
                            'holder': f'"{parts[6].strip()}"',
                            'country': parts[3].strip() if len(parts) > 3 else ''
                        }]
                    }
                }
    except:
        return None

def get_unique_subnets(input_file):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    subnet_counts = {}
    
    with open(input_file, 'r') as file:
        for line in file:
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                try:
                    if ipaddress.ip_address(ip):
                        network = '.'.join(ip.split('.')[:2]) + '.0.0/16'
                        subnet_counts[network] = subnet_counts.get(network, 0) + 1
                except ValueError:
                    continue
    
    return sorted(list(subnet_counts.keys())), subnet_counts

def get_sample_ip_for_subnet(subnet, input_file):
    with open(input_file, 'r') as file:
        for line in file:
            ip = line.split()[1]
            if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
                return ip
    return None

def query_rir_api(endpoint, subnet):
    try:
        headers = {'Accept': 'application/json'}
        response = requests.get(f"{endpoint}{subnet}", headers=headers)
        return response.json()
    except:
        return None

def get_route_data(subnet):
    # Try Team Cymru first
    cymru_data = query_team_cymru(subnet)
    if cymru_data:
        print(f"  → Found data via Team Cymru")
        return cymru_data

    # Try each RIR's APIs as fallback
    print(f"  → Trying RIR APIs...")
    for rir, endpoints in ROUTING_APIS.items():
        for endpoint in endpoints:
            data = query_rir_api(endpoint, subnet)
            if data:
                if rir == 'RIPE' and (data['data'].get('asns') or data['data'].get('announced')):
                    print(f"  → Found data via RIPE")
                    return data
                elif rir == 'LACNIC' and data.get('networks'):
                    print(f"  → Found data via LACNIC")
                    return {'data': {'asns': [{'asn': data['networks'][0]['autnum']}]}}
                elif rir == 'APNIC' and data.get('objects'):
                    print(f"  → Found data via APNIC")
                    return {'data': {'asns': [{'asn': data['objects'][0].get('handle')}]}}
                elif rir == 'AFRINIC' and data.get('entities'):
                    print(f"  → Found data via AFRINIC")
                    return {'data': {'asns': [{'asn': data['entities'][0].get('handle')}]}}
                elif rir == 'ARIN' and data.get('net'):
                    print(f"  → Found data via ARIN")
                    return {'data': {'asns': [{'asn': data['net'].get('originAS')}]}}

    # Last resort: WHOIS lookup
    print(f"  → Trying WHOIS lookup...")
    sample_ip = get_sample_ip_for_subnet(subnet, INPUT_FILE)
    if sample_ip:
        try:
            w = whois.whois(sample_ip)
            print(f"  → Found data via WHOIS")
            return {
                'data': {
                    'asns': [{
                        'asn': w.asn,
                        'holder': f'"{w.org}"'
                    }]
                }
            }
        except:
            pass
    
    return {'data': {}}

def get_asn_info(asn):
    for rir, endpoints in ROUTING_APIS.items():
        try:
            response = requests.get(f"{endpoints[0]}?resource={asn}")
            data = response.json()
            if data.get('data') or data.get('objects'):
                return data
        except:
            continue
    return {'data': {}}

def process_routes(check_missing=False):
    df = pd.DataFrame(columns=['subnet', 'asn', 'asn_desc', 'country', 'count'])
    df = df.astype({
        'subnet': 'string',
        'asn': 'string',
        'asn_desc': 'string',
        'country': 'string',
        'count': 'int64'
    })
    
    subnets, subnet_counts = get_unique_subnets(INPUT_FILE)
    total_subnets = len(subnets)
    
    print(f"Starting global network data collection for {total_subnets} unique subnets")
    
    for idx, subnet in enumerate(subnets, 1):
        print(f"[{idx}/{total_subnets}] Processing subnet: {subnet}")
        route_data = get_route_data(subnet)
        
        try:
            if route_data['data'].get('asns'):
                asn = route_data['data']['asns'][0]['asn']
                print(f"  → Found ASN: {asn}")
                
                asn_data = get_asn_info(asn)
                holder = asn_data['data'].get('holder', route_data['data']['asns'][0].get('holder', ''))
                country = asn_data['data'].get('country', route_data['data']['asns'][0].get('country', ''))
                
                print(f"  → Retrieved ASN details: {holder}")
                
                df = pd.concat([df, pd.DataFrame([{
                    'subnet': subnet,
                    'asn': str(asn),
                    'asn_desc': holder,
                    'country': country,
                    'count': subnet_counts[subnet]
                }])], ignore_index=True)
            else:
                print(f"  → No routing data found for {subnet}")
        except Exception as e:
            print(f"  → Error processing {subnet}: {str(e)}")
            continue
        
        time.sleep(RATE_LIMIT_DELAY/1000)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f'{OUTPUT_FILE_PREFIX}_{timestamp}.csv'
    df.to_csv(output_file, index=False)
    
    detailed_output = f'{OUTPUT_FILE_PREFIX}_detailed_{timestamp}.csv'
    with open(INPUT_FILE, 'r') as infile, open(detailed_output, 'w') as outfile:
        outfile.write("original_line,subnet,asn,asn_desc,country\n")
        for line in infile:
            ip = line.split()[1]
            subnet = '.'.join(ip.split('.')[:2]) + '.0.0/16'
            if subnet in df['subnet'].values:
                subnet_data = df[df['subnet'] == subnet].iloc[0]
                outfile.write(f"{line.strip()},{subnet},{subnet_data['asn']},{subnet_data['asn_desc']},{subnet_data['country']}\n")
    
    if check_missing:
        print("\nChecking for missing ASN information...")
        df_detailed = pd.read_csv(detailed_output, dtype={'asn': str, 'asn_desc': str})
        df_summary = pd.read_csv(output_file, dtype={'asn': str, 'asn_desc': str})
        
        # Clean any triple quotes in both dataframes
        df_detailed['asn_desc'] = df_detailed['asn_desc'].str.replace('"""', '"')
        df_summary['asn_desc'] = df_summary['asn_desc'].str.replace('"""', '"')
        
        missing_entries = df_detailed[
            ((df_detailed['asn'].astype(str).str.upper() == 'NA') & 
             (df_detailed['asn_desc'].astype(str).str.upper().isin(['"NA"', 'NA']))) |
            ((df_detailed['asn'].isna()) & (df_detailed['asn_desc'].isna()))
        ]
        total_missing = len(missing_entries)
        
        if total_missing > 0:
            print(f"Found {total_missing} entries with missing ASN information")
            updated = False
            
            for idx, (index, row) in enumerate(missing_entries.iterrows(), 1):
                ip = row['original_line'].split()[1]
                subnet = row['subnet']
                print(f"[{idx}/{total_missing}] Querying ASN for {ip}")
                
                asn, asn_desc = query_cymru_dns(ip)
                if asn and asn_desc:
                    print(f"  → Found ASN: {asn}")
                    print(f"  → Description: {asn_desc}")
                    
                    # Update detailed file
                    df_detailed.loc[index, 'asn'] = str(asn)
                    df_detailed.loc[index, 'asn_desc'] = str(asn_desc)
                    
                    # Update summary file for matching subnet
                    summary_idx = df_summary[df_summary['subnet'] == subnet].index
                    if not summary_idx.empty:
                        df_summary.loc[summary_idx[0], 'asn'] = str(asn)
                        df_summary.loc[summary_idx[0], 'asn_desc'] = str(asn_desc)
                    
                    updated = True
                else:
                    print(f"  → No additional data found")
                
                time.sleep(RATE_LIMIT_DELAY/1000)
            
            if updated:
                df_detailed.to_csv(detailed_output, index=False)
                df_summary.to_csv(output_file, index=False)
                print("\nUpdated both detailed and summary outputs with new ASN information")
        else:
            print("No missing ASN entries found")
    
    print(f"\nData collection complete!")
    print(f"Processed {total_subnets} unique subnets")
    print(f"Summary results exported to: {output_file}")
    print(f"Detailed results exported to: {detailed_output}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-missing', action='store_true', help='Check and update missing ASN information')
    args = parser.parse_args()
    
    process_routes(check_missing=args.check_missing)