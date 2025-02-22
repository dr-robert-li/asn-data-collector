import requests
import pandas as pd
import ipaddress
from datetime import datetime
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, HTTPLookupError
import time
import socket
import subprocess
import re
import os
from typing import Dict, List, Tuple

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

def query_rir_api(endpoint, subnet, verbose=False):
    try:
        headers = {'Accept': 'application/json'}
        response = requests.get(f"{endpoint}{subnet}", headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        if verbose:
            print(f"  → Status code {response.status_code} from {endpoint}")
        return None
    except requests.Timeout:
        if verbose:
            print(f"  → Timeout while querying {endpoint}")
        return None
    except requests.RequestException as e:
        if verbose:
            print(f"  → Error querying {endpoint}: {str(e)}")
        return None
    except ValueError as e:
        if verbose:
            print(f"  → Invalid JSON from {endpoint}")
        return None
    finally:
        time.sleep(RATE_LIMIT_DELAY/1000)

def get_route_data(subnet, verbose=False):
    def is_valid_data(asn, holder):
        return asn and holder and asn.upper() != 'NA' and holder.upper() != 'NA' and holder != '""'

    # Try Team Cymru first
    cymru_data = query_team_cymru(subnet)
    if cymru_data and is_valid_data(cymru_data['data']['asns'][0]['asn'], cymru_data['data']['asns'][0].get('holder', '')):
        print(f"  → Found valid data via Team Cymru")
        return cymru_data

    # Try each RIR's APIs
    print(f"  → Trying RIR APIs...")
    for rir, endpoints in ROUTING_APIS.items():
        for endpoint in endpoints:
            data = query_rir_api(endpoint, subnet)
            if data:
                if rir == 'RIPE':
                    if data.get('data', {}).get('asns'):
                        asn = data['data']['asns'][0].get('asn', 'NA')
                        holder = data['data']['asns'][0].get('holder', 'NA')
                        if is_valid_data(asn, holder):
                            print(f"  → Found valid data via RIPE")
                            return {'data': {'asns': [{'asn': str(asn), 'holder': f'"{holder}"'}]}}
                
                elif rir == 'LACNIC':
                    if data.get('entities'):
                        asn = data['entities'][0].get('handle', 'NA').replace('AS', '')
                        holder = data['entities'][0].get('name', 'NA')
                        if is_valid_data(asn, holder):
                            print(f"  → Found valid data via LACNIC")
                            return {'data': {'asns': [{'asn': asn, 'holder': f'"{holder}"'}]}}
                
                elif rir == 'APNIC':
                    if data.get('entities'):
                        asn = data['entities'][0].get('handle', 'NA').replace('AS', '')
                        holder = data['entities'][0].get('name', 'NA')
                        if is_valid_data(asn, holder):
                            print(f"  → Found valid data via APNIC")
                            return {'data': {'asns': [{'asn': asn, 'holder': f'"{holder}"'}]}}
                
                elif rir == 'AFRINIC':
                    if data.get('entities'):
                        asn = data['entities'][0].get('handle', 'NA').replace('AS', '')
                        holder = data['entities'][0].get('name', 'NA')
                        if is_valid_data(asn, holder):
                            print(f"  → Found valid data via AFRINIC")
                            return {'data': {'asns': [{'asn': asn, 'holder': f'"{holder}"'}]}}
                
                elif rir == 'ARIN':
                    if data.get('handle'):
                        asn = data.get('originASNs', {}).get('originASN', [{}])[0].get('originAS', 'NA').replace('AS', '')
                        holder = data.get('name', 'NA')
                        if is_valid_data(asn, holder):
                            print(f"  → Found valid data via ARIN")
                            return {'data': {'asns': [{'asn': asn, 'holder': f'"{holder}"'}]}}

    # Fallback to RDAP/WHOIS lookup using ipwhois
    print(f"  → Falling back to RDAP/WHOIS lookup...")
    sample_ip = get_sample_ip_for_subnet(subnet, INPUT_FILE)
    if sample_ip:
        try:
            print(f"  → Using sample IP: {sample_ip}")
            obj = IPWhois(sample_ip)
            results = obj.lookup_rdap()
            
            if results.get('asn') and results.get('network', {}).get('name'):
                asn = results['asn']
                holder = results['network']['name']
                country = results.get('asn_country_code', '')
                
                if is_valid_data(asn, holder):
                    print(f"  → Found valid data via RDAP")
                    return {
                        'data': {
                            'asns': [{
                                'asn': asn,
                                'holder': f'"{holder}"',
                                'country': country
                            }]
                        }
                    }
        except (IPDefinedError, HTTPLookupError) as e:
            if verbose:
                print(f"  → RDAP lookup failed: {str(e)}")
        except Exception as e:
            if verbose:
                print(f"  → Error during RDAP lookup: {str(e)}")
    
    print(f"  → No valid data found from any source")
    return {'data': {'asns': [{'asn': 'NA', 'holder': '"NA"'}]}}

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

def find_checkpoint_files():
    checkpoint_files = [f for f in os.listdir('.') if f.startswith(f'{OUTPUT_FILE_PREFIX}_checkpoint_')]
    return checkpoint_files

def get_related_files(checkpoint_file):
    timestamp = checkpoint_file.replace(f'{OUTPUT_FILE_PREFIX}_checkpoint_', '').replace('.txt', '')
    return {
        'summary': f'{OUTPUT_FILE_PREFIX}_{timestamp}.csv',
        'detailed': f'{OUTPUT_FILE_PREFIX}_detailed_{timestamp}.csv'
    }

def process_routes(check_missing=False, use_checkpoint=False, verbose=False):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f'{OUTPUT_FILE_PREFIX}_{timestamp}.csv'
    detailed_output = f'{OUTPUT_FILE_PREFIX}_detailed_{timestamp}.csv'
    checkpoint_file = f'{OUTPUT_FILE_PREFIX}_checkpoint_{timestamp}.txt'
    
    # Initialize processed_subnets set
    processed_subnets = set()
    
    # Handle checkpoint selection if requested
    if use_checkpoint:
        checkpoint_files = find_checkpoint_files()
        if checkpoint_files:
            print("\nFound checkpoint files:")
            print("0. Start new process (ignore checkpoints)")
            for idx, cf in enumerate(checkpoint_files, 1):
                related = get_related_files(cf)
                print(f"{idx}. {cf}")
                print(f"   Related files: {related['summary']}, {related['detailed']}")
            
            choice = int(input("\nEnter number (0 to start new): "))
            if choice == 0:
                print("\nStarting new process.")
            elif 0 < choice <= len(checkpoint_files):
                checkpoint_file = checkpoint_files[choice-1]
                related_files = get_related_files(checkpoint_file)
                output_file = related_files['summary']
                detailed_output = related_files['detailed']
                
                with open(checkpoint_file, 'r') as f:
                    processed_subnets = set(f.read().splitlines())
                print(f"\nContinuing from checkpoint: {checkpoint_file}")
                print(f"Previously processed subnets: {len(processed_subnets)}")
            else:
                print("\nInvalid selection. Starting new process.")
        else:
            print("No checkpoint files found. Starting new process.")
    
    subnets, subnet_counts = get_unique_subnets(INPUT_FILE)
    total_subnets = len(subnets)
    
    print(f"Starting global network data collection for {total_subnets} unique subnets")
    
    # Create CSV files with headers if they don't exist
    if not os.path.exists(output_file):
        pd.DataFrame(columns=['subnet', 'asn', 'asn_desc', 'country', 'count']).to_csv(output_file, index=False)
    
    if not os.path.exists(detailed_output):
        with open(detailed_output, 'w') as outfile:
            outfile.write("original_line,subnet,asn,asn_desc,country\n")
    
    for idx, subnet in enumerate(subnets, 1):
        if subnet in processed_subnets:
            print(f"[{idx}/{total_subnets}] Skipping already processed subnet: {subnet}")
            continue
            
        print(f"[{idx}/{total_subnets}] Processing subnet: {subnet}")
        route_data = get_route_data(subnet, verbose)
        
        try:
            if route_data['data'].get('asns'):
                asn = route_data['data']['asns'][0]['asn']
                print(f"  → Found ASN: {asn}")
                
                asn_data = get_asn_info(asn)
                holder = asn_data['data'].get('holder', route_data['data']['asns'][0].get('holder', ''))
                country = asn_data['data'].get('country', route_data['data']['asns'][0].get('country', ''))
                
                print(f"  → Retrieved ASN details: {holder}")
                
                # Write to summary file incrementally
                with open(output_file, 'a') as f:
                    pd.DataFrame([{
                        'subnet': subnet,
                        'asn': str(asn),
                        'asn_desc': holder,
                        'country': country,
                        'count': subnet_counts[subnet]
                    }]).to_csv(f, header=False, index=False)
                
                # Write to detailed file incrementally
                with open(INPUT_FILE, 'r') as infile, open(detailed_output, 'a') as outfile:
                    for line in infile:
                        ip = line.split()[1]
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
                            outfile.write(f"{line.strip()},{subnet},{asn},{holder},{country}\n")
            else:
                print(f"  → No routing data found for {subnet}")
            
            # Save checkpoint after each successful processing
            with open(checkpoint_file, 'a') as f:
                f.write(f"{subnet}\n")
            processed_subnets.add(subnet)
            
        except Exception as e:
            if verbose:
                print(f"  → Error processing {subnet}: {str(e)}")
            continue
        
        time.sleep(RATE_LIMIT_DELAY/1000)
    
    if check_missing:
        print("\nChecking for missing ASN information...")
        df_detailed = pd.read_csv(detailed_output, dtype={'asn': str, 'asn_desc': str})
        df_summary = pd.read_csv(output_file, dtype={'asn': str, 'asn_desc': str})
        
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
                    
                    df_detailed.loc[index, 'asn'] = str(asn)
                    df_detailed.loc[index, 'asn_desc'] = str(asn_desc)
                    
                    summary_idx = df_summary[df_summary['subnet'] == subnet].index
                    if not summary_idx.empty:
                        df_summary.loc[summary_idx[0], 'asn'] = str(asn)
                        df_summary.loc[summary_idx[0], 'asn_desc'] = str(asn_desc)
                    
                    updated = True
                else:
                    if verbose:
                        print(f"  → No additional data found")
                
                time.sleep(RATE_LIMIT_DELAY/1000)
            
            if updated:
                df_detailed.to_csv(detailed_output, index=False)
                df_summary.to_csv(output_file, index=False)
                print("\nUpdated both detailed and summary outputs with new ASN information")
        else:
            print("No missing ASN entries found")
    
    # Clean up checkpoint file after successful completion
    if os.path.exists(checkpoint_file):
        os.remove(checkpoint_file)
    
    print(f"\nData collection complete!")
    print(f"Processed {total_subnets} unique subnets")
    print(f"Summary results exported to: {output_file}")
    print(f"Detailed results exported to: {detailed_output}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-missing', action='store_true', help='Check and update missing ASN information')
    parser.add_argument('--checkpoint', action='store_true', help='Use existing checkpoint if available')
    parser.add_argument('--verbose', action='store_true', help='Show detailed error messages and status codes')
    args = parser.parse_args()
    
    process_routes(check_missing=args.check_missing, use_checkpoint=args.checkpoint, verbose=args.verbose)