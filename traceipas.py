import subprocess
import requests
import re

def trace_as(target):
    trace_output = []
    try:
        trace_result = subprocess.check_output(['tracert', target]).decode('latin-1')
        trace_output = trace_result.splitlines()
    except Exception as e:
        raise RuntimeError(f"Traceroute failed: {e}")
    
    as_info = {}
    ipv4_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b' 
    ipv6_regex = r'([a-f0-9:]+:+)+[a-f0-9]+'
    for line in trace_output:
        ipv4_match = re.search(ipv4_regex, line)
        ipv6_match = re.search(ipv6_regex, line)
        if ipv4_match:
            ip_address = ipv4_match.group()
        elif ipv6_match:
            ip_address = ipv6_match.group()
        else:
            continue
        as_info[ip_address] = get_as(ip_address)
    
    return as_info

def get_as(ip_address):
    response = requests.get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip_address}")
    response_country = requests.get(f"https://stat.ripe.net/data/rir/data.json?resource={ip_address}&lod=2")
    data = response.json()
    data_country = response_country.json()

    as_number = data["data"]["asns"][0]["asn"] if data["data"]["asns"] else "Unknown"

    country = None
    if "data" in data_country and "rirs" in data_country["data"] and data_country["data"]["rirs"]:
        for rir in data_country["data"]["rirs"]:
            if rir.get("country"):
                country = rir["country"]
                break

    provider = data["data"]["asns"][0]["holder"] if data["data"]["asns"] else "Unknown"

    return as_number, country, provider

if __name__ == "__main__":
    target = input("Enter domain name or IP address: ")
    as_info = trace_as(target)
    print("{: >5} {: >30} {: >20} {: >10} {: >30}".format("# N", "IP", "AS", "Country", "Provider"))
    for i, (ip, info) in enumerate(as_info.items(), start=1):
        as_number, country, provider = info
        print("{: >5} {: >30} {: >20} {: >10} {: >30}".format(i, ip, as_number, country, provider))