#!/usr/bin/env python3
import nmap
import socket
import netifaces
import requests
import concurrent.futures
from datetime import datetime
import json

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'network_info': {},
            'hosts': []
        }

    def get_network_info(self):
        """Gather basic network interface information and detect network range"""
        self.network_range = None
        
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip_addr = ip_info['addr']
                    netmask = ip_info['netmask']
                    
                    # Skip loopback and special use addresses
                    if ip_addr.startswith('127.') or ip_addr.startswith('169.254'):
                        continue
                        
                    # Calculate network range from IP and netmask
                    ip_parts = [int(part) for part in ip_addr.split('.')]
                    mask_parts = [int(part) for part in netmask.split('.')]
                    network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                    network_addr = '.'.join(map(str, network_parts))
                    
                    # Store interface information
                    self.results['network_info'][interface] = {
                        'ip': ip_addr,
                        'netmask': netmask,
                        'network': network_addr
                    }
                    
                    # Set network range for scanning (first found non-loopback interface)
                    if not self.network_range:
                        # Calculate CIDR notation
                        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                        self.network_range = f"{network_addr}/{cidr}"
                        
            except Exception as e:
                print(f"Error getting info for interface {interface}: {e}")

    def scan_host(self, host):
        """Scan an individual host"""
        try:
            # Enhanced scan with OS detection, version detection, script scanning, and timing
            self.nm.scan(host, arguments='-sS -sV -O -A -T4 --script=default,vuln')
            
            if host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'os_matches': [],
                    'ports': [],
                    'vulnerabilities': []
                }
                
                # Get OS detection results
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        os_info = {
                            'name': osmatch['name'],
                            'accuracy': osmatch['accuracy'],
                            'osclass': [{
                                'type': osclass.get('type', ''),
                                'vendor': osclass.get('vendor', ''),
                                'osfamily': osclass.get('osfamily', ''),
                                'osgen': osclass.get('osgen', '')
                            } for osclass in osmatch.get('osclass', [])]
                        }
                        host_info['os_matches'].append(os_info)

                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        port_data = {
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'cpe': port_info.get('cpe', []),
                            'scripts': {}
                        }
                        
                        # Get script results for the port
                        if 'script' in port_info:
                            port_data['scripts'] = port_info['script']
                            
                            # Extract vulnerability information
                            for script_name, script_output in port_info['script'].items():
                                if any(x in script_name.lower() for x in ['vuln', 'exploit', 'security', 'ssl']):
                                    host_info['vulnerabilities'].append({
                                        'port': port,
                                        'type': script_name,
                                        'details': script_output
                                    })
                        
                        host_info['ports'].append(port_data)
                
                return host_info
        except Exception as e:
            print(f"Error scanning host {host}: {e}")
        return None

    def scan_network(self, network):
        """Scan entire network range"""
        self.get_network_info()
        
        # Perform initial ping sweep to find active hosts
        self.nm.scan(hosts=network, arguments='-sn')
        active_hosts = self.nm.all_hosts()
        
        # Scan active hosts in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_host = {executor.submit(self.scan_host, host): host 
                            for host in active_hosts}
            
            for future in concurrent.futures.as_completed(future_to_host):
                host_info = future.result()
                if host_info:
                    self.results['hosts'].append(host_info)

    def generate_report(self):
        """Generate a summary report"""
        total_hosts = len(self.results['hosts'])
        open_ports = sum(len([p for p in host['ports'] if p['state'] == 'open']) 
                        for host in self.results['hosts'])
        
        report = {
            'summary': {
                'total_hosts': total_hosts,
                'total_open_ports': open_ports,
                'scan_time': self.results['scan_time']
            },
            'details': self.results
        }
        
        return report

    def save_results(self, filename='network_scan.json'):
        """Save scan results to file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)

def main():
    scanner = NetworkScanner()
    
    # Get network info first
    scanner.get_network_info()
    
    if not scanner.network_range:
        print("Error: Could not detect network range. Are you connected to a network?")
        return
        
    print(f"Detected network range: {scanner.network_range}")
    print("Network interfaces found:")
    for interface, info in scanner.results['network_info'].items():
        print(f"  {interface}: {info['ip']} (network: {info['network']}, netmask: {info['netmask']})")
    
    print(f"\nStarting network scan of {scanner.network_range}")
    scanner.scan_network(scanner.network_range)
    report = scanner.generate_report()
    
    print("\nScan Summary:")
    print(f"Total hosts found: {report['summary']['total_hosts']}")
    print(f"Total open ports: {report['summary']['total_open_ports']}")
    
    scanner.save_results()
    print("\nDetailed results saved to network_scan.json")

if __name__ == "__main__":
    main()
