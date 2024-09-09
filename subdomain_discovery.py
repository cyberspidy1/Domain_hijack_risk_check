import subprocess
import json

class SubdomainDiscovery:
    def __init__(self, domain):
        self.domain = domain
    
    def discover_subdomains(self):
        print(f"Discovering subdomains for {self.domain}...")
        subdomains = self.run_sublister(self.domain)
        return subdomains
    
    def run_sublister(self, domain):
        result = subprocess.run(
            ["sublist3r", "-d", domain, "-o", f"{domain}_subdomains.txt"],
            stdout=subprocess.PIPE
        )
        with open(f"{domain}_subdomains.txt") as f:
            subdomains = [line.strip() for line in f.readlines()]
        return subdomains

