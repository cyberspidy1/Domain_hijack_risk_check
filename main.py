from subdomain_discovery import SubdomainDiscovery
from vulnerability_checker import VulnerabilityChecker
from report_generator import ReportGenerator

def main(domain):
    # Step 1: Subdomain Discovery
    discovery = SubdomainDiscovery(domain)
    subdomains = discovery.discover_subdomains()
    
    # Step 2: Vulnerability Checking
    checker = VulnerabilityChecker(domain, subdomains)
    results = checker.check_vulnerabilities()
    
    # Step 3: Report Generation
    report = ReportGenerator(domain, results)
    report.generate_report()

if __name__ == "__main__":
    domain = input("Enter the domain: ")
    main(domain)

