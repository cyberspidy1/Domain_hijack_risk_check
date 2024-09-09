import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm

class ReportGenerator:
    def __init__(self, domain, results):
        self.domain = domain
        self.results = results
        self.test_types = [
            "DNS Status Check",
            "HTTP Response Check",
            "Cloud Resource Check (e.g., S3 buckets)",
            "Wildcard Subdomain Check",
            "Orphan CNAME Check",
        ]

    def generate_report(self):
        self.generate_summary()
        self.generate_detailed_report()
        self.generate_pie_chart()

    def generate_summary(self):
        # Prepare summary data
        summary_data = {
            'Subdomain': [],
            'Hijacking Risk': [],
            'Context': []
        }

        print("Running the scan and collecting results:")
        for subdomain, data in tqdm(self.results.items(), desc="Scanning Subdomains"):
            hijacking_risk = data['subdomain_hijacking']
            context = self._generate_context(hijacking_risk, data)
            summary_data['Subdomain'].append(subdomain)
            summary_data['Hijacking Risk'].append(hijacking_risk)
            summary_data['Context'].append(context)

        # Create a DataFrame for summary
        df_summary = pd.DataFrame(summary_data)

        # Save to Excel with a "Tests Performed" sheet
        summary_file = f"{self.domain}_summary.xlsx"
        with pd.ExcelWriter(summary_file, engine='openpyxl') as writer:
            df_summary.to_excel(writer, sheet_name='Summary', index=False)
            self._add_tests_performed_sheet(writer)

    def generate_detailed_report(self):
        # Prepare detailed report data
        detailed_data = {
            'Subdomain': [],
            'DNS Status': [],
            'HTTP Status': [],
            'Hijacking Risk': [],
            'Cloud Resource': [],
            'Wildcard Check': [],
            'Orphan CNAME': [],
            'Context': []
        }

        for subdomain, data in self.results.items():
            hijacking_risk = data['subdomain_hijacking']
            context = self._generate_context(hijacking_risk, data)
            detailed_data['Subdomain'].append(subdomain)
            detailed_data['DNS Status'].append(data['dns_status'])
            detailed_data['HTTP Status'].append(data['http_status'])
            detailed_data['Hijacking Risk'].append(hijacking_risk)
            detailed_data['Cloud Resource'].append(data['cloud_resource_check'])
            detailed_data['Wildcard Check'].append(data['wildcard_check'])
            detailed_data['Orphan CNAME'].append(data['cname_orphan_check'])
            detailed_data['Context'].append(context)

        # Create a DataFrame for detailed report
        df_detailed = pd.DataFrame(detailed_data)

        # Save to Excel
        detailed_file = f"{self.domain}_detailed_report.xlsx"
        with pd.ExcelWriter(detailed_file, engine='openpyxl') as writer:
            df_detailed.to_excel(writer, sheet_name='Detailed Report', index=False)

    def _generate_context(self, hijacking_risk, data):
        """
        Generate context and explanations based on the hijacking risk and associated data.
        """
        if hijacking_risk == "Unresolved (Danger of Hijacking)":
            return ("This subdomain's DNS does not resolve, meaning there could be a dangling DNS entry "
                    "or an orphaned resource pointing to an external service, making it vulnerable to "
                    "hijacking if an attacker claims the resource.")
        elif hijacking_risk == "Potential Hijacking":
            return ("This subdomain resolves but has no valid HTTP response, indicating a possible orphaned resource "
                    "like a cloud service (e.g., AWS S3, Heroku) that could be claimed by an attacker.")
        elif data['cloud_resource_check'] == "Orphaned S3 Bucket":
            return "The subdomain points to an orphaned cloud resource (e.g., an S3 bucket) that could be claimed and abused by an attacker."
        elif data['wildcard_check'] == "Wildcard Record Detected":
            return "This subdomain has a wildcard DNS record, which means any non-existent subdomain resolves to this record, potentially exposing unintended services."
        elif data['cname_orphan_check'] == "Orphaned CNAME":
            return "This subdomain has an orphaned CNAME record pointing to a deleted or non-existent resource, making it hijackable by an attacker who claims the target resource."
        else:
            return "This subdomain appears safe with no clear hijacking risk."

    def _add_tests_performed_sheet(self, writer):
        """
        Add a sheet to the Excel file detailing the tests performed during the scan.
        """
        test_data = {
            "Test Type": self.test_types,
            "Description": [
                "Check if the DNS for the subdomain resolves properly.",
                "Check if the subdomain returns a valid HTTP response.",
                "Check if the subdomain points to an orphaned cloud resource (e.g., AWS S3, Heroku).",
                "Check for wildcard DNS records that can lead to unintended exposure.",
                "Check if the subdomain's CNAME record points to a deleted or non-existent service."
            ]
        }

        df_tests = pd.DataFrame(test_data)
        df_tests.to_excel(writer, sheet_name='Tests Performed', index=False)

    def generate_pie_chart(self):
        """
        Generate a pie chart to visualize the hijacking risk distribution.
        """
        hijacking_risks = [data['subdomain_hijacking'] for data in self.results.values()]
        risk_labels, risk_counts = pd.Series(hijacking_risks).value_counts().index, pd.Series(hijacking_risks).value_counts().values

        plt.figure(figsize=(6, 6))
        plt.pie(risk_counts, labels=risk_labels, autopct='%1.1f%%', colors=['#ff9999', '#66b3ff', '#99ff99', '#ffcc99'])
        plt.title(f"Subdomain Hijacking Risk Distribution for {self.domain}")
        plt.savefig(f"{self.domain}_hijacking_risk_pie_chart.png")
        plt.show()

