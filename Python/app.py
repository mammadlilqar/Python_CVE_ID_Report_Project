from flask import Flask, render_template, request

import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__)

def fetch_cve_info(cve_id):
    cve_id = cve_id.upper()  # Convert to uppercase for consistency

    # Validate the CVE ID format
    if not re.match(r'^CVE-\d{4}-\d{4,6}$', cve_id):
        return None, None, None, None  # Return None for MITRE data

    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"

    nvd_response = requests.get(nvd_url)
    mitre_response = requests.get(mitre_url)

    nvd_description = None
    nvd_severity = None
    mitre_description = None
    mitre_severity = None
    if nvd_response.status_code == 200:
        nvd_soup = BeautifulSoup(nvd_response.content, "html.parser")
        nvd_description_element = nvd_soup.find("p", attrs={"data-testid": "vuln-description"})
        nvd_severity_element = nvd_soup.find("span", class_="severityDetail")

        nvd_description = nvd_description_element.text.strip() if nvd_description_element else "Description not found on NVD page."
        nvd_severity = nvd_severity_element.text.strip() if nvd_severity_element else "Severity not found on NVD page."

    if mitre_response.status_code == 200:
        mitre_soup = BeautifulSoup(nvd_response.content, "html.parser")
        mitre_description_element = mitre_soup.find("p", attrs={"data-testid": "vuln-description"})
        mitre_severity_element = mitre_soup.find("span", class_="severityDetail")

        mitre_description = mitre_description_element.text.strip() if mitre_description_element else "Description not found on NVD page."
        mitre_severity = mitre_severity_element.text.strip() if mitre_severity_element else "Severity not found on NVD page."

    return nvd_description, nvd_severity, mitre_description,mitre_severity

def generate_report(cve_id, nvd_description, nvd_severity, mitre_description,mitre_severity):
    report = f"CVE ID: {cve_id}\n"
    report += f"NVD Description: {nvd_description}\n"
    report += f"NVD Severity: {nvd_severity}\n"
    report += f"MITRE Description: {mitre_description}\n"
    report += f"MITRE Severity: {mitre_severity}\n"
    return report

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        cve_id = request.form["cve_id"].replace(" ", "")  # Remove spaces
        
        # Validate the CVE ID format
        if not re.match(r'^CVE-\d{4}-\d{4,6}$', cve_id):
            error_message = "Invalid CVE ID format. Please enter a valid CVE ID."
            return render_template("index.html", error_message=error_message)

        nvd_description, nvd_severity, mitre_description,mitre_severity = fetch_cve_info(cve_id)

        if nvd_description:
            report = generate_report(cve_id, nvd_description, nvd_severity, mitre_description,mitre_severity)
            return render_template("report.html", report=report)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
