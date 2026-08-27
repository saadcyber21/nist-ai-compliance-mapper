📊 Automated NIST AI Risk & Compliance Mapper

DevSecOps CLI tool for automated "Compliance-as-Code" scanning against the NIST AI RMF and OWASP LLM Top 10.

📖 Executive Summary

As enterprise AI adoption scales, manual compliance audits bottleneck deployment and expose organizations to regulatory fines (e.g., EU AI Act).

The NIST AI Compliance Mapper introduces Governance-as-Code. By parsing standard application architecture files (JSON), this DevSecOps CLI tool automatically evaluates security controls against the NIST AI Risk Management Framework (RMF) and the OWASP LLM Top 10, instantly generating executive-ready Markdown audit reports.

🏗️ Architecture & Workflow

Input: Developers define their AI infrastructure, data classification, and security controls in a standard architecture.json file.

Analysis: The CLI engine ingests the configuration and evaluates it against a programmatic Rule Engine of NIST and OWASP constraints.

Output: A dynamically generated audit_report.md detailing Critical/High/Medium vulnerabilities and actionable remediation steps.

🚀 Quick Start

This tool is built with 100% standard Python libraries. Zero dependencies required.

1. Define Architecture

Review the sample architecture.json file. Notice it is processing PII but lacks a Data_Anonymization control.

2. Run the Compliance Scan

python nist_mapper.py --config architecture.json --output audit_report.md


3. Review the Output

The tool will evaluate the JSON and generate a highly formatted audit_report.md file in your directory outlining the specific NIST and OWASP violations.

🎯 Supported Frameworks

NIST AI 100-1: Artificial Intelligence Risk Management Framework (AI RMF)

OWASP LLM: Top 10 Vulnerabilities for Large Language Model Applications

EU AI Act: Data privacy and localized hosting constraints

Developed for Enterprise DevSecOps & GRC Automation.