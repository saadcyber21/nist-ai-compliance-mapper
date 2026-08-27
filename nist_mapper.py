import json
import argparse
import datetime
import sys

class AIGovernanceRulesEngine:
    """Evaluates AI architecture against NIST AI RMF and OWASP LLM Frameworks."""
    
    def __init__(self):
        # A mock enterprise ruleset
        self.rules = [
            {
                "id": "NIST-AI-RMF-MAP-1.5",
                "framework": "NIST AI RMF",
                "name": "Data Classification & Privacy Risk",
                "condition": lambda config: config.get("data_classification") in ["PII", "PHI"] and "Data_Anonymization" not in config.get("security_controls", []),
                "severity": "CRITICAL",
                "finding": "System processes PII but lacks a Data Anonymization control.",
                "recommendation": "Implement a Data Anonymization pipeline (e.g., Presidio) before LLM ingestion to comply with GDPR and EU AI Act."
            },
            {
                "id": "OWASP-LLM02",
                "framework": "OWASP Top 10 for LLMs",
                "name": "Insecure Output Handling",
                "condition": lambda config: config.get("infrastructure", {}).get("network_exposure") == "public_api" and "Output_Sanitization" not in config.get("security_controls", []),
                "severity": "HIGH",
                "finding": "Public facing API lacks LLM output sanitization.",
                "recommendation": "Add Output Sanitization middleware to prevent XSS and SSRF attacks originating from LLM hallucinations."
            },
            {
                "id": "NIST-AI-RMF-GOV-2.1",
                "framework": "NIST AI RMF",
                "name": "Vendor Model Transparency",
                "condition": lambda config: config.get("llm_provider") in ["OpenAI", "Anthropic", "Google"],
                "severity": "MEDIUM",
                "finding": "Dependency on closed-source external LLM provider.",
                "recommendation": "Ensure vendor SLAs include continuous red-teaming reports and establish a failover to a localized open-source model (e.g., Llama 3) for business continuity."
            }
        ]

    def scan(self, architecture_config: dict) -> list:
        findings = []
        for rule in self.rules:
            if rule["condition"](architecture_config):
                findings.append({
                    "id": rule["id"],
                    "framework": rule["framework"],
                    "severity": rule["severity"],
                    "finding": rule["finding"],
                    "recommendation": rule["recommendation"]
                })
        return findings

def generate_markdown_report(project_name: str, findings: list, output_file: str):
    """Generates a professional Markdown audit report."""
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    md_content = f"# 🛡️ Automated AI Compliance Audit Report\n"
    md_content += f"**Project:** {project_name}  \n"
    md_content += f"**Audit Date:** {date_str}  \n"
    md_content += f"**Status:** {'🔴 FAILED (Critical Findings)' if any(f['severity'] == 'CRITICAL' for f in findings) else '🟡 WARNING'}\n\n"
    md_content += "---\n\n## 📊 Executive Summary\n"
    md_content += f"The automated DevSecOps scanner identified **{len(findings)}** compliance violations against the NIST AI Risk Management Framework (RMF) and OWASP LLM Top 10.\n\n"
    
    md_content += "## 🚨 Detailed Findings\n\n"
    
    for idx, finding in enumerate(findings, 1):
        md_content += f"### {idx}. [{finding['severity']}] {finding['id']} ({finding['framework']})\n"
        md_content += f"- **Vulnerability:** {finding['finding']}\n"
        md_content += f"- **Remediation:** {finding['recommendation']}\n\n"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(md_content)

def main():
    parser = argparse.ArgumentParser(description="Automated NIST AI RMF Compliance Scanner")
    parser.add_argument("--config", type=str, required=True, help="Path to the architecture JSON file")
    parser.add_argument("--output", type=str, default="audit_report.md", help="Output path for the Markdown report")
    args = parser.parse_args()

    print("\n" + "="*50)
    print("🏛️  INITIALIZING NIST AI COMPLIANCE SCANNER")
    print("="*50)
    
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
        print(f"[*] Loaded Architecture: {config.get('project_name')} (v{config.get('version')})")
    except Exception as e:
        print(f"[!] Error loading config: {e}")
        sys.exit(1)

    print("[*] Engaging Rule Engine (NIST AI RMF, OWASP LLM, EU AI Act)...")
    engine = AIGovernanceRulesEngine()
    findings = engine.scan(config)

    print(f"[*] Scan Complete. Found {len(findings)} violations.")
    
    generate_markdown_report(config.get('project_name'), findings, args.output)
    
    print(f"[+] Audit Report generated successfully: {args.output}")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()