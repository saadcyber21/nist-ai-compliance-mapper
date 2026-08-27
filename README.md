🛡️ AI SecGuard: Enterprise NIST & SAST Engine

DevSecOps toolkit featuring a "Compliance-as-Code" mapper for the NIST AI RMF and a mathematical Abstract Syntax Tree (AST) scanner to prevent OWASP LLM vulnerabilities.

⚡ The Problem: AI Moves Fast, Security Lags

As enterprises race to deploy AI Agents (LangChain, AutoGPT) and LLMs, manual security audits bottleneck production and expose organizations to massive regulatory fines (e.g., the EU AI Act). Traditional text-based security scanners fail to understand the complex execution contexts of AI-generated code.

🚀 The Solution: Dual-Engine DevSecOps

This repository provides a zero-dependency, dual-engine toolkit designed to be dropped directly into enterprise CI/CD pipelines:

Governance-as-Code (CLI): Parses AI system architecture JSON files and dynamically generates executive-ready Markdown audit reports mapping to the NIST AI Risk Management Framework.

Mathematical AST Scanner (SAST): A custom built Static Application Security Testing engine that compiles Python source code into an Abstract Syntax Tree (AST) to mathematically detect hardcoded secrets and dangerous LLM code execution paths (OWASP LLM02/LLM04).

🏗️ System Architecture

graph TD
    subgraph Phase 1: GRC Automation
        A[architecture.json] -->|Parsed via CLI| C(NIST Rule Engine)
        C -->|Evaluates Constraints| R[audit_report.md]
    end

    subgraph Phase 2: Code Security Analysis
        B[vulnerable_app.py] -->|Parsed to AST Nodes| S(SAST Engine)
        S -->|Detects OWASP Violations| F{Pipeline Pass/Fail}
    end


💻 Engine 1: AST Security Scanner (SAST)

Instead of relying on basic regex string matching, this engine uses Python's native ast library to deeply understand execution paths and flag dangerous LLM implementation patterns before compilation.

Execution

python sast_engine.py vulnerable_app.py


Example Detection Output

==================================================
🔍 INITIALIZING AST SECURITY SCANNER
==================================================
[*] Scanning vulnerable_app.py...
[!] Scan Complete. Found 2 severe vulnerabilities:

 -> Line 9 | Hardcoded Secret Detected (CRITICAL)
    Details: Sensitive data assigned to 'LLM_API_KEY' in plaintext.

 -> Line 19 | Insecure Output Handling (OWASP LLM04) (CRITICAL)
    Details: Dangerous use of eval(). Never pass LLM output directly to execution functions.
==================================================


📊 Engine 2: NIST AI Compliance Mapper

Automates the generation of GRC documentation. Feeds architectural metadata into a rule engine to instantly output remediation steps for compliance blindspots.

Execution

python nist_mapper.py --config architecture.json --output audit_report.md


Supported Frameworks

NIST AI 100-1: Artificial Intelligence Risk Management Framework

OWASP LLM Top 10: Specifically targeting LLM02 (Insecure Output Handling) and LLM04 (Model Denial of Service).

EU AI Act: Data privacy, PII scrubbing (e.g., Presidio pipeline enforcement), and localized model hosting constraints.

🔧 Installation & CI/CD Integration

Zero external dependencies required. Built with 100% standard Python libraries to ensure seamless integration into heavily restricted enterprise environments.

git clone https://github.com/YOUR_USERNAME/nist-ai-compliance-mapper.git
cd nist-ai-compliance-mapper


Designed to fail CI/CD builds (sys.exit(1)) when OWASP vulnerabilities are mathematically proven in the AST structure.

Developed for Enterprise DevSecOps, GRC Automation, and Secure AI Agent Deployment.
