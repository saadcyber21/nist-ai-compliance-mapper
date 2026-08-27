"""
FAANG-Grade Static Application Security Testing (SAST) Engine.
Uses Abstract Syntax Tree (AST) parsing to mathematically deconstruct 
and evaluate Python source code for OWASP LLM Vulnerabilities.
"""
import ast
import sys
import os

class SecurityASTVisitor(ast.NodeVisitor):
    """Walks the AST nodes to detect insecure coding patterns."""
    def __init__(self):
        self.vulnerabilities = []

    def visit_Assign(self, node):
        """Rule 1: Detect hardcoded API keys (Credential Leakage)."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(keyword in var_name for keyword in ['api_key', 'secret', 'token']):
                    # Check if the assigned value is a raw string/constant
                    if isinstance(node.value, ast.Constant):
                        self.vulnerabilities.append({
                            "line": node.lineno,
                            "type": "Credential Leakage",
                            "description": f"Hardcoded secret detected in variable '{target.id}'."
                        })
        self.generic_visit(node)

    def visit_Call(self, node):
        """Rule 2: Detect dangerous execution of LLM Outputs (OWASP LLM02)."""
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.vulnerabilities.append({
                    "line": node.lineno,
                    "type": "Insecure Output Handling (OWASP LLM02)",
                    "description": f"Dangerous '{node.func.id}()' detected. If an LLM hallucinates code here, it executes with system privileges."
                })
        self.generic_visit(node)

def scan_file(filepath: str):
    """Parses a Python file into an AST and evaluates security rules."""
    print(f"[*] Compiling Abstract Syntax Tree for: {filepath}")
    
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        source_code = f.read()

    try:
        # Convert raw source code into an Abstract Syntax Tree
        tree = ast.parse(source_code)
    except SyntaxError as e:
        print(f"[!] Syntax error in target file: {e}")
        return

    # Initialize the visitor and walk the tree
    analyzer = SecurityASTVisitor()
    analyzer.visit(tree)

    print("\n" + "="*50)
    print(f"🛡️  AST SECURITY SCAN RESULTS: {filepath}")
    print("="*50)
    
    if not analyzer.vulnerabilities:
        print("[+] No vulnerabilities detected. Code is clean.")
    else:
        for v in analyzer.vulnerabilities:
            print(f"[Line {v['line']}] [{v['type']}]")
            print(f"  -> {v['description']}\n")
    print("="*50)

if __name__ == "__main__":
    # If a file is passed via CLI, scan it. Otherwise, scan the local vulnerable file.
    target = sys.argv[1] if len(sys.argv) > 1 else "vulnerable_app.py"
    scan_file(target)