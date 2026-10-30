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

def scan_file(filepath: str, quiet: bool = False):
    """Parse a Python file into an AST and evaluate the security rules.

    Returns ``(vulnerabilities, error)`` where ``vulnerabilities`` is the list of
    finding dicts and ``error`` is a string when the file could not be scanned at
    all.

    Returning the findings is what makes this usable as a gate. The original
    version only printed them and returned None, which meant no caller -- and no
    CI step -- could distinguish "clean" from "three hardcoded credentials".
    A scanner that cannot fail a build is a demo, not a control.
    """
    def emit(*args):
        if not quiet:
            print(*args)

    emit(f"[*] Compiling Abstract Syntax Tree for: {filepath}")

    if not os.path.exists(filepath):
        emit(f"[!] File not found: {filepath}")
        return [], f"file not found: {filepath}"

    with open(filepath, "r", encoding="utf-8") as f:
        source_code = f.read()

    try:
        # Convert raw source code into an Abstract Syntax Tree
        tree = ast.parse(source_code)
    except SyntaxError as e:
        emit(f"[!] Syntax error in target file: {e}")
        return [], f"syntax error: {e}"

    # Initialize the visitor and walk the tree
    analyzer = SecurityASTVisitor()
    analyzer.visit(tree)

    emit("\n" + "="*50)
    emit(f"🛡️  AST SECURITY SCAN RESULTS: {filepath}")
    emit("="*50)

    if not analyzer.vulnerabilities:
        emit("[+] No vulnerabilities detected. Code is clean.")
    else:
        for v in analyzer.vulnerabilities:
            emit(f"[Line {v['line']}] [{v['type']}]")
            emit(f"  -> {v['description']}\n")
    emit("="*50)
    emit(f"Total findings: {len(analyzer.vulnerabilities)}")

    return analyzer.vulnerabilities, None

def main(argv=None) -> int:
    """CLI entry point. Exits non-zero when findings exist, so CI can gate."""
    import argparse

    ap = argparse.ArgumentParser(
        prog="sast_engine",
        description="AST-based SAST scanner for OWASP LLM vulnerability classes.")
    ap.add_argument("target", nargs="?", default="vulnerable_app.py",
                    help="Python file to scan (default: the bundled test fixture)")
    ap.add_argument("--allow-findings", action="store_true",
                    help="report findings but exit 0 anyway (for demos, not CI)")
    ap.add_argument("--quiet", action="store_true", help="suppress the scan narrative")
    args = ap.parse_args(argv)

    vulns, error = scan_file(args.target, quiet=args.quiet)
    if error:
        # A file that could not be scanned is not a clean file. Fail loudly
        # rather than letting a typo in the path read as a passing scan.
        return 2
    if vulns and not args.allow_findings:
        return 1
    return 0


if __name__ == "__main__":
    # If a file is passed via CLI, scan it. Otherwise, scan the local vulnerable file.
    sys.exit(main(sys.argv[1:]))