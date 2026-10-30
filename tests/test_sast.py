"""Tests for the AST SAST engine.

The fixture-based assertions check both directions, and that matters more than
it looks. A scanner that finds the two planted flaws proves it fires; a scanner
that stays quiet on clean code proves it is not simply firing at everything.
Only the pair together means anything, which is why both halves are here.

The "ground truth" test is deliberately self-referential: it counts ``exec`` and
``eval`` calls by walking the AST directly, independently of the scanner's own
visitor, so a regression in the visitor cannot also silently move the expected
value.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sast_engine import SecurityASTVisitor, main, scan_file  # noqa: E402

FIXTURE = ROOT / "vulnerable_app.py"


def _find(text: str) -> list[dict]:
    """Run the visitor over source text and return its findings."""
    visitor = SecurityASTVisitor()
    visitor.visit(ast.parse(text))
    return visitor.vulnerabilities


# ---------------------------------------------------------------------------
# Detection: the fixture exists precisely so this can be asserted.
# ---------------------------------------------------------------------------


def test_detects_both_planted_vulnerabilities():
    vulns, error = scan_file(str(FIXTURE), quiet=True)

    assert error is None, f"fixture should scan cleanly, got: {error}"
    types = {v["type"] for v in vulns}
    assert "Credential Leakage" in types, "missed the hardcoded API key"
    assert any("OWASP LLM02" in t for t in types), "missed the blind exec() of LLM output"
    assert len(vulns) == 2, f"expected exactly the 2 planted flaws, got {len(vulns)}"


def test_reports_accurate_line_numbers():
    """A finding without a correct location is not actionable."""
    vulns, _ = scan_file(str(FIXTURE), quiet=True)
    source = FIXTURE.read_text().splitlines()

    for v in vulns:
        line = source[v["line"] - 1]
        assert "api_key" in line or "exec(" in line, (
            f"line {v['line']} does not contain the reported flaw: {line!r}"
        )


def test_ground_truth_exec_count_matches_scanner():
    """Cross-check the visitor against an independent AST walk."""
    tree = ast.parse(FIXTURE.read_text())
    expected = sum(
        1
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id in ("eval", "exec")
    )
    assert expected == 1, "fixture should contain exactly one exec/eval call"

    found = [v for v in _find(FIXTURE.read_text()) if "OWASP LLM02" in v["type"]]
    assert len(found) == expected


# ---------------------------------------------------------------------------
# Silence: equally important.
# ---------------------------------------------------------------------------


def test_clean_code_produces_no_findings():
    clean = '''
"""A module that does nothing dangerous."""
import json
from pathlib import Path


def load_config(path: str) -> dict:
    """Read configuration from disk."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def summarise(items: list[int]) -> int:
    return sum(items)
'''
    assert _find(clean) == [], "scanner fired on clean code — false positive"


def test_secret_keyword_in_a_non_literal_is_not_flagged():
    """Only constant assignments are leaks; passing a name through is not."""
    code = '''
def connect(api_key):
    """api_key arrives from the environment, not a literal."""
    return use(api_key)

api_key_from_env = os.getenv("API_KEY")
'''
    assert _find(code) == [], (
        "flagged a non-literal as a hardcoded secret — this would make the "
        "scanner too noisy to gate a build"
    )


# ---------------------------------------------------------------------------
# CI gating contract
# ---------------------------------------------------------------------------


def test_exit_code_1_when_findings_exist():
    assert main([str(FIXTURE), "--quiet"]) == 1


def test_exit_code_0_with_allow_findings():
    assert main([str(FIXTURE), "--quiet", "--allow-findings"]) == 0


def test_exit_code_0_on_clean_target(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("VALUE = 1\n", encoding="utf-8")
    assert main([str(clean), "--quiet"]) == 0


def test_exit_code_2_on_missing_file(tmp_path):
    """An unscannable file must not read as a clean scan.

    This is the failure mode that silently turns a security gate into a no-op:
    a renamed path, a bad glob, and the build goes green while scanning nothing.
    """
    assert main([str(tmp_path / "absent.py"), "--quiet"]) == 2


def test_exit_code_2_on_syntax_error(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def f(:\n    pass\n", encoding="utf-8")
    assert main([str(broken), "--quiet"]) == 2
