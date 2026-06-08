"""VAULTMAP — auto-generated detector core."""
from __future__ import annotations
import re, time
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "VAULTMAP"
TOOL_VERSION = "0.1.0"

PATTERNS = [('VM-MISS-RECOVERY', 'high', 2.5, 'NO_RECOVERY_CODES', '(?i)recovery[_-]?codes\\s*:\\s*(none|\\[\\s*\\]|null)', 'Save recovery codes in encrypted offline store.'), ('VM-MISS-BENEFICIARY', 'medium', 2.0, 'NO_BENEFICIARY', '(?i)beneficiary\\s*:\\s*(none|\\"\\")', 'Designate beneficiary in account settings.')]
FILE_GLOBS = ['*.yaml', '*.yml']

def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    files: list[Path] = []
    if p.is_dir():
        for g in FILE_GLOBS:
            files.extend(p.rglob(g))
    elif p.is_file():
        files = [p]
    result.items_scanned = len(files)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rid,sev,w,title,pat,rem in PATTERNS:
            for m in re.finditer(pat, text):
                line = text.count(chr(10), 0, m.start()) + 1
                result.add(Finding(
                    id=rid, severity=sev, weight=w, title=title,
                    description=f"{title}: `{m.group(0)[:80]}`",
                    location=f"{f}:{line}", remediation=rem, category="vault",
                ))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time()-t0)*1000)
    return result
