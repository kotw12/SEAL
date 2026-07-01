"""Render a SEAL engagement result as text, JSON, or SARIF."""
from __future__ import annotations

import json

from .models import EngagementResult, Severity

_SARIF_LEVEL = {
    Severity.INFO: "note", Severity.LOW: "note", Severity.MEDIUM: "warning",
    Severity.HIGH: "error", Severity.CRITICAL: "error",
}


def to_text(result: EngagementResult) -> str:
    lines: list[str] = []
    lines.append("═" * 66)
    lines.append(f"  SEAL engagement report — {result.target}")
    lines.append("═" * 66)
    lines.append(f"  rounds run    : {len(result.rounds)}")
    lines.append(f"  stop reason   : {result.stop_reason}")
    lines.append(f"  VERIFIED      : {len(result.verified)}   (false positives refuted: {len(result.refuted)})")
    lines.append("")
    if result.verified:
        lines.append("  ── verified findings ──────────────────────────────────────")
        for f in result.verified:
            lines.append(f"  [{f.severity.name:8}] {f.vuln_class:6} {f.surface}")
            lines.append(f"             evidence : {f.evidence}")
            lines.append(f"             poc      : {f.poc}")
            lines.append(f"             verified : {f.verify_notes}")
            lines.append("")
    else:
        lines.append("  (no findings survived verification)")
        lines.append("")
    lines.append("  ── evolution lineage ──────────────────────────────────────")
    for r in result.rounds:
        s = r.strategy
        v = sum(1 for f in result.verified if f.strategy_id == s.id)
        lines.append(f"  round {r.round_index}: technique={s.technique}"
                     f"{(' focus='+s.focus_class) if s.focus_class else ''}"
                     f"  → {len(r.findings)} candidates")
    lines.append("═" * 66)
    return "\n".join(lines)


def to_json(result: EngagementResult, indent: int = 2) -> str:
    return result.to_json(indent=indent)


def to_sarif(result: EngagementResult) -> str:
    """Minimal SARIF 2.1.0 for CI ingestion (verified findings only)."""
    rules: dict[str, dict] = {}
    sarif_results = []
    for f in result.verified:
        rule_id = f"seal/{f.vuln_class}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f.vuln_class,
            "shortDescription": {"text": f"{f.vuln_class} (SEAL-verified)"},
        })
        sarif_results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}\nPoC: {f.poc}\nVerified: {f.verify_notes}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": f.surface}}
            }],
            "properties": {"severity": f.severity.name, "evidence": f.evidence,
                           "status": f.status.value},
        })
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "SEAL",
                "informationUri": "https://github.com/local/seal",
                "version": "0.1.0",
                "rules": list(rules.values()),
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def render(result: EngagementResult, fmt: str = "text") -> str:
    return {"text": to_text, "json": to_json, "sarif": to_sarif}.get(fmt, to_text)(result)
