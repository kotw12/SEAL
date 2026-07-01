"""MAP-Elites-lite archive: the memory that drives evolution.

Cells are keyed by (vuln_class, coarse surface bucket). Each cell keeps the
single best *verified* finding seen so far (highest severity). The archive
also records which technique families have been tried and which produced
verified results, so the mutator can push toward diversity and away from
dead ends.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Finding, FindingStatus


@dataclass
class EliteArchive:
    elites: dict[tuple[str, str], Finding] = field(default_factory=dict)
    tried_techniques: set[str] = field(default_factory=set)
    productive_techniques: set[str] = field(default_factory=set)   # yielded ≥1 verified
    seen_fingerprints: set[str] = field(default_factory=set)

    def note_attempt(self, technique: str) -> None:
        self.tried_techniques.add(technique)

    def observe(self, finding: Finding) -> bool:
        """Record a finding. Returns True if it's a *new* elite for its cell."""
        self.seen_fingerprints.add(finding.id)
        if finding.status != FindingStatus.VERIFIED:
            return False
        self.productive_techniques.add(_tech_of(finding))
        cell = finding.cell
        cur = self.elites.get(cell)
        if cur is None or finding.severity > cur.severity:
            self.elites[cell] = finding
            return True
        return False

    def has_seen(self, finding: Finding) -> bool:
        return finding.id in self.seen_fingerprints

    @property
    def verified(self) -> list[Finding]:
        return sorted(self.elites.values(), key=lambda f: (-int(f.severity), f.vuln_class, f.surface))

    @property
    def covered_classes(self) -> set[str]:
        return {cell[0] for cell in self.elites}

    def coverage(self) -> int:
        return len(self.elites)


def _tech_of(finding: Finding) -> str:
    # PoC is prefixed with "[technique] ..." by the runners; best-effort parse.
    # Guard against poc=None (a custom runner or deserialization may produce it).
    poc = finding.poc or ""
    if poc.startswith("[") and "]" in poc:
        return poc[1:poc.index("]")]
    return "unknown"
