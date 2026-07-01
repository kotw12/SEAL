"""Core data model for SEAL.

Deliberately dependency-free (stdlib only) so the loop machinery can be
unit-tested and run end-to-end offline, without invoking the scanner or
touching the network. The scan-engine runner plugs in on top.
"""
from __future__ import annotations

import enum
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: object) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, (int, float)):
            return cls(max(0, min(4, int(value))))
        name = str(value).strip().upper()
        return cls.__members__.get(name, cls.INFO)


class FindingStatus(str, enum.Enum):
    CANDIDATE = "candidate"   # reported by an attack round, not yet checked
    VERIFIED = "verified"     # reproduced independently by the verification loop
    REFUTED = "refuted"       # verification could not reproduce it (false positive)


def _now() -> float:
    # time.time() is allowed here (real runtime); workflow scripts are the only
    # place the harness forbids the clock.
    return time.time()


@dataclass
class Finding:
    """A single candidate/verified vulnerability."""
    vuln_class: str                     # e.g. "sqli", "xss", "idor", "ssrf"
    surface: str                        # where: URL + param, endpoint, etc.
    severity: Severity = Severity.INFO
    title: str = ""
    evidence: str = ""                  # what proved it (response snippet, marker)
    poc: str = ""                       # reproducible proof-of-concept (request/payload)
    status: FindingStatus = FindingStatus.CANDIDATE
    round_index: int = 0
    strategy_id: str = ""               # attempt/strategy that produced it
    parent_id: str = ""                 # lineage: finding this evolved from
    verify_notes: str = ""              # why verified/refuted
    id: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        if isinstance(self.status, str):
            self.status = FindingStatus(self.status)
        if not self.id:
            self.id = self.fingerprint()

    def fingerprint(self) -> str:
        """Stable identity for dedup: same class+surface+poc => same finding.

        Fields are JSON-encoded (not '|'-joined) so a separator character inside
        a field cannot forge a collision between distinct findings.
        """
        raw = json.dumps([self.vuln_class, self.surface, self.poc],
                         ensure_ascii=False).encode("utf-8", "ignore")
        return hashlib.sha1(raw).hexdigest()[:12]

    @property
    def cell(self) -> tuple[str, str]:
        """MAP-Elites cell key: (vuln_class, coarse surface bucket)."""
        return (self.vuln_class.lower().strip() or "unknown", _surface_bucket(self.surface))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["severity_name"] = self.severity.name
        d["status"] = self.status.value
        return d


def _surface_bucket(surface: str) -> str:
    """Coarsen a surface to a MAP-Elites bucket (drop query values, keep path+param names)."""
    s = surface.split("#", 1)[0]
    if "?" in s:
        base, _, query = s.partition("?")
        params = sorted(p.split("=", 1)[0] for p in query.split("&") if p)
        return base + ("?" + ",".join(params) if params else "")
    return s


@dataclass
class Strategy:
    """An attack strategy/instruction for one round (the unit that evolves)."""
    instruction: str                    # natural-language directive to the agent
    technique: str = "baseline"         # technique family (mutation dimension)
    focus_class: str = ""               # vuln class this round targets ("" = broad)
    round_index: int = 0
    parent_id: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raw = f"{self.round_index}|{self.technique}|{self.focus_class}|{self.instruction}"
            self.id = "s" + hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:10]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RoundResult:
    """Outcome of running one attack round against the target."""
    round_index: int
    strategy: Strategy
    findings: list[Finding] = field(default_factory=list)
    raw_log: str = ""                   # runner transcript (path or inline)
    error: str = ""
    started_at: float = field(default_factory=_now)
    ended_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "round_index": self.round_index,
            "strategy": self.strategy.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }


@dataclass
class EngagementResult:
    """Final SEAL engagement outcome."""
    target: str
    rounds: list[RoundResult] = field(default_factory=list)
    verified: list[Finding] = field(default_factory=list)
    refuted: list[Finding] = field(default_factory=list)
    stop_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "stop_reason": self.stop_reason,
            "rounds_run": len(self.rounds),
            "verified": [f.to_dict() for f in self.verified],
            "refuted": [f.to_dict() for f in self.refuted],
            "rounds": [r.to_dict() for r in self.rounds],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
