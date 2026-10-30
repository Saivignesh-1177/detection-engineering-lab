"""A small Sigma-inspired detection engine with no dependencies.

A rule is JSON:
  {
    "id": "DET-001", "title": "...", "level": "high",
    "attack": ["T1059.001"],
    "logsource": {"product": "windows", "event_id": 1},
    "selection": {"Image|endswith": ["\\powershell.exe"], "CommandLine|contains": ["-enc"]},
    "filter":    {"ParentImage|endswith": ["\\sccm.exe"]},
    "threshold": {"count": 5, "window_s": 60, "group_by": "SourceIp"}   # optional
  }

Selection semantics: every field must match (AND). The values listed for one field are OR'd.
A filter removes known-good matches. A threshold turns per-event matches into an aggregate alert.
"""
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

MODIFIERS = {
    "equals": lambda v, p: v == p,
    "contains": lambda v, p: p in v,
    "startswith": lambda v, p: v.startswith(p),
    "endswith": lambda v, p: v.endswith(p),
    "re": lambda v, p: re.search(p, v) is not None,
}


@dataclass
class Alert:
    rule_id: str
    title: str
    level: str
    attack: list[str]
    events: list[dict] = field(default_factory=list)


def _field_matches(event: dict, key: str, patterns) -> bool:
    name, _, mod = key.partition("|")
    mod = mod or "equals"
    if name not in event:
        return False
    if not isinstance(patterns, list):
        patterns = [patterns]
    value = event[name]
    if isinstance(value, (int, float)) and mod == "equals":
        return any(value == p for p in patterns)
    value = str(value).lower()
    fn = MODIFIERS[mod]
    return any(fn(value, str(p).lower()) for p in patterns)


def _block_matches(event: dict, block: dict) -> bool:
    return bool(block) and all(_field_matches(event, k, v) for k, v in block.items())


class Rule:
    def __init__(self, spec: dict) -> None:
        self.spec = spec
        self.id = spec["id"]
        self.logsource = spec.get("logsource", {})
        for key in list(spec.get("selection", {})) + list(spec.get("filter", {})):
            mod = key.partition("|")[2] or "equals"
            if mod not in MODIFIERS:
                raise ValueError(f"{self.id}: unknown modifier '{mod}'")

    def matches(self, event: dict) -> bool:
        for k, v in self.logsource.items():
            if event.get(k) != v:
                return False
        if not _block_matches(event, self.spec["selection"]):
            return False
        return not _block_matches(event, self.spec.get("filter", {}))

    def alert(self, events: list[dict]) -> Alert:
        s = self.spec
        return Alert(s["id"], s["title"], s["level"], s.get("attack", []), events)


def load_rules(directory: str | Path) -> list[Rule]:
    return [Rule(json.loads(p.read_text(encoding="utf-8"))) for p in sorted(Path(directory).glob("*.json"))]


def _ts(event: dict) -> float:
    return datetime.fromisoformat(event["UtcTime"].replace("Z", "+00:00")).timestamp()


def run(rules: list[Rule], events: list[dict]) -> list[Alert]:
    alerts: list[Alert] = []
    events = sorted(events, key=_ts)
    for rule in rules:
        th = rule.spec.get("threshold")
        if not th:
            alerts += [rule.alert([e]) for e in events if rule.matches(e)]
            continue
        windows: dict[str, deque] = defaultdict(deque)
        fired: set[str] = set()
        for e in events:
            if not rule.matches(e):
                continue
            key = str(e.get(th["group_by"], "?"))
            win = windows[key]
            win.append(e)
            while _ts(e) - _ts(win[0]) > th["window_s"]:
                win.popleft()
            if len(win) >= th["count"] and key not in fired:
                fired.add(key)
                alerts.append(rule.alert(list(win)))
    return alerts


def load_events(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
