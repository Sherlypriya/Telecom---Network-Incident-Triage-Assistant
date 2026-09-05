"""
Loads runbooks from the /runbooks directory (markdown with YAML frontmatter)
and matches incidents to the most relevant runbook based on the alert types
present in the incident. Keyword/rule-based matching — simple, explainable,
and easy to later swap for embeddings/RAG without changing the interface.
"""
import os
import re
from dataclasses import dataclass
from typing import List, Optional
from collections import Counter

from app.models.schemas import Alert, RunbookMatch

RUNBOOK_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "runbooks")


@dataclass
class Runbook:
    id: str
    title: str
    keywords: List[str]
    steps: List[str]
    source_file: str


def _parse_frontmatter(text: str):
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        return {}, text
    fm_raw, body = m.groups()
    fm = {}
    for line in fm_raw.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if val.startswith("[") and val.endswith("]"):
            val = [v.strip() for v in val[1:-1].split(",") if v.strip()]
        fm[key] = val
    return fm, body


def _extract_steps(body: str) -> List[str]:
    steps = []
    in_steps = False
    for line in body.splitlines():
        if line.strip().lower().startswith("## initial response steps"):
            in_steps = True
            continue
        if in_steps:
            if line.strip().startswith("#"):
                break
            m = re.match(r"^\d+\.\s+(.*)", line.strip())
            if m:
                steps.append(m.group(1))
    return steps


def load_runbooks() -> List[Runbook]:
    runbooks = []
    if not os.path.isdir(RUNBOOK_DIR):
        return runbooks
    for fname in sorted(os.listdir(RUNBOOK_DIR)):
        if not fname.endswith(".md"):
            continue
        path = os.path.join(RUNBOOK_DIR, fname)
        with open(path, "r") as f:
            text = f.read()
        fm, body = _parse_frontmatter(text)
        title_match = re.search(r"^#\s+(.*)", body, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else fname
        keywords = fm.get("keywords", [])
        if isinstance(keywords, str):
            keywords = [keywords]
        runbooks.append(Runbook(
            id=fm.get("id", fname),
            title=title,
            keywords=keywords,
            steps=_extract_steps(body),
            source_file=fname,
        ))
    return runbooks


_RUNBOOKS_CACHE: Optional[List[Runbook]] = None


def get_runbooks() -> List[Runbook]:
    global _RUNBOOKS_CACHE
    if _RUNBOOKS_CACHE is None:
        _RUNBOOKS_CACHE = load_runbooks()
    return _RUNBOOKS_CACHE


def match_runbook(alerts: List[Alert], min_confidence: float = 0.34) -> Optional[RunbookMatch]:
    """
    Scores each runbook by the fraction of its keyword set that appears among
    the incident's alert types, weighted slightly by how dominant that type is
    in the incident. Returns None if no runbook clears the confidence bar,
    signalling the incident should be escalated instead of guessed at.
    """
    type_counts = Counter(a.alert_type.value for a in alerts)
    total = sum(type_counts.values())
    if total == 0:
        return None

    best: Optional[Runbook] = None
    best_score = 0.0

    for rb in get_runbooks():
        if not rb.keywords:
            continue
        overlap_types = [t for t in rb.keywords if t in type_counts]
        if not overlap_types:
            continue
        # fraction of incident's alert volume explained by this runbook's keywords
        explained = sum(type_counts[t] for t in overlap_types) / total
        # fraction of the runbook's own keyword set that's present (specificity bonus)
        specificity = len(overlap_types) / len(rb.keywords)
        score = 0.7 * explained + 0.3 * specificity
        if score > best_score:
            best_score = score
            best = rb

    if best is None or best_score < min_confidence:
        return None

    return RunbookMatch(
        runbook_id=best.id,
        title=best.title,
        confidence=round(best_score, 2),
        recommended_steps=best.steps,
        source_file=best.source_file,
    )
