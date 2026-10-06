from dataclasses import dataclass
from typing import Protocol

from detector import scan_text_for_secrets


@dataclass(frozen=True)
class DetectionContext:
    text: str
    file_path: str
    commit: str


class CandidateDetector(Protocol):
    name: str

    def detect(self, context: DetectionContext) -> list[dict]:
        ...


class PatternDetectionEngine:
    name = "built-in-patterns"

    def detect(self, context: DetectionContext) -> list[dict]:
        return scan_text_for_secrets(
            context.text,
            file_path=context.file_path,
            commit=context.commit,
        )


def detect_candidates(
    context: DetectionContext,
    detectors: tuple[CandidateDetector, ...] | None = None,
) -> list[dict]:
    active_detectors = detectors or (PatternDetectionEngine(),)
    candidates = []
    for detector in active_detectors:
        candidates.extend(detector.detect(context))
    return candidates


def merge_independent_evidence(candidates: list[dict]) -> list[dict]:
    merged: dict[tuple[str, int, str], dict] = {}
    for candidate in candidates:
        key = (
            candidate.get("source_file", ""),
            candidate.get("line", 0),
            candidate.get("type", ""),
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = candidate
            continue
        existing.setdefault("static_analysis", []).extend(
            candidate.get("static_analysis", [])
        )
        existing.setdefault("evidence", []).extend(candidate.get("evidence", []))
        if not existing.get("redacted_context") and candidate.get("redacted_context"):
            existing["redacted_context"] = candidate["redacted_context"]
            existing["context"] = candidate["redacted_context"]
    return list(merged.values())
