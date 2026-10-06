import hashlib
import re

from detector import (
    _is_documentation_or_sample,
    _is_test_path,
    redact_sensitive_text,
)
from policy import evaluate_scope

CONFIDENCE_THRESHOLDS = {
    "FALSE_POSITIVE": 0,
    "LOW": 35,
    "MEDIUM": 60,
    "HIGH": 80,
    "VERY_HIGH": 95,
}

_SOURCE_PATTERN = re.compile(
    r"(?i)\b(?:req(?:uest)?\.(?:query|body|params|headers)|"
    r"request\.(?:args|form|values))\b"
)
_SQL_SINK_PATTERN = re.compile(r"(?i)\b(?:query|execute|raw|execSql)\s*\(")
_COMMAND_SINK_PATTERN = re.compile(r"(?i)\b(?:exec|eval|system|spawn|popen)\s*\(")
_SSRF_SINK_PATTERN = re.compile(r"(?i)\b(?:fetch|requests?\.(?:get|post)|axios\.)")
_PARAMETERIZED_SQL = re.compile(r"(?i)\b(?:query|execute)\s*\([^)]*(?:\?|,\s*\[)")
_SENSITIVE_CORS_CONTEXT = re.compile(
    r"(?i)(?:Access-Control-Allow-Credentials['\"]?\s*[:=]\s*['\"]?true|"
    r"authorization|session|cookie|account|profile|private[_ -]?data)"
)
_AUTH_GUARD = re.compile(
    r"(?i)(?:authorize|authori[sz]ation|isAuthenticated|requireAuth|"
    r"permission|access.?control|sanitize|escape|allowlist|parameterized)"
)


def redact_secrets(text: str) -> str:
    return redact_sensitive_text(text)


def _source_sink_evidence(finding: dict) -> tuple[str | None, str | None, int, list[str]]:
    context = finding.get("redacted_context") or finding.get("context") or ""
    lines = context.splitlines()
    source_lines = [line for line in lines if _SOURCE_PATTERN.search(line)]
    if not source_lines:
        return None, None, 1, ["attacker_controlled_source_not_proven"]

    kind = finding.get("type", "").lower()
    if "sql" in kind:
        sink_pattern = _SQL_SINK_PATTERN
        sink_name = "SQL query/execute sink"
        guarded = _PARAMETERIZED_SQL.search(context)
    elif "command" in kind:
        sink_pattern = _COMMAND_SINK_PATTERN
        sink_name = "command execution sink"
        guarded = None
    elif "ssrf" in kind:
        sink_pattern = _SSRF_SINK_PATTERN
        sink_name = "outbound HTTP request sink"
        guarded = None
    elif "path traversal" in kind or "file upload" in kind:
        sink_pattern = re.compile(r"(?i)\b(?:open|readFile|writeFile|createWriteStream|move)\s*\(")
        sink_name = "file access sink"
        guarded = None
    elif "redirect" in kind:
        sink_pattern = re.compile(r"(?i)\b(?:redirect|sendRedirect)\s*\(")
        sink_name = "redirect sink"
        guarded = None
    else:
        return "request-controlled input", None, 2, ["source_seen_but_sink_not_proven"]

    sink_lines = [line for line in lines if sink_pattern.search(line)]
    if not sink_lines:
        return "request-controlled input", None, 2, ["sensitive_sink_not_proven"]
    same_line = next(
        (line for line in source_lines if sink_pattern.search(line)),
        None,
    )
    if same_line is None:
        return "request-controlled input", sink_name, 2, ["source_and_sink_seen_but_dataflow_not_proven"]
    if guarded and sink_pattern.search(same_line):
        return "request-controlled input", sink_name, 2, ["parameterized_query_evidence"]
    if _AUTH_GUARD.search(same_line):
        return (
            "request-controlled input",
            sink_name,
            2,
            ["same_context_contains_validation_or_authorization_marker"],
        )
    return "request-controlled input", sink_name, 3, ["source_and_sink_in_same_context"]


def _impact_score(finding: dict, reachability: int) -> tuple[int, list[str]]:
    kind = finding.get("type", "").lower()
    context = finding.get("redacted_context") or finding.get("context") or ""
    negatives = []
    if "cors" in kind:
        if _SENSITIVE_CORS_CONTEXT.search(context):
            return 3, ["cors_sensitive_data_or_credentials_context"]
        return 0, ["cors_wildcard_without_demonstrated_impact"]
    if finding.get("category") == "Secret Leak" or finding.get("category") == "Potential Secret":
        return 2, ["secret_shaped_value_detected_but_live_authenticity_unverified"]
    if reachability < 3:
        return 0, ["security_impact_not_demonstrated"]
    if any(term in kind for term in ("sql", "command", "ssrf", "path traversal", "xss", "redirect", "file upload")):
        return 3, ["attacker_controlled_input_reaches_security_sensitive_sink"]
    negatives.append("impact_not_demonstrated_by_static_evidence")
    return 0, negatives


def _fingerprint(report: dict) -> str:
    context = report.get("redacted_context", "")
    code_lines = [
        re.sub(r"\s+", " ", line).strip().lower()
        for line in context.splitlines()
        if line.strip() and "[REDACTED_SECRET]" not in line
    ]
    signature = "|".join(code_lines)
    identity = "|".join(
        (
            report.get("company", ""),
            report.get("repository", ""),
            report.get("file", ""),
            report.get("type", ""),
            str(report.get("line", 0)),
            report.get("source", "") or "",
            report.get("sink", "") or "",
            signature,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _independent_static_sources(
    candidate: dict,
    file_path: str,
    line: int,
    commit: str,
) -> set[str]:
    supported_tools = {"semgrep", "codeql", "custom_ast"}
    records = candidate.get("static_analysis", [])
    if not isinstance(records, list):
        return set()
    return {
        record["tool"].lower()
        for record in records
        if isinstance(record, dict)
        and isinstance(record.get("tool"), str)
        and record["tool"].lower() in supported_tools
        and isinstance(record.get("rule_id"), str)
        and bool(record["rule_id"].strip())
        and record.get("file") == file_path
        and record.get("line") == line
        and record.get("commit") == commit
    }


def validate_candidate(
    candidate: dict,
    company: str,
    repository: str,
    commit: str,
    commit_url: str,
    policy: dict,
) -> dict:
    file_path = candidate.get("source_file", "")
    redacted_context = redact_secrets(
        candidate.get("redacted_context") or candidate.get("context") or ""
    )
    finding_type = candidate.get("type", "Unknown")
    is_test = candidate.get("is_test", _is_test_path(file_path))
    is_example = candidate.get("is_example", _is_documentation_or_sample(file_path))
    is_placeholder = candidate.get("is_placeholder", False)
    source, sink, reachability, flow_evidence = _source_sink_evidence(
        {**candidate, "redacted_context": redacted_context}
    )
    impact, impact_evidence = _impact_score(
        {**candidate, "type": finding_type, "redacted_context": redacted_context},
        reachability,
    )
    scope = evaluate_scope(company, repository, finding_type, file_path, policy)
    evidence = list(candidate.get("evidence", [])) + flow_evidence + impact_evidence
    negative_evidence = list(candidate.get("negative_evidence", []))
    if is_test:
        negative_evidence.append("test_fixture_or_mock_path")
    elif is_example:
        negative_evidence.append("documentation_or_sample_path")
    if is_placeholder:
        negative_evidence.append("placeholder_or_known_fake_value")
    if scope["scope_status"] != "IN_SCOPE":
        negative_evidence.extend(scope["scope_evidence"]["reasons"])
    if "cors" in finding_type.lower() and impact == 0:
        status = "FALSE_POSITIVE"
        negative_evidence.append("cors_without_demonstrated_security_impact")
    elif is_test or is_example or is_placeholder:
        status = "FALSE_POSITIVE"
    else:
        status = "POTENTIAL"

    static_sources = _independent_static_sources(
        candidate,
        file_path,
        candidate.get("line", 0),
        commit,
    )
    independent_sources = len(static_sources)
    evidence.extend(f"static_analysis:{tool}" for tool in sorted(static_sources))
    confidence_score = 15
    if source:
        confidence_score += 10
    if sink:
        confidence_score += 10
    if reachability >= 3:
        confidence_score += 15
    if impact >= 3:
        confidence_score += 20
    confidence_score += min(independent_sources, 2) * 10
    if scope["in_scope"]:
        confidence_score += 10
    if not is_test and not is_example:
        confidence_score += 5
    if status == "FALSE_POSITIVE":
        confidence_score = 0
    confidence_score = min(100, confidence_score)

    evidence_complete = bool(
        source
        and sink
        and reachability >= 3
        and impact >= 3
        and independent_sources >= 2
        and scope["in_scope"]
        and status != "FALSE_POSITIVE"
    )
    confidence_level = next(
        (
            level
            for level, threshold in reversed(list(CONFIDENCE_THRESHOLDS.items()))
            if confidence_score >= threshold
        ),
        "LOW",
    )
    if not evidence_complete and confidence_level in {"HIGH", "VERY_HIGH"}:
        confidence_level = "MEDIUM"

    severity = (
        "CRITICAL" if impact == 5 else
        "HIGH" if impact == 4 else
        "MEDIUM" if impact == 3 else
        "LOW" if impact == 2 else
        "INFORMATIONAL" if impact == 1 else
        "NONE"
    )
    report = {
        "company": company,
        "program": company,
        "repository": repository,
        "commit": commit,
        "commit_url": commit_url,
        "file": file_path,
        "line": candidate.get("line", 0),
        "type": finding_type,
        "category": candidate.get("category", "Unknown"),
        "severity": severity,
        "confidence": confidence_score,
        "confidence_level": confidence_level,
        "reachability": reachability,
        "impact": impact,
        "scope_status": scope["scope_status"],
        "in_scope": scope["in_scope"],
        "bounty_eligible": scope["bounty_eligible"],
        "duplicate_probability": 0,
        "novelty": 1,
        "source": source,
        "sink": sink,
        "evidence": evidence,
        "negative_evidence": negative_evidence,
        "redacted_context": redacted_context,
        "ai_reasoning": "",
        "report_draft": "",
        "status": status,
        "false_positive": status == "FALSE_POSITIVE",
        "evidence_complete": evidence_complete,
        "manual_validation_required": not evidence_complete,
        "duplicate": False,
        "provider": candidate.get("provider"),
        "secret_type": candidate.get("secret_type"),
        "is_example": is_example,
        "is_test": is_test,
        "is_placeholder": is_placeholder,
    }
    report["fingerprint"] = _fingerprint(report)
    return report


def may_send_telegram(report: dict) -> bool:
    return (
        report.get("confidence_level") in {"HIGH", "VERY_HIGH"}
        and report.get("in_scope") is True
        and report.get("bounty_eligible") is True
        and report.get("duplicate") is False
        and report.get("false_positive") is False
        and report.get("evidence_complete") is True
        and report.get("ai_confirmed") is True
        and report.get("reachability", 0) >= 3
        and report.get("impact", 0) >= 3
    )
