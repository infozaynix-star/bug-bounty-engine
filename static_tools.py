import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from detector import redact_sensitive_text

logger = logging.getLogger(__name__)
SUPPORTED_STATIC_TOOLS = {"semgrep", "codeql"}
TOOL_TIMEOUT_SECONDS = 1800
SUPPORTED_LANGUAGE_SUFFIXES = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".php": "php",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".yml": "yaml",
    ".yaml": "yaml",
}


def language_for_file(file_path: str) -> str | None:
    return SUPPORTED_LANGUAGE_SUFFIXES.get(Path(file_path).suffix.lower())


def _verify_checkout_commit(repository_path: Path, expected_commit: str) -> None:
    if not expected_commit:
        raise ValueError("Expected commit SHA is required for a static scan")
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_path,
        capture_output=True,
        check=False,
        text=True,
        timeout=15,
    )
    if result.returncode:
        raise RuntimeError(f"Cannot determine checked-out revision: {result.stderr.strip()}")
    if result.stdout.strip().casefold() != expected_commit.casefold():
        raise ValueError("Static scan checkout does not match the commit being analyzed")


def _relative_path(root: Path, value: str) -> str | None:
    candidate = Path(unquote(value))
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _classify_rule(rule_id: str, message: str, tags: list[Any]) -> str:
    combined = " ".join([rule_id, message, *(str(tag) for tag in tags)]).lower()
    categories = (
        (("sqli", "sql-injection", "cwe-89"), "Potential SQL Injection"),
        (("command-injection", "os-command", "cwe-78"), "Unsafe Command Execution"),
        (("ssrf", "server-side-request-forgery", "cwe-918"), "Potential SSRF"),
        (("path-traversal", "cwe-22"), "Potential Path Traversal"),
        (("xss", "cross-site-scripting", "cwe-79"), "Potential XSS"),
        (("idor", "authorization", "cwe-639"), "Potential IDOR"),
        (("cors", "cross-origin"), "Insecure Permissive CORS"),
        (("deserialization", "cwe-502"), "Potential Unsafe Deserialization"),
        (("redirect", "cwe-601"), "Potential Open Redirect"),
    )
    for terms, finding_type in categories:
        if any(term in combined for term in terms):
            return finding_type
    return f"Static Analysis Candidate: {rule_id}"


def _candidate(
    tool: str,
    rule_id: str,
    message: str,
    file_path: str,
    line: int,
    snippet: str,
    commit: str,
    tags: list[Any] | None = None,
) -> dict:
    tags = tags or []
    safe_snippet = redact_sensitive_text(snippet)
    return {
        "type": _classify_rule(rule_id, message, tags),
        "category": "Code Vulnerability",
        "source_file": file_path,
        "line": line,
        "context": safe_snippet,
        "redacted_context": safe_snippet,
        "confidence": "LOW",
        "is_example": False,
        "is_test": False,
        "is_placeholder": False,
        "status": "POTENTIAL",
        "evidence": [f"{tool}:{rule_id}"],
        "negative_evidence": [],
        "static_analysis": [
            {
                "tool": tool,
                "rule_id": rule_id,
                "file": file_path,
                "line": line,
                "commit": commit,
            }
        ],
        "detection_method": f"{tool} static analysis",
    }


def parse_semgrep_results(
    payload: dict[str, Any],
    repository_path: Path,
    commit: str,
) -> list[dict]:
    findings = []
    for result in payload.get("results", []):
        if not isinstance(result, dict):
            continue
        extra = result.get("extra", {})
        extra = extra if isinstance(extra, dict) else {}
        location = result.get("start", {})
        location = location if isinstance(location, dict) else {}
        path = _relative_path(repository_path, str(result.get("path", "")))
        line = location.get("line", 0)
        rule_id = result.get("check_id")
        if (
            not path
            or language_for_file(path) is None
            or not isinstance(line, int)
            or line < 1
            or not isinstance(rule_id, str)
        ):
            continue
        findings.append(
            _candidate(
                "semgrep",
                rule_id,
                str(extra.get("message", "")),
                path,
                line,
                str(extra.get("lines", "")),
                commit,
                extra.get("metadata", {}).get("cwe", [])
                if isinstance(extra.get("metadata"), dict)
                else [],
            )
        )
    return findings


def parse_sarif(
    payload: dict[str, Any],
    repository_path: Path,
    commit: str,
    tool: str = "codeql",
) -> list[dict]:
    if tool not in SUPPORTED_STATIC_TOOLS:
        raise ValueError(f"Unsupported SARIF evidence source: {tool}")

    findings = []
    for run in payload.get("runs", []):
        if not isinstance(run, dict):
            continue
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", []) if isinstance(driver, dict) else []
        rules_by_id = {
            rule.get("id"): rule
            for rule in rules
            if isinstance(rule, dict) and isinstance(rule.get("id"), str)
        }
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId")
            message = result.get("message", {})
            message_text = message.get("text", "") if isinstance(message, dict) else ""
            locations = result.get("locations", [])
            if not isinstance(rule_id, str) or not locations:
                continue
            physical = locations[0].get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            uri = artifact.get("uri")
            if not isinstance(uri, str):
                continue
            path = _relative_path(repository_path, uri)
            line = region.get("startLine", 0)
            if (
                not path
                or language_for_file(path) is None
                or not isinstance(line, int)
                or line < 1
            ):
                continue
            snippet = region.get("snippet", {})
            snippet_text = snippet.get("text", "") if isinstance(snippet, dict) else ""
            rule_metadata = rules_by_id.get(rule_id, {}).get("properties", {})
            tags = rule_metadata.get("tags", []) if isinstance(rule_metadata, dict) else []
            findings.append(
                _candidate(
                    tool,
                    rule_id,
                    str(message_text),
                    path,
                    line,
                    str(snippet_text),
                    commit,
                    tags if isinstance(tags, list) else [],
                )
            )
    return findings


def run_semgrep(
    repository_path: Path,
    config_path: Path,
    expected_commit: str,
) -> list[dict]:
    executable = shutil.which("semgrep")
    if executable is None:
        logger.info("Semgrep is not installed; skipping configured scan")
        return []
    repository_path = repository_path.resolve()
    config_path = config_path.resolve()
    if not repository_path.is_dir() or not config_path.is_file():
        raise FileNotFoundError("Semgrep checkout or explicit local rules file is missing")
    _verify_checkout_commit(repository_path, expected_commit)
    result = subprocess.run(
        [
            executable,
            "scan",
            "--json",
            "--config",
            str(config_path),
            "--metrics=off",
            "--quiet",
            ".",
        ],
        cwd=repository_path,
        capture_output=True,
        check=False,
        text=True,
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError(f"Semgrep failed: {result.stderr[-2000:]}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("Semgrep returned invalid JSON") from error
    return parse_semgrep_results(payload, repository_path, expected_commit)


def run_codeql(
    repository_path: Path,
    database_path: Path,
    query_suite: Path,
    expected_commit: str,
) -> list[dict]:
    executable = shutil.which("codeql")
    if executable is None:
        logger.info("CodeQL CLI is not installed; skipping configured scan")
        return []
    repository_path = repository_path.resolve()
    database_path = database_path.resolve()
    query_suite = query_suite.resolve()
    if not repository_path.is_dir() or not database_path.is_dir() or not query_suite.is_file():
        raise FileNotFoundError("CodeQL checkout, database, or explicit query suite is missing")

    provenance_file = database_path / ".bbengine-commit"
    if not provenance_file.is_file():
        raise ValueError("CodeQL database requires a .bbengine-commit provenance file")
    database_commit = provenance_file.read_text(encoding="utf-8").strip()
    if database_commit.casefold() != expected_commit.casefold():
        raise ValueError("CodeQL database does not match the commit being analyzed")
    _verify_checkout_commit(repository_path, expected_commit)

    with tempfile.TemporaryDirectory(prefix="bbengine-codeql-") as temp_dir:
        sarif_path = Path(temp_dir) / "results.sarif"
        result = subprocess.run(
            [
                executable,
                "database",
                "analyze",
                str(database_path),
                str(query_suite),
                "--format=sarif-latest",
                f"--output={sarif_path}",
            ],
            cwd=repository_path,
            capture_output=True,
            check=False,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
        if result.returncode:
            raise RuntimeError(f"CodeQL failed: {result.stderr[-2000:]}")
        try:
            payload = json.loads(sarif_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("CodeQL did not produce valid SARIF") from error
    return parse_sarif(payload, repository_path, expected_commit, "codeql")


def run_configured_scans(
    options: dict,
    expected_commit: str,
) -> list[dict]:
    repository_path = Path(options["checkout_path"])
    findings = []
    if options.get("semgrep_config"):
        findings.extend(
            run_semgrep(repository_path, Path(options["semgrep_config"]), expected_commit)
        )
    if options.get("codeql_database") and options.get("codeql_query_suite"):
        findings.extend(
            run_codeql(
                repository_path,
                Path(options["codeql_database"]),
                Path(options["codeql_query_suite"]),
                expected_commit,
            )
        )
    return findings
