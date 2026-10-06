import requests
import time
import base64
import logging
import json
import subprocess
from urllib.parse import quote

from config import My_GITHUB_TOKEN, TARGET_REPOS
from detector import context_from_source
from dependency_analysis import analyze_dependency_manifest
from detection_engine import DetectionContext, detect_candidates, merge_independent_evidence
from ai import analyze_finding_with_ai
from notifier import send_telegram_alert
from pipeline import may_send_telegram, validate_candidate
from policy import (
    authorized_repositories,
    load_scope_policy,
    organization_wildcard_is_authorized,
    repository_is_authorized,
    scanner_options,
    source_path_is_authorized,
)
from static_tools import run_configured_scans
from storage import (
    is_commit_processed,
    is_finding_duplicate,
    mark_commit_processed,
    record_finding,
)

HEADERS = {
    "Accept": "application/vnd.github.v3+json"
}
logger = logging.getLogger(__name__)
if My_GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {My_GITHUB_TOKEN}"


class GitHubAPIError(RuntimeError):
    """A GitHub REST request failed or returned an unexpected response."""


def _github_get_json(url: str, params: dict | None = None):
    try:
        response = requests.get(url, headers=HEADERS, params=params, timeout=15)
    except requests.RequestException as error:
        raise GitHubAPIError(
            f"GitHub request failed ({type(error).__name__})"
        ) from error

    if response.status_code != 200:
        detail = f"HTTP {response.status_code}"
        if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
            detail += (
                "; API rate limit exhausted, reset at "
                f"{response.headers.get('X-RateLimit-Reset', 'unknown')}"
            )
        raise GitHubAPIError(detail)

    try:
        return response.json()
    except ValueError as error:
        raise GitHubAPIError("GitHub returned invalid JSON") from error


def get_company_repositories(org_name: str, limit: int | None = None) -> list:
    """List recent public organization repositories, following all result pages."""
    if limit is not None and limit < 1:
        raise ValueError("Repository limit must be positive or None")

    repositories = []
    page = 1
    page_size = 100
    while limit is None or len(repositories) < limit:
        payload = _github_get_json(
            f"https://api.github.com/orgs/{quote(org_name, safe='')}/repos",
            {
                "type": "public",
                "sort": "updated",
                "direction": "desc",
                "per_page": page_size,
                "page": page,
            },
        )
        if not isinstance(payload, list):
            raise GitHubAPIError("GitHub returned an unexpected repository-list shape")
        for repository in payload:
            if not isinstance(repository, dict):
                raise GitHubAPIError("GitHub returned a malformed repository entry")
            full_name = repository.get("full_name")
            owner = repository.get("owner", {})
            owner_login = owner.get("login") if isinstance(owner, dict) else None
            if (
                repository.get("private") is False
                and isinstance(full_name, str)
                and isinstance(owner_login, str)
                and owner_login.casefold() == org_name.casefold()
            ):
                repositories.append(repository)
                if limit is not None and len(repositories) >= limit:
                    return repositories
        if len(payload) < page_size:
            break
        page += 1
    return repositories


def get_repo_recent_commits(owner: str, repo: str, limit: int = 5) -> list:
    """جلب أحدث الـ Commits للمستودع"""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page={limit}"
    payload = _github_get_json(url)
    if not isinstance(payload, list):
        raise GitHubAPIError("GitHub returned an unexpected commit-list shape")
    return payload


def get_commit_details(owner: str, repo: str, commit_sha: str) -> dict:
    """جلب التفاصيل الكاملة والـ Diff للـ Commit"""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
    payload = _github_get_json(url)
    if not isinstance(payload, dict):
        raise GitHubAPIError("GitHub returned an unexpected commit detail shape")
    return payload


def get_file_content_at_commit(
    owner: str, repo: str, file_path: str, commit_sha: str, max_bytes: int = 1_000_000
) -> str | None:
    encoded_path = quote(file_path, safe="/")
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{encoded_path}"
    try:
        response = requests.get(
            url,
            headers={**HEADERS, "Accept": "application/vnd.github+json"},
            params={"ref": commit_sha},
            timeout=15,
        )
    except requests.RequestException:
        logger.exception("Could not fetch source context for %s at %s", file_path, commit_sha)
        return None

    if response.status_code != 200:
        logger.warning(
            "GitHub source context unavailable for %s at %s (HTTP %s)",
            file_path,
            commit_sha,
            response.status_code,
        )
        return None
    try:
        payload = response.json()
        encoded_content = payload.get("content", "")
        if payload.get("encoding") != "base64" or not isinstance(encoded_content, str):
            raise ValueError("GitHub Contents API did not return base64 file content")
        decoded = base64.b64decode(encoded_content, validate=False)
        if len(decoded) > max_bytes:
            logger.info("Skipping oversized context file %s (%d bytes)", file_path, len(decoded))
            return None
        return decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError, TypeError, AttributeError):
        logger.exception("Could not decode source context for %s at %s", file_path, commit_sha)
        return None


def process_commit(
    company_name: str,
    repo_fullname: str,
    commit_data: dict,
    commit_url: str,
    policy: dict | None = None,
    stats: dict | None = None,
    static_candidates: list[dict] | None = None,
):
    """تحليل ملفات الـ Commit المحدثة وكشف الثغرات البرمجية والمفاتيح"""
    commit_sha = commit_data.get("sha")
    files = commit_data.get("files", [])
    policy = policy if policy is not None else load_scope_policy()
    stats = stats if stats is not None else {}
    file_context_cache: dict[str, str | None] = {}

    for file_info in files:
        file_path = file_info.get("filename", "")
        patch = file_info.get("patch", "")

        if not source_path_is_authorized(
            company_name, repo_fullname, file_path, policy
        ):
            stats["out_of_scope"] = stats.get("out_of_scope", 0) + 1
            continue
        stats["files_analyzed"] = stats.get("files_analyzed", 0) + 1
        stats["lines_analyzed"] = stats.get("lines_analyzed", 0) + sum(
            line.startswith("+") and not line.startswith("+++")
            for line in patch.splitlines()
        )
        findings = detect_candidates(
            DetectionContext(patch, file_path, commit_sha or "")
        ) if patch else []
        findings.extend(
            candidate
            for candidate in static_candidates or []
            if candidate.get("source_file") == file_path
        )
        findings = merge_independent_evidence(findings)

        for finding in findings:
            if finding.get("line", 0) > 0 and file_path not in file_context_cache:
                owner, repo_name = repo_fullname.split("/", 1)
                file_context_cache[file_path] = get_file_content_at_commit(
                    owner,
                    repo_name,
                    file_path,
                    commit_sha or "",
                )
            source_text = file_context_cache.get(file_path)
            if source_text:
                full_context = context_from_source(source_text, finding.get("line", 0))
                if full_context:
                    finding["redacted_context"] = full_context
                    finding["context"] = full_context
                    finding["context_source"] = "github_contents_at_commit"

            stats["candidates"] = stats.get("candidates", 0) + 1
            if finding.get("category") in {"Secret Leak", "Potential Secret"}:
                stats["secrets_detected"] = stats.get("secrets_detected", 0) + 1
            else:
                stats["potential_vulnerabilities"] = stats.get("potential_vulnerabilities", 0) + 1

            report = validate_candidate(
                finding,
                company_name,
                repo_fullname,
                commit_sha or "",
                commit_url or "",
                policy,
            )
            if report["false_positive"]:
                stats["false_positives"] = stats.get("false_positives", 0) + 1
            if not report["in_scope"]:
                stats["out_of_scope"] = stats.get("out_of_scope", 0) + 1
                continue

            if is_finding_duplicate(report["fingerprint"]):
                report["duplicate"] = True
                report["duplicate_probability"] = 1
                report["negative_evidence"].append("already_known_finding")
                stats["duplicates"] = stats.get("duplicates", 0) + 1
                record_finding(report)
                continue

            report["ai_confirmed"] = False
            if (
                report["evidence_complete"]
                and report["confidence_level"] in {"HIGH", "VERY_HIGH"}
                and report["scope_status"] == "IN_SCOPE"
                and not report["false_positive"]
            ):
                ai_eval = analyze_finding_with_ai(report)
                report["ai_reasoning"] = ai_eval.get("reason", "")
                report["ai_missing_evidence"] = ai_eval.get("missing_evidence", [])
                report["ai_confirmed"] = ai_eval.get("should_notify") is True
                if not report["ai_confirmed"]:
                    report["negative_evidence"].append(
                        "AI_classification_did_not_confirm_or_evidence_missing"
                    )

            if report["confidence_level"] == "HIGH":
                stats["high_confidence"] = stats.get("high_confidence", 0) + 1
            elif report["confidence_level"] == "VERY_HIGH":
                stats["very_high_confidence"] = stats.get("very_high_confidence", 0) + 1

            alertable = may_send_telegram(report)
            if alertable:
                report["status"] = "HIGH_CONFIDENCE_FINDING"
            was_duplicate = record_finding(report)
            if was_duplicate:
                report["duplicate"] = True
                stats["duplicates"] = stats.get("duplicates", 0) + 1
                continue
            stats["reports_generated"] = stats.get("reports_generated", 0) + 1

            if alertable:
                payload = {
                    **report,
                    "repo": repo_fullname,
                    "commit_sha": commit_sha,
                    "context": report["redacted_context"],
                    "ai_reason": report["ai_reasoning"],
                }
                if send_telegram_alert(payload):
                    stats["telegram_sent"] = stats.get("telegram_sent", 0) + 1
                    print(f"🚨 [HIGH-CONFIDENCE FINDING] {repo_fullname} ({finding.get('type')})")


def run_monitoring_cycle():
    """تشغيل دورة فحص واحدة لكافة الشركات المستهدفة"""
    print("\n⚡ [CYCLE START] جاري استعلام برامج المستودعات المستهدفة...")
    stats = {
        "commits_seen": 0,
        "commits_analyzed": 0,
        "repositories_scanned": 0,
        "files_analyzed": 0,
        "lines_analyzed": 0,
        "candidates": 0,
        "secrets_detected": 0,
        "potential_vulnerabilities": 0,
        "false_positives": 0,
        "out_of_scope": 0,
        "duplicates": 0,
        "high_confidence": 0,
        "very_high_confidence": 0,
        "reports_generated": 0,
        "telegram_sent": 0,
        "github_api_errors": 0,
    }
    policy = load_scope_policy()
    authorized_targets = []

    programs = policy.get("programs", {})
    if not isinstance(programs, dict):
        raise RuntimeError("Scope policy has an invalid programs mapping")
    for company_name, program in programs.items():
        if not isinstance(company_name, str) or not isinstance(program, dict):
            continue
        org_name = program.get("organization")
        if not isinstance(org_name, str) or not org_name:
            continue

        repositories = set(authorized_repositories(company_name, policy))
        if organization_wildcard_is_authorized(company_name, org_name, policy):
            try:
                discovered = get_company_repositories(org_name)
            except GitHubAPIError as error:
                stats["github_api_errors"] += 1
                logger.error(
                    "Could not discover public repositories for authorized organization %s: %s",
                    org_name,
                    error,
                )
                discovered = []
            for item in discovered:
                full_name = item.get("full_name")
                if (
                    isinstance(full_name, str)
                    and repository_is_authorized(company_name, full_name, policy)
                ):
                    repositories.add(full_name)

        if TARGET_REPOS:
            repositories = {
                repository
                for repository in repositories
                if repository.casefold() in TARGET_REPOS
            }
        authorized_targets.extend(
            (company_name, org_name, repository) for repository in repositories
        )

    print(f"GitHub token configured: {'yes' if My_GITHUB_TOKEN else 'no (unauthenticated API limits)'}")
    if TARGET_REPOS:
        print(f"TARGET_REPOS filter configured: {len(TARGET_REPOS)} repository/repositories")
    if not authorized_targets:
        if TARGET_REPOS:
            print(
                "No repositories scanned: TARGET_REPOS did not match any repository "
                "explicitly authorized in scope_policy.json."
            )
        else:
            print(
                "No repositories scanned: no repositories matched a verified scope policy. "
                "Organization discovery requires an explicit, verified all-public-repositories "
                "wildcard; organization names alone do not authorize scanning."
            )
        print("Add verified in-scope repositories to scope_policy.json, then run again.")

    authorized_targets.sort(key=lambda target: target[2].casefold())
    for company_name, org_name, repo_fullname in authorized_targets:
        print(f"🔍 فحص شركة: {company_name} ({org_name})...")
        owner, repo_name = repo_fullname.split("/", 1)
        stats["repositories_scanned"] += 1
        try:
            commits = get_repo_recent_commits(owner, repo_name, limit=5)
        except GitHubAPIError as error:
            stats["github_api_errors"] += 1
            logger.error(
                "Could not list commits for authorized repository %s: %s",
                repo_fullname,
                error,
            )
            continue

        for commit in commits:
            if not isinstance(commit, dict):
                stats["github_api_errors"] += 1
                logger.error("GitHub returned malformed commit data for %s", repo_fullname)
                continue
            commit_sha = commit.get("sha")
            commit_url = commit.get("html_url")
            if not commit_sha:
                continue
            stats["commits_seen"] += 1

            if is_commit_processed(commit_sha, repo_fullname):
                print(f"   ⏩ الـ Commit ({commit_sha[:7]}) مفحوص سابقاً.. تجاوز.")
                break

            print(f"   🔎 جاري فحص الـ Commit الجديد: {commit_sha[:7]} في {repo_fullname}...")

            try:
                commit_details = get_commit_details(owner, repo_name, commit_sha)
            except GitHubAPIError as error:
                stats["github_api_errors"] += 1
                logger.error(
                    "Could not fetch commit %s from %s; it will be retried: %s",
                    commit_sha[:7],
                    repo_fullname,
                    error,
                )
                continue
            if "files" not in commit_details or not isinstance(
                commit_details["files"], list
            ):
                stats["github_api_errors"] += 1
                logger.error(
                    "Commit details for %s at %s contained no valid files list; "
                    "it will be retried",
                    repo_fullname,
                    commit_sha[:7],
                )
                continue
            stats["commits_analyzed"] += 1
            static_candidates = []
            options = scanner_options(company_name, repo_fullname, policy)
            if options.get("dependency_advisory_catalog"):
                try:
                    catalog_path = options["dependency_advisory_catalog"]
                    with open(catalog_path, encoding="utf-8") as catalog_file:
                        advisory_catalog = json.load(catalog_file)
                    owner_name, repository_name = repo_fullname.split("/", 1)
                    for changed_file in commit_details.get("files", []):
                        file_path = changed_file.get("filename", "")
                        if not file_path.endswith(
                            ("package-lock.json", "requirements.txt", "requirements.lock")
                        ):
                            continue
                        if not source_path_is_authorized(
                            company_name, repo_fullname, file_path, policy
                        ):
                            continue
                        source = get_file_content_at_commit(
                            owner_name,
                            repository_name,
                            file_path,
                            commit_sha,
                        )
                        if source:
                            static_candidates.extend(
                                analyze_dependency_manifest(
                                    source,
                                    file_path,
                                    advisory_catalog,
                                    commit_sha,
                                )
                            )
                except (OSError, ValueError, json.JSONDecodeError):
                    logger.exception(
                        "Offline dependency advisory scan failed for %s at %s",
                        repo_fullname,
                        commit_sha,
                    )
            if options.get("checkout_path"):
                try:
                    static_candidates.extend(run_configured_scans(options, commit_sha))
                except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
                    logger.exception(
                        "Configured static analysis failed for %s at %s: %s",
                        repo_fullname,
                        commit_sha,
                        error,
                    )
            process_commit(
                company_name,
                repo_fullname,
                commit_details,
                commit_url or "",
                policy,
                stats,
                static_candidates,
            )

            mark_commit_processed(commit_sha, repo_fullname)
            time.sleep(0.3)

    print("\n## SCAN SUMMARY")
    print(f"Repositories scanned: {stats['repositories_scanned']}")
    print(f"Commits seen: {stats['commits_seen']}")
    print(f"Commits analyzed: {stats['commits_analyzed']}")
    print(f"Files analyzed: {stats['files_analyzed']}")
    print(f"Lines analyzed: {stats['lines_analyzed']}")
    print(f"Candidates: {stats['candidates']}")
    print(f"Secrets detected: {stats['secrets_detected']}")
    print(f"Potential vulnerabilities: {stats['potential_vulnerabilities']}")
    print(f"False positives: {stats['false_positives']}")
    print(f"Out of scope: {stats['out_of_scope']}")
    print(f"Duplicates: {stats['duplicates']}")
    print(f"High confidence: {stats['high_confidence']}")
    print(f"Very high confidence: {stats['very_high_confidence']}")
    print(f"Reports generated: {stats['reports_generated']}")
    print(f"Telegram alerts: {stats['telegram_sent']}")
    print(f"GitHub API errors: {stats['github_api_errors']}")
    candidate_count = max(stats["candidates"], 1)
    print(f"Signal rate: {stats['telegram_sent'] / candidate_count:.2%}")
    print(
        "High-confidence rate: "
        f"{(stats['high_confidence'] + stats['very_high_confidence']) / candidate_count:.2%}"
    )
    print(f"Duplicate rate: {stats['duplicates'] / candidate_count:.2%}")
    print(f"False-positive rate: {stats['false_positives'] / candidate_count:.2%}")
    if not authorized_targets:
        if stats["github_api_errors"]:
            raise RuntimeError(
                "No repositories were scanned because GitHub discovery failed; see API errors"
            )
        raise RuntimeError(
            "No repositories were scanned because no repositories matched the verified "
            "scope policy and TARGET_REPOS filter"
        )
    if stats["github_api_errors"]:
        raise RuntimeError(
            f"Monitoring cycle completed with {stats['github_api_errors']} GitHub API error(s)"
        )