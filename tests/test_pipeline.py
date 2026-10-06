import contextlib
import base64
import io
import tempfile
import unittest
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ai
import config
import github_monitor
import main as app_main
import notifier
import storage
from detector import scan_text_for_secrets
from detection_engine import DetectionContext, detect_candidates, merge_independent_evidence
from dependency_analysis import analyze_dependency_manifest
from pipeline import may_send_telegram, validate_candidate
from policy import (
    authorized_repositories,
    evaluate_scope,
    load_scope_policy,
    scanner_options,
)
from static_tools import parse_sarif, parse_semgrep_results


def eligible_policy() -> dict:
    return {
        "programs": {
            "Example Program": {
                "organization": "example-org",
                "repositories": {
                    "example-org/app": {
                        "in_scope": True,
                        "bounty_eligible": True,
                        "source_code_eligible": True,
                        "requirements_confirmed": True,
                        "policy_url": "https://example.com/bug-bounty",
                        "allowed_types": [
                            "Potential SQL Injection",
                            "Insecure Permissive CORS",
                            "GitHub Personal Access Token",
                            "AWS Access Key ID",
                        ],
                    }
                }
            }
        }
    }


def eligible_wildcard_policy() -> dict:
    return {
        "programs": {
            "Example Program": {
                "organization": "example-org",
                "in_scope_repos": ["*"],
                "in_scope": True,
                "all_public_repositories_confirmed": True,
                "bounty_eligible": True,
                "source_code_eligible": True,
                "requirements_confirmed": True,
                "policy_url": "https://example.com/bug-bounty",
                "allowed_types": [
                    "Potential SQL Injection",
                    "GitHub Personal Access Token",
                ],
                "excluded_repositories": ["example-org/internal"],
                "excluded_paths": ["generated/"],
            }
        }
    }


class EvidencePipelineTests(unittest.TestCase):
    def test_real_shaped_secret_is_redacted_and_kept_as_candidate(self) -> None:
        token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
        finding = scan_text_for_secrets(f'TOKEN = "{token}"', "src/settings.py")[0]
        self.assertEqual(finding["status"], "POTENTIAL")
        self.assertEqual(finding["provider"], "GitHub")
        self.assertNotIn(token, finding["redacted_context"])
        self.assertNotIn(token, repr(finding))

    def test_multiline_private_key_body_is_not_returned_or_exposed_to_entropy_scan(self) -> None:
        body = "MIIEpAIBAAKCAQEA" + "A1b2C3d4" * 12
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{body}\n"
            "-----END RSA PRIVATE KEY-----"
        )
        findings = scan_text_for_secrets(pem, "src/key.pem")
        self.assertTrue(findings)
        self.assertTrue(all(body not in repr(item) for item in findings))
        self.assertTrue(all("REDACTED_SECRET" in item["redacted_context"] for item in findings))

    def test_known_fake_secret_is_rejected(self) -> None:
        finding = scan_text_for_secrets(
            'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"', "src/settings.py"
        )[0]
        self.assertEqual(finding["status"], "FALSE_POSITIVE")
        self.assertTrue(finding["is_placeholder"])

    def test_test_fixture_secret_is_rejected(self) -> None:
        token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
        finding = scan_text_for_secrets(
            f'TOKEN = "{token}"', "tests/fixtures/test_credentials.py"
        )[0]
        self.assertTrue(finding["is_test"])
        self.assertEqual(finding["status"], "FALSE_POSITIVE")
        self.assertNotIn(token, finding["redacted_context"])

    def test_placeholder_is_rejected(self) -> None:
        finding = scan_text_for_secrets(
            'API_KEY = "YOUR_API_KEY"', ".env.example"
        )[0]
        self.assertTrue(finding["is_placeholder"])
        self.assertTrue(finding["is_example"])
        self.assertEqual(finding["status"], "FALSE_POSITIVE")

    def test_wildcard_cors_without_impact_is_false_positive(self) -> None:
        finding = scan_text_for_secrets(
            'Access-Control-Allow-Origin: "*"', "src/server.py"
        )[0]
        report = validate_candidate(
            finding, "Example Program", "example-org/app", "abc", "", eligible_policy()
        )
        self.assertEqual(report["impact"], 0)
        self.assertEqual(report["status"], "FALSE_POSITIVE")
        self.assertFalse(may_send_telegram(report))

    def test_cors_with_sensitive_context_has_impact_but_is_not_auto_confirmed(self) -> None:
        text = (
            'Access-Control-Allow-Origin: "*"\n'
            "Access-Control-Allow-Credentials: true\n"
            "return current_user.private_profile"
        )
        finding = scan_text_for_secrets(text, "src/server.py")[0]
        report = validate_candidate(
            finding, "Example Program", "example-org/app", "abc", "", eligible_policy()
        )
        self.assertEqual(report["impact"], 3)
        self.assertFalse(report["evidence_complete"])
        self.assertFalse(may_send_telegram(report))

    def test_optimistic_update_is_not_sql_injection(self) -> None:
        self.assertEqual(
            scan_text_for_secrets(
                "const optimisticUpdate = () => cache.update + state;",
                "src/ui.ts",
            ),
            [],
        )

    def test_safe_parameterized_sql_is_not_a_candidate(self) -> None:
        self.assertEqual(
            scan_text_for_secrets(
                'db.query("SELECT * FROM users WHERE id = ?", [request.query.id]);',
                "src/db.ts",
            ),
            [],
        )

    def test_ssrf_candidate_and_allowlisted_url_are_distinguished_as_candidates(self) -> None:
        unsafe = scan_text_for_secrets(
            "fetch(request.query.url)", "src/fetcher.js"
        )
        safe = scan_text_for_secrets(
            "if (!isAllowedUrl(request.query.url)) throw Error();\n"
            "fetch(validatedUrl)",
            "src/fetcher.js",
        )
        self.assertTrue(any(item["type"] == "Potential SSRF" for item in unsafe))
        self.assertFalse(any(item["type"] == "Potential SSRF" for item in safe))

    def test_command_candidate_is_detected_but_escaped_command_is_not_matched(self) -> None:
        unsafe = scan_text_for_secrets(
            "subprocess.run(request.args)", "src/runner.py"
        )
        safe = scan_text_for_secrets(
            "subprocess.run(shlex.quote(command), shell=False)", "src/runner.py"
        )
        self.assertTrue(any(item["type"] == "Unsafe Command Execution" for item in unsafe))
        self.assertFalse(any(item["type"] == "Unsafe Command Execution" for item in safe))

    def test_path_traversal_candidate_and_safe_join_are_not_equivalent(self) -> None:
        unsafe = scan_text_for_secrets(
            "open(request.args['path'])", "src/download.py"
        )
        safe = scan_text_for_secrets(
            "open(safe_join(base_dir, validated_name))", "src/download.py"
        )
        self.assertTrue(any(item["type"] == "Potential Path Traversal" for item in unsafe))
        self.assertFalse(any(item["type"] == "Potential Path Traversal" for item in safe))

    def test_idor_and_github_actions_candidates_are_static_candidates_only(self) -> None:
        idor = scan_text_for_secrets(
            "record = User.findById(request.params.id)", "src/users.js"
        )
        unsafe_workflow = scan_text_for_secrets(
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}",
            ".github/workflows/test.yml",
        )
        safe_workflow = scan_text_for_secrets(
            "on:\n  pull_request:\npermissions:\n  contents: read",
            ".github/workflows/test.yml",
        )
        self.assertTrue(any(item["type"] == "Potential IDOR" for item in idor))
        self.assertTrue(
            any(item["type"] == "Potential Unsafe GitHub Actions Trigger" for item in unsafe_workflow)
        )
        self.assertTrue(
            any(item["type"] == "Potential Untrusted GitHub Actions Checkout" for item in unsafe_workflow)
        )
        self.assertEqual(safe_workflow, [])

    def test_sql_candidate_requires_independent_evidence_before_high_confidence(self) -> None:
        source = 'db.query("SELECT * FROM users WHERE id = " + request.query.id);'
        finding = scan_text_for_secrets(source, "src/db.ts")[0]
        report = validate_candidate(
            finding, "Example Program", "example-org/app", "abc", "", eligible_policy()
        )
        self.assertEqual(report["reachability"], 3)
        self.assertEqual(report["impact"], 3)
        self.assertFalse(report["evidence_complete"])
        self.assertNotIn(report["confidence_level"], {"HIGH", "VERY_HIGH"})
        finding["static_analysis"] = [
            {
                "tool": "semgrep",
                "rule_id": "rule-1",
                "file": "src/db.ts",
                "line": finding["line"],
                "commit": "abc",
            },
            {
                "tool": "codeql",
                "rule_id": "query-2",
                "file": "src/db.ts",
                "line": finding["line"],
                "commit": "abc",
            },
        ]
        validated = validate_candidate(
            finding, "Example Program", "example-org/app", "abc", "", eligible_policy()
        )
        self.assertTrue(validated["evidence_complete"])
        self.assertIn(validated["confidence_level"], {"HIGH", "VERY_HIGH"})
        self.assertFalse(may_send_telegram(validated))

    def test_duplicate_fingerprint_ignores_commit(self) -> None:
        candidate = scan_text_for_secrets(
            'db.query("SELECT * FROM users WHERE id = " + request.query.id);',
            "src/db.ts",
        )[0]
        first = validate_candidate(
            candidate, "Example Program", "example-org/app", "commit-a", "", eligible_policy()
        )
        second = validate_candidate(
            candidate, "Example Program", "example-org/app", "commit-b", "", eligible_policy()
        )
        self.assertEqual(first["fingerprint"], second["fingerprint"])

    def test_same_finding_across_commits_is_one_record_with_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original_db = storage.DB_NAME
            original_state_file = storage.STATE_FILE
            storage.DB_NAME = str(Path(directory) / "test.db")
            storage.STATE_FILE = Path(directory) / "state.json"
            try:
                storage.init_db()
                report = {
                    "fingerprint": "same-finding",
                    "commit": "commit-a",
                    "company": "Example Program",
                    "repository": "example-org/app",
                    "type": "Potential SQL Injection",
                    "redacted_context": "safe",
                }
                self.assertFalse(storage.record_finding(report))
                later_observation = {**report, "commit": "commit-b"}
                self.assertTrue(storage.record_finding(later_observation))
                connection = storage.get_db_connection()
                try:
                    self.assertEqual(
                        connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                        1,
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM finding_observations"
                        ).fetchone()[0],
                        2,
                    )
                finally:
                    connection.close()
            finally:
                storage.DB_NAME = original_db
                storage.STATE_FILE = original_state_file

    def test_finding_fingerprint_survives_new_ephemeral_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original_db = storage.DB_NAME
            original_state_file = storage.STATE_FILE
            storage.DB_NAME = str(Path(directory) / "first.db")
            storage.STATE_FILE = Path(directory) / "state.json"
            try:
                storage.init_db()
                self.assertFalse(
                    storage.record_finding(
                        {
                            "fingerprint": "stable-finding-hash",
                            "commit": "commit-a",
                            "redacted_context": "safe",
                        }
                    )
                )
                storage.DB_NAME = str(Path(directory) / "next-run.db")
                storage.init_db()
                self.assertTrue(storage.is_finding_duplicate("stable-finding-hash"))
                self.assertTrue(
                    storage.record_finding(
                        {
                            "fingerprint": "stable-finding-hash",
                            "commit": "commit-b",
                            "redacted_context": "safe",
                        }
                    )
                )
            finally:
                storage.DB_NAME = original_db
                storage.STATE_FILE = original_state_file

    def test_processed_commits_are_scoped_to_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original_state_file = storage.STATE_FILE
            storage.STATE_FILE = Path(directory) / "state.json"
            try:
                storage.mark_commit_processed("shared-sha", "example-org/first")
                self.assertTrue(
                    storage.is_commit_processed("shared-sha", "example-org/first")
                )
                self.assertFalse(
                    storage.is_commit_processed("shared-sha", "example-org/second")
                )
                state = json.loads(storage.STATE_FILE.read_text(encoding="utf-8"))
                self.assertEqual(
                    state,
                    {
                        "processed_repository_commits": {
                            "example-org/first": ["shared-sha"]
                        },
                        "finding_fingerprints": [],
                    },
                )
            finally:
                storage.STATE_FILE = original_state_file

    def test_invalid_persisted_state_fails_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original_state_file = storage.STATE_FILE
            storage.STATE_FILE = Path(directory) / "state.json"
            storage.STATE_FILE.write_text("{invalid", encoding="utf-8")
            try:
                with self.assertRaisesRegex(RuntimeError, "Could not read scanner state"):
                    storage.is_commit_processed("commit-a", "example-org/app")
            finally:
                storage.STATE_FILE = original_state_file

    def test_once_flag_runs_one_cycle_and_returns_success(self) -> None:
        with (
            patch.object(app_main, "run_monitoring_cycle") as cycle,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = app_main.main(["--once"])
        self.assertEqual(result, 0)
        cycle.assert_called_once_with()

    def test_once_flag_returns_failure_when_cycle_raises(self) -> None:
        with (
            patch.object(
                app_main,
                "run_monitoring_cycle",
                side_effect=RuntimeError("cycle failed"),
            ) as cycle,
            self.assertLogs(app_main.logger, level="ERROR"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = app_main.main(["--once"])
        self.assertEqual(result, 1)
        cycle.assert_called_once_with()

    def test_storage_redacts_secret_from_structured_report(self) -> None:
        token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
        with tempfile.TemporaryDirectory() as directory:
            original_db = storage.DB_NAME
            original_state_file = storage.STATE_FILE
            storage.DB_NAME = str(Path(directory) / "test.db")
            storage.STATE_FILE = Path(directory) / "state.json"
            try:
                storage.init_db()
                storage.record_finding(
                    {
                        "fingerprint": "redacted-report",
                        "commit": "commit-a",
                        "redacted_context": f'TOKEN = "{token}"',
                        "evidence": [f"candidate value: {token}"],
                    }
                )
                connection = storage.get_db_connection()
                try:
                    persisted = connection.execute(
                        "SELECT context, report_json FROM findings"
                    ).fetchone()
                    self.assertNotIn(token, persisted["context"])
                    self.assertNotIn(token, persisted["report_json"])
                finally:
                    connection.close()
            finally:
                storage.DB_NAME = original_db
                storage.STATE_FILE = original_state_file

    def test_unconfigured_asset_is_out_of_scope(self) -> None:
        result = evaluate_scope(
            "Example Program",
            "example-org/app",
            "Potential SQL Injection",
            "src/db.py",
            {"programs": {}},
        )
        self.assertFalse(result["in_scope"])
        self.assertFalse(result["bounty_eligible"])
        self.assertEqual(result["scope_status"], "OUT_OF_SCOPE")

    def test_explicit_bounty_eligible_asset_is_in_scope(self) -> None:
        result = evaluate_scope(
            "Example Program",
            "example-org/app",
            "Potential SQL Injection",
            "src/db.py",
            eligible_policy(),
        )
        self.assertTrue(result["in_scope"])
        self.assertTrue(result["bounty_eligible"])
        self.assertEqual(result["scope_status"], "IN_SCOPE")

    def test_policy_type_exclusions_override_general_asset_scope(self) -> None:
        policy = eligible_policy()
        asset = policy["programs"]["Example Program"]["repositories"]["example-org/app"]
        asset["excluded_types"] = ["Potential SQL Injection"]
        result = evaluate_scope(
            "Example Program", "example-org/app", "Potential SQL Injection", "src/db.py", policy
        )
        self.assertFalse(result["in_scope"])
        self.assertIn("finding_type_excluded_by_policy", result["scope_evidence"]["reasons"])

    def test_alert_gate_requires_ai_confirmation_and_every_evidence_gate(self) -> None:
        valid = {
            "confidence_level": "HIGH",
            "in_scope": True,
            "bounty_eligible": True,
            "duplicate": False,
            "false_positive": False,
            "evidence_complete": True,
            "ai_confirmed": True,
            "reachability": 3,
            "impact": 3,
        }
        self.assertTrue(may_send_telegram(valid))
        for key, value in (
            ("ai_confirmed", False),
            ("evidence_complete", False),
            ("in_scope", False),
            ("bounty_eligible", False),
            ("duplicate", True),
            ("false_positive", True),
            ("confidence_level", "MEDIUM"),
            ("reachability", 2),
            ("impact", 2),
        ):
            with self.subTest(gate=key):
                self.assertFalse(may_send_telegram({**valid, key: value}))

    def test_ai_receives_redacted_context_and_cannot_assign_confidence(self) -> None:
        token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
        client = Mock()
        client.chat.completions.create.return_value = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=json.dumps(
                            {
                                "classification": "INSUFFICIENT_EVIDENCE",
                                "reason_ar": "الأدلة غير كافية",
                                "missing_evidence": ["reachability"],
                            }
                        )
                    )
                )
            ]
        )
        with patch.object(ai, "groq_client", client):
            result = ai.analyze_finding_with_ai(
                {
                    "type": "GitHub Personal Access Token",
                    "redacted_context": f'TOKEN = "{token}"',
                }
            )
        sent_messages = client.chat.completions.create.call_args.kwargs["messages"]
        self.assertNotIn(token, repr(sent_messages))
        self.assertFalse(result["should_notify"])
        self.assertEqual(result["classification"], "INSUFFICIENT_EVIDENCE")
        self.assertNotIn("confidence", result)

    def test_notifier_blocks_candidate_even_if_called_directly(self) -> None:
        with patch.object(notifier.requests, "post") as post:
            sent = notifier.send_telegram_alert(
                {
                    "confidence_level": "MEDIUM",
                    "in_scope": True,
                    "bounty_eligible": True,
                    "duplicate": False,
                    "false_positive": False,
                    "evidence_complete": True,
                    "ai_confirmed": True,
                    "reachability": 4,
                    "impact": 5,
                }
            )
        self.assertFalse(sent)
        post.assert_not_called()

    def test_notifier_does_not_log_bot_token_from_request_exception(self) -> None:
        bot_token = "123456:private-test-token"
        payload = {
            "confidence_level": "HIGH",
            "in_scope": True,
            "bounty_eligible": True,
            "duplicate": False,
            "false_positive": False,
            "evidence_complete": True,
            "ai_confirmed": True,
            "reachability": 3,
            "impact": 3,
            "company": "Example",
            "repo": "example-org/app",
            "type": "Potential SQL Injection",
            "context": "safe context",
            "commit_url": "https://github.com/example-org/app/commit/abc",
        }
        with (
            patch.object(notifier, "TELEGRAM_BOT_TOKEN", bot_token),
            patch.object(notifier, "TELEGRAM_CHAT_ID", "test-chat"),
            patch.object(
                notifier.requests,
                "post",
                side_effect=notifier.requests.ConnectionError(
                    f"failed at https://api.telegram.org/bot{bot_token}/sendMessage"
                ),
            ),
            self.assertLogs(notifier.logger, level="ERROR") as captured,
        ):
            sent = notifier.send_telegram_alert(payload)
        self.assertFalse(sent)
        self.assertNotIn(bot_token, "\n".join(captured.output))

    def test_monitor_discards_unscoped_candidate_before_ai_or_dedup(self) -> None:
        stats = {}
        commit = {
            "sha": "commit-a",
            "files": [
                {
                    "filename": "src/server.py",
                    "patch": '@@ -0,0 +1 @@\n+Access-Control-Allow-Origin: "*"',
                }
            ],
        }
        with (
            patch.object(github_monitor, "analyze_finding_with_ai") as ai_call,
            patch.object(github_monitor, "is_finding_duplicate") as duplicate_check,
        ):
            github_monitor.process_commit(
                "Unknown Program",
                "unknown-org/repo",
                commit,
                "",
                {"programs": {}},
                stats,
            )
        ai_call.assert_not_called()
        duplicate_check.assert_not_called()
        self.assertEqual(stats["out_of_scope"], 1)

    def test_empty_scope_prevents_github_repository_collection(self) -> None:
        output = io.StringIO()
        with (
            patch.object(github_monitor, "load_scope_policy", return_value={"programs": {}}),
            patch.object(github_monitor, "get_company_repositories") as list_repos,
            contextlib.redirect_stdout(output),
            self.assertRaisesRegex(RuntimeError, "no repositories matched"),
        ):
            github_monitor.run_monitoring_cycle()
        list_repos.assert_not_called()
        self.assertIn("verified all-public-repositories wildcard", output.getvalue())

    def test_verified_organization_wildcard_authorizes_matching_public_asset(self) -> None:
        policy = eligible_wildcard_policy()
        self.assertTrue(
            github_monitor.organization_wildcard_is_authorized(
                "Example Program", "example-org", policy
            )
        )
        self.assertTrue(
            github_monitor.repository_is_authorized(
                "Example Program", "example-org/public-repo", policy
            )
        )
        result = evaluate_scope(
            "Example Program",
            "example-org/public-repo",
            "Potential SQL Injection",
            "src/db.py",
            policy,
        )
        self.assertTrue(result["in_scope"])

    def test_wildcard_requires_explicit_all_public_attestation_and_honors_exclusions(self) -> None:
        policy = eligible_wildcard_policy()
        program = policy["programs"]["Example Program"]
        program.pop("all_public_repositories_confirmed")
        self.assertFalse(
            github_monitor.repository_is_authorized(
                "Example Program", "example-org/repo", policy
            )
        )

        policy = eligible_wildcard_policy()
        self.assertFalse(
            github_monitor.repository_is_authorized(
                "Example Program", "example-org/internal", policy
            )
        )
        self.assertFalse(
            github_monitor.source_path_is_authorized(
                "Example Program",
                "example-org/public-repo",
                "generated/output.py",
                policy,
            )
        )

    def test_prepopulated_organization_wildcards_are_disabled_by_default(self) -> None:
        policy = load_scope_policy()
        programs = policy["programs"]
        self.assertTrue(
            {
                "Shopify",
                "GitLab",
                "Automattic",
                "Brave",
                "PayPal",
                "Uber",
                "Salesforce",
                "HashiCorp",
            }.issubset(programs)
        )
        self.assertFalse(
            any(
                github_monitor.organization_wildcard_is_authorized(
                    name, program["organization"], policy
                )
                for name, program in programs.items()
            )
        )

    def test_organization_repository_discovery_paginates_and_filters_public_org_repos(self) -> None:
        first_page = [
            {
                "full_name": f"example-org/repo-{index}",
                "owner": {"login": "example-org"},
                "private": False,
            }
            for index in range(100)
        ]
        first_page.extend(
            [
                {
                    "full_name": "other-org/fork",
                    "owner": {"login": "other-org"},
                    "private": False,
                },
                {
                    "full_name": "example-org/private",
                    "owner": {"login": "example-org"},
                    "private": True,
                },
            ]
        )
        with patch.object(
            github_monitor,
            "_github_get_json",
            side_effect=[first_page, []],
        ) as request:
            repositories = github_monitor.get_company_repositories("example-org")

        self.assertEqual(len(repositories), 100)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[0].args[1]["type"], "public")
        self.assertEqual(request.call_args_list[1].args[1]["page"], 2)

    def test_monitor_discovers_and_scans_repositories_from_verified_wildcard(self) -> None:
        output = io.StringIO()
        discovered = [
            {
                "full_name": "example-org/active-repo",
                "owner": {"login": "example-org"},
                "private": False,
            }
        ]
        with (
            patch.object(
                github_monitor,
                "load_scope_policy",
                return_value=eligible_wildcard_policy(),
            ),
            patch.object(
                github_monitor, "get_company_repositories", return_value=discovered
            ) as discover,
            patch.object(
                github_monitor, "get_repo_recent_commits", return_value=[]
            ) as fetch_commits,
            contextlib.redirect_stdout(output),
        ):
            github_monitor.run_monitoring_cycle()

        discover.assert_called_once_with("example-org")
        fetch_commits.assert_called_once_with(
            "example-org", "active-repo", limit=5
        )
        self.assertIn("Repositories scanned: 1", output.getvalue())

    def test_target_repositories_parse_as_case_insensitive_full_names(self) -> None:
        self.assertEqual(
            config.parse_target_repositories("Org/Repo, another/project ,"),
            {"org/repo", "another/project"},
        )

    def test_github_api_rate_limit_is_reported_instead_of_empty_results(self) -> None:
        response = Mock()
        response.status_code = 403
        response.headers = {
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "1791330000",
        }
        with (
            patch.object(github_monitor.requests, "get", return_value=response),
            self.assertRaisesRegex(
                github_monitor.GitHubAPIError,
                "API rate limit exhausted",
            ),
        ):
            github_monitor.get_repo_recent_commits("example-org", "app")

    def test_authorized_target_repo_is_requested_for_recent_commits(self) -> None:
        output = io.StringIO()
        with (
            patch.object(github_monitor, "TARGET_REPOS", {"example-org/app"}),
            patch.object(
                github_monitor,
                "load_scope_policy",
                return_value=eligible_policy(),
            ),
            patch.object(
                github_monitor,
                "get_repo_recent_commits",
                return_value=[],
            ) as fetch_commits,
            contextlib.redirect_stdout(output),
        ):
            github_monitor.run_monitoring_cycle()

        fetch_commits.assert_called_once_with("example-org", "app", limit=5)
        self.assertIn("Repositories scanned: 1", output.getvalue())

    def test_unconfigured_tools_return_no_external_scan_candidates(self) -> None:
        self.assertEqual(
            scanner_options("Example Program", "example-org/app", eligible_policy()),
            {},
        )

    def test_only_explicitly_authorized_repositories_are_collected(self) -> None:
        self.assertEqual(
            authorized_repositories("Example Program", eligible_policy()),
            ["example-org/app"],
        )

    def test_dependency_advisory_match_is_candidate_not_confirmed_finding(self) -> None:
        lockfile = json.dumps(
            {
                "packages": {
                    "": {"name": "example-app", "version": "1.0.0"},
                    "node_modules/example-package": {
                        "name": "example-package",
                        "version": "1.2.3",
                    },
                }
            }
        )
        catalog = {
            "advisories": [
                {
                    "id": "CVE-2099-12345",
                    "ecosystem": "npm",
                    "package": "example-package",
                    "affected_versions": ["1.2.3"],
                    "severity": "HIGH",
                }
            ]
        }
        findings = analyze_dependency_manifest(
            lockfile, "package-lock.json", catalog, "commit-a"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "POTENTIAL")
        self.assertEqual(findings[0]["advisory_id"], "CVE-2099-12345")
        self.assertEqual(findings[0]["commit"], "commit-a")

    def test_semgrep_results_are_normalized_and_secrets_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
            payload = {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.command-injection",
                        "path": "src/handler.py",
                        "start": {"line": 12},
                        "extra": {
                            "message": "Command injection",
                            "lines": f"subprocess.run(request.args['cmd']) # {token}",
                            "metadata": {"cwe": ["CWE-78"]},
                        },
                    }
                ]
            }
            findings = parse_semgrep_results(payload, root, "abc")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source_file"], "src/handler.py")
        self.assertEqual(findings[0]["line"], 12)
        self.assertEqual(findings[0]["type"], "Unsafe Command Execution")
        self.assertNotIn(token, repr(findings))
        self.assertEqual(findings[0]["static_analysis"][0]["commit"], "abc")

    def test_sarif_outside_checkout_is_discarded(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            payload = {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {"id": "py/sql-injection", "properties": {"tags": ["CWE-89"]}}
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/sql-injection",
                                "message": {"text": "SQL injection"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": str(Path(outside) / "file.py")
                                            },
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        self.assertEqual(parse_sarif(payload, root, "abc"), [])

    def test_sarif_normalizes_codeql_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {"id": "py/sql-injection", "properties": {"tags": ["CWE-89"]}}
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/sql-injection",
                                "message": {"text": "SQL injection"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/db.py"},
                                            "region": {
                                                "startLine": 4,
                                                "snippet": {
                                                    "text": "db.execute('SELECT * FROM x ' + request.args['id'])"
                                                },
                                            },
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
            findings = parse_sarif(payload, root, "abc")
        self.assertEqual(findings[0]["type"], "Potential SQL Injection")
        self.assertEqual(findings[0]["static_analysis"][0]["tool"], "codeql")

    def test_detection_engine_preserves_legacy_detector_api(self) -> None:
        context = DetectionContext(
            "const optimisticUpdate = () => cache.update + state;",
            "src/ui.ts",
            "abc",
        )
        self.assertEqual(detect_candidates(context), [])
        self.assertEqual(
            scan_text_for_secrets(context.text, context.file_path, context.commit),
            [],
        )

    def test_candidates_from_independent_tools_merge_at_same_location(self) -> None:
        base = {
            "source_file": "src/db.py",
            "line": 9,
            "type": "Potential SQL Injection",
            "evidence": ["pattern:candidate"],
        }
        semgrep = {
            **base,
            "static_analysis": [
                {"tool": "semgrep", "rule_id": "sqli", "file": "src/db.py", "line": 9, "commit": "abc"}
            ],
        }
        codeql = {
            **base,
            "static_analysis": [
                {"tool": "codeql", "rule_id": "py/sqli", "file": "src/db.py", "line": 9, "commit": "abc"}
            ],
        }
        merged = merge_independent_evidence([semgrep, codeql])
        self.assertEqual(len(merged), 1)
        report = validate_candidate(
            {**merged[0], "redacted_context": "db.query(request.query.id)"},
            "Example Program",
            "example-org/app",
            "abc",
            "",
            eligible_policy(),
        )
        self.assertTrue(report["evidence_complete"])

    def test_github_contents_collector_decodes_source_without_persisting_secrets(self) -> None:
        content = "password = 'nonSensitiveFixtureValue12345'"
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "encoding": "base64",
            "content": base64.b64encode(content.encode()).decode(),
        }
        with patch.object(github_monitor.requests, "get", return_value=response) as get:
            loaded = github_monitor.get_file_content_at_commit(
                "example-org", "app", "src/a file.py", "abc"
            )
        self.assertEqual(loaded, content)
        self.assertIn("src/a%20file.py", get.call_args.args[0])
        self.assertEqual(get.call_args.kwargs["params"], {"ref": "abc"})


if __name__ == "__main__":
    unittest.main()
