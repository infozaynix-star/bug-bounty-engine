# Scope and alert policy

The engine fails closed: an empty or invalid `scope_policy.json` permits no
Telegram alerts. Do not add an organization or repository unless its current
bug-bounty policy explicitly authorizes public source-code review for that
asset and finding type.

Add a repository only after checking the program's current scope, exclusions,
source-code eligibility, and bounty eligibility. Use the exact repository
name returned by GitHub:

```json
{
  "programs": {
    "Shopify": {
      "organization": "Shopify",
      "repositories": {
        "Shopify/example-repository": {
          "in_scope": true,
          "bounty_eligible": true,
          "source_code_eligible": true,
          "requirements_confirmed": true,
          "policy_url": "https://example.invalid/replace-with-official-policy",
          "allowed_types": ["Potential SQL Injection"],
          "excluded_types": [],
          "excluded_paths": ["vendor/", "generated/"]
        }
      }
    }
  }
}
```

The repository and URL above are placeholders; replace them with the verified
asset and the official current program policy before enabling monitoring.

For a program whose official terms explicitly cover **every public repository**
owned by the organization, an organization-wide wildcard may be configured:

```json
{
  "programs": {
    "Verified Program": {
      "organization": "verified-org",
      "in_scope_repos": ["*"],
      "in_scope": true,
      "all_public_repositories_confirmed": true,
      "bounty_eligible": true,
      "source_code_eligible": true,
      "requirements_confirmed": true,
      "policy_url": "https://example.invalid/replace-with-verified-policy",
      "allowed_types": ["Potential SQL Injection"],
      "excluded_repositories": ["verified-org/excluded-repository"],
      "excluded_paths": ["vendor/", "generated/"]
    }
  }
}
```

The requested organization entries are pre-populated in `scope_policy.json`
with wildcard templates, but all authorization and verification fields are
false and their policy URLs/types are blank. They therefore remain disabled.
The wildcard remains disabled unless every confirmation field above is set,
the policy URL is HTTPS, and at least one finding type is listed. This must be
verified against the program's current official policy; an organization's
presence in `config.py` or a `TARGET_REPOS` value does not grant authorization.
Wildcard discovery retrieves public repositories sorted by recent activity,
follows all GitHub API pages, verifies each result is public and owned by the
configured organization, and applies repository/path exclusions before
analysis.

An omitted asset, missing eligibility flag, mismatched repository owner,
unconfirmed program requirements, missing policy URL, or finding type not
listed in `allowed_types` is out of scope. Program policies change; review this
file against the program's current rules before enabling an asset.

Paths in `static_analysis` options are resolved relative to the project
directory when they are not absolute paths.

Commits already marked as processed are not automatically rescanned after
changing policy. Repository-specific commit hashes are stored in `state.json`
so scheduled GitHub Actions runs can carry scan state forward. That file
contains only public repository names, commit hashes, and one-way finding
fingerprints, not finding reports or credentials. Keeping fingerprints also
prevents repeat alerts when the per-run SQLite database is recreated. To
re-evaluate a commit, remove its SHA from that repository's list in
`state.json`; to re-evaluate a previously reported finding, remove its
fingerprint there as well. Legacy local SQLite rows in `processed_commits` do
not identify a repository and may be scanned again once after upgrading.

The `.github/workflows/scanner.yml` workflow runs `main.py --once` every five
minutes and can also be started manually. Add `GROQ_API_KEY`,
`TELEGRAM_BOT_TOKEN`, and `TELEGRAM_CHAT_ID` as repository Actions secrets.
The workflow uses the `MY_GITHUB_TOKEN` repository secret when configured,
falling back to the automatically provided `GITHUB_TOKEN`, and requires
Actions workflow permissions to allow contents writes so it can commit updated
scan state. It passes `GROQ_MODEL` through from its optional repository secret;
the application default is used if it is unset. Its state commits include
`[skip ci]`; the workflow is not configured to run on push events.

`TARGET_REPOS` is an optional comma-separated environment variable (or Actions
repository variable) that filters the authorized repositories for a run. It
does not grant scope: every listed repository must still be explicitly
authorized in `scope_policy.json`. Without this filter, all repositories
explicitly authorized by that policy are considered.

For each authorized repository the scanner checks the five latest commits per
run. Keep the organization list and commit-detail calls in mind when enabling
large organizations: GitHub API rate limits and the Actions job timeout can
limit how many repositories finish in one cycle. API errors are reported and
cause the one-shot run to fail rather than appearing as a successful empty
scan.

The built-in regular expressions produce candidates only. High-confidence
alerts additionally require explicit scope, evidence of a source-to-sink path,
impact, and at least two independent static-analysis evidence sources. No
CodeQL or Semgrep executable is bundled with this project, so a pattern-only
finding cannot satisfy that gate. The LLM may reject a candidate or explain
missing evidence; it cannot raise its score or override the gates.

Static scanner results are accepted only as structured `static_analysis`
entries attached to a candidate, each containing `tool` (`semgrep`, `codeql`,
or `custom_ast`), `rule_id`, exact `file`, exact `line`, and the analyzed
commit. Distinct tools must independently report that same location. Semgrep
and CodeQL are optional local integrations configured per repository; the
engine does not install either tool or download an untrusted checkout to run
them. Configured scans require a local checkout at the exact commit. CodeQL
also requires a `.bbengine-commit` provenance file in its local database.

For a candidate file only, the collector can fetch source at the observed
commit to provide bounded, redacted context. This improves review context but
does not prove dataflow. An optional local advisory catalog can match exact
versions in supported npm and pinned-PyPI manifests; these matches are also
candidates and need reachability, impact, scope, and independent evidence.
No online advisory feed or version-range solver is included.

Secrets are masked before persistence, AI requests, and Telegram messages.
Never use a discovered credential, attempt live exploitation, or test a
third-party system. Findings that need runtime validation remain for manual
review under the relevant program's rules.
