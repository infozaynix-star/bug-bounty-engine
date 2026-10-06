import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
POLICY_PATH = Path(__file__).with_name("scope_policy.json")


def _program_and_asset(company: str, repository: str, policy: dict) -> tuple[dict, dict]:
    programs = policy.get("programs", {})
    program = programs.get(company, {}) if isinstance(programs, dict) else {}
    if not isinstance(program, dict):
        return {}, {}
    repositories = program.get("repositories", {})
    asset = repositories.get(repository, {}) if isinstance(repositories, dict) else {}
    return program, asset if isinstance(asset, dict) else {}


def _organization_wildcard_record(program: dict) -> dict:
    repositories = program.get("in_scope_repos", [])
    if not isinstance(repositories, list) or "*" not in repositories:
        return {}
    return program


def _organization_wildcard_is_verified(program: dict, organization: str) -> bool:
    record = _organization_wildcard_record(program)
    policy_url = record.get("policy_url", "")
    allowed_types = record.get("allowed_types", [])
    return (
        bool(record)
        and record.get("in_scope") is True
        and record.get("all_public_repositories_confirmed") is True
        and record.get("bounty_eligible") is True
        and record.get("source_code_eligible") is True
        and record.get("requirements_confirmed") is True
        and isinstance(record.get("organization"), str)
        and record["organization"].casefold() == organization.casefold()
        and isinstance(policy_url, str)
        and policy_url.startswith("https://")
        and isinstance(allowed_types, list)
        and any(isinstance(item, str) and item.strip() for item in allowed_types)
    )


def repository_is_authorized(company: str, repository: str, policy: dict) -> bool:
    program, asset = _program_and_asset(company, repository, policy)
    organization = program.get("organization", "")
    repository_owner = repository.split("/", 1)[0] if "/" in repository else ""
    if not asset and _organization_wildcard_is_verified(program, repository_owner):
        excluded_repositories = program.get("excluded_repositories", [])
        if not isinstance(excluded_repositories, list):
            return False
        return (
            repository_owner.casefold() == organization.casefold()
            and repository.casefold()
            not in {
                item.casefold()
                for item in excluded_repositories
                if isinstance(item, str)
            }
        )

    allowed_types = asset.get("allowed_types", [])
    policy_url = asset.get("policy_url", "")
    return (
        asset.get("in_scope") is True
        and asset.get("bounty_eligible") is True
        and asset.get("source_code_eligible") is True
        and asset.get("requirements_confirmed") is True
        and isinstance(organization, str)
        and bool(organization)
        and repository_owner.casefold() == organization.casefold()
        and isinstance(policy_url, str)
        and policy_url.startswith("https://")
        and isinstance(allowed_types, list)
        and any(isinstance(item, str) and item for item in allowed_types)
    )


def source_path_is_authorized(
    company: str, repository: str, source_file: str, policy: dict
) -> bool:
    _, asset = repositories_for_scope(
        company, repository.split("/", 1)[0], repository, policy
    )
    if not repository_is_authorized(company, repository, policy):
        return False
    excluded_paths = asset.get("excluded_paths", [])
    if not isinstance(excluded_paths, list):
        return True
    normalized_source = source_file.replace("\\", "/").strip("/")
    return not any(
        isinstance(path, str)
        and path
        and (
            normalized_source == path.replace("\\", "/").strip("/")
            or normalized_source.startswith(path.replace("\\", "/").strip("/") + "/")
        )
        for path in excluded_paths
    )


def program_has_authorized_repository(
    company: str, organization: str, policy: dict
) -> bool:
    programs = policy.get("programs", {})
    program = programs.get(company, {}) if isinstance(programs, dict) else {}
    if not isinstance(program, dict):
        return False
    if str(program.get("organization", "")).casefold() != organization.casefold():
        return False
    if _organization_wildcard_is_verified(program, organization):
        return True
    repositories = program.get("repositories", {})
    if not isinstance(repositories, dict):
        return False
    return any(
        repository_is_authorized(company, repository, policy)
        for repository in repositories
        if isinstance(repository, str)
    )


def authorized_repositories(company: str, policy: dict) -> list[str]:
    programs = policy.get("programs", {})
    program = programs.get(company, {}) if isinstance(programs, dict) else {}
    if not isinstance(program, dict):
        return []
    repositories = program.get("repositories", {})
    if not isinstance(repositories, dict):
        return []
    return sorted(
        repository
        for repository in repositories
        if isinstance(repository, str)
        and repository_is_authorized(company, repository, policy)
    )


def organization_wildcard_is_authorized(
    company: str, organization: str, policy: dict
) -> bool:
    programs = policy.get("programs", {})
    program = programs.get(company, {}) if isinstance(programs, dict) else {}
    return (
        isinstance(program, dict)
        and _organization_wildcard_is_verified(program, organization)
    )


def repositories_for_scope(
    company: str, organization: str, repository: str, policy: dict
) -> tuple[dict, dict]:
    program, asset = _program_and_asset(company, repository, policy)
    if asset:
        return program, asset
    if _organization_wildcard_is_verified(program, organization):
        return program, program
    return program, {}


def scanner_options(company: str, repository: str, policy: dict) -> dict:
    if not repository_is_authorized(company, repository, policy):
        return {}
    _, asset = repositories_for_scope(
        company, repository.split("/", 1)[0], repository, policy
    )
    options = asset.get("static_analysis", {})
    if not isinstance(options, dict):
        return {}
    path_options = {
        key: value
        for key, value in options.items()
        if key in {
            "checkout_path",
            "semgrep_config",
            "codeql_database",
            "codeql_query_suite",
            "dependency_advisory_catalog",
        }
        and isinstance(value, str)
        and value.strip()
    }
    return {
        key: str(
            candidate.expanduser()
            if candidate.is_absolute()
            else (POLICY_PATH.parent / candidate).resolve()
        )
        for key, value in path_options.items()
        for candidate in [Path(value)]
    }


def load_scope_policy(path: Path = POLICY_PATH) -> dict:
    try:
        with path.open(encoding="utf-8") as policy_file:
            policy = json.load(policy_file)
    except FileNotFoundError:
        logger.warning("Scope policy file is missing; all assets will be treated as out of scope")
        return {"programs": {}}
    except (OSError, json.JSONDecodeError):
        logger.exception("Could not load scope policy; all assets will be treated as out of scope")
        return {"programs": {}}

    if not isinstance(policy, dict) or not isinstance(policy.get("programs"), dict):
        logger.error("Invalid scope policy format; all assets will be treated as out of scope")
        return {"programs": {}}
    return policy


def evaluate_scope(
    company: str,
    repository: str,
    finding_type: str,
    source_file: str,
    policy: dict,
) -> dict:
    repository_owner = repository.split("/", 1)[0] if "/" in repository else ""
    program, asset = repositories_for_scope(company, repository_owner, repository, policy)
    allowed_types = asset.get("allowed_types", [])
    excluded_types = asset.get("excluded_types", [])
    excluded_paths = asset.get("excluded_paths", [])
    allowed_types = (
        [value for value in allowed_types if isinstance(value, str)]
        if isinstance(allowed_types, list)
        else []
    )
    excluded_types = (
        [value for value in excluded_types if isinstance(value, str)]
        if isinstance(excluded_types, list)
        else []
    )
    excluded_paths = (
        [value for value in excluded_paths if isinstance(value, str) and value]
        if isinstance(excluded_paths, list)
        else []
    )
    in_scope = asset.get("in_scope") is True
    bounty_eligible = asset.get("bounty_eligible") is True
    source_code_eligible = asset.get("source_code_eligible") is True
    requirements_confirmed = asset.get("requirements_confirmed") is True
    organization = program.get("organization", "")
    owner_verified = (
        isinstance(organization, str)
        and bool(organization)
        and repository_owner.casefold() == organization.casefold()
    )
    policy_url = asset.get("policy_url", "")
    policy_reference_present = (
        isinstance(policy_url, str) and policy_url.startswith("https://")
    )
    type_allowed = finding_type in allowed_types
    type_not_excluded = finding_type not in excluded_types
    normalized_source = source_file.replace("\\", "/").strip("/")
    path_excluded = any(
        normalized_source == path.replace("\\", "/").strip("/")
        or normalized_source.startswith(path.replace("\\", "/").strip("/") + "/")
        for path in excluded_paths
    )

    allowed = (
        repository_is_authorized(company, repository, policy)
        and type_allowed
        and type_not_excluded
        and not path_excluded
    )
    reasons = []
    if not in_scope:
        reasons.append("asset_not_explicitly_in_scope")
    if not bounty_eligible:
        reasons.append("asset_not_confirmed_bounty_eligible")
    if not source_code_eligible:
        reasons.append("source_code_eligibility_not_confirmed")
    if not requirements_confirmed:
        reasons.append("program_requirements_not_confirmed")
    if not owner_verified:
        reasons.append("repository_owner_does_not_match_program")
    if not policy_reference_present:
        reasons.append("current_program_policy_reference_missing")
    if not type_allowed:
        reasons.append("finding_type_not_in_allowed_types")
    if not type_not_excluded:
        reasons.append("finding_type_excluded_by_policy")
    if path_excluded:
        reasons.append("source_path_excluded_by_policy")

    return {
        "in_scope": allowed,
        "bounty_eligible": allowed,
        "scope_status": "IN_SCOPE" if allowed else "OUT_OF_SCOPE",
        "scope_evidence": {
            "program": company,
            "repository": repository,
            "source_code_eligible": source_code_eligible,
            "owner_verified": owner_verified,
            "requirements_confirmed": requirements_confirmed,
            "policy_url": policy_url if policy_reference_present else None,
            "reasons": reasons,
        },
    }
