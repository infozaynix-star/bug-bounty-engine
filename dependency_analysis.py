import json
import re


def _normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _dependency_entries(text: str, file_path: str) -> list[tuple[str, str, int, str]]:
    if file_path.endswith("package-lock.json"):
        payload = json.loads(text)
        entries = []
        packages = payload.get("packages", {})
        if isinstance(packages, dict):
            for package_path, data in packages.items():
                if not package_path.startswith("node_modules/") or not isinstance(data, dict):
                    continue
                name = data.get("name") or package_path.rsplit("node_modules/", 1)[-1]
                version = data.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    entries.append((name, version, 0, "npm"))
            return entries

        def collect_v1(dependencies: dict) -> None:
            for name, data in dependencies.items():
                if not isinstance(data, dict):
                    continue
                version = data.get("version")
                if isinstance(version, str):
                    entries.append((name, version, 0, "npm"))
                nested = data.get("dependencies", {})
                if isinstance(nested, dict):
                    collect_v1(nested)

        dependencies = payload.get("dependencies", {})
        if isinstance(dependencies, dict):
            collect_v1(dependencies)
        return entries

    if file_path.endswith(("requirements.txt", "requirements.lock")):
        entries = []
        for line_number, line in enumerate(text.splitlines(), 1):
            match = re.match(
                r"^\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9.+!-]+)\s*(?:#.*)?$",
                line,
            )
            if match:
                entries.append((match.group(1), match.group(2), line_number, "PyPI"))
        return entries
    return []


def analyze_dependency_manifest(
    text: str,
    file_path: str,
    advisory_catalog: dict,
    commit: str = "",
) -> list[dict]:
    """Match resolved lockfile versions against a caller-supplied offline advisory catalog."""
    advisories = advisory_catalog.get("advisories", [])
    if not isinstance(advisories, list):
        return []
    candidates = []
    for package, version, line_number, ecosystem in _dependency_entries(text, file_path):
        normalized_name = _normalize_package_name(package)
        for advisory in advisories:
            if not isinstance(advisory, dict):
                continue
            if str(advisory.get("ecosystem", "")).lower() != ecosystem.lower():
                continue
            if _normalize_package_name(str(advisory.get("package", ""))) != normalized_name:
                continue
            affected_versions = advisory.get("affected_versions", [])
            if not isinstance(affected_versions, list) or version not in affected_versions:
                continue
            advisory_id = str(advisory.get("id", "")).strip()
            if not advisory_id:
                continue
            candidates.append(
                {
                    "type": "Vulnerable Dependency Candidate",
                    "category": "Dependency Vulnerability",
                    "source_file": file_path,
                    "line": line_number,
                    "package": package,
                    "version": version,
                    "advisory_id": advisory_id,
                    "severity": str(advisory.get("severity", "UNKNOWN")).upper(),
                    "redacted_context": f"{package}=={version}",
                    "evidence": [f"offline_advisory:{advisory_id}"],
                    "negative_evidence": ["advisory_match_requires_reachability_and_scope_review"],
                    "status": "POTENTIAL",
                    "is_example": False,
                    "is_test": False,
                    "is_placeholder": False,
                    "commit": commit,
                    "detection_method": "Offline dependency advisory match",
                }
            )
    return candidates
