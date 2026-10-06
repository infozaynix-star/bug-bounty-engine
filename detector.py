import math
import re
from pathlib import PurePosixPath


SECRET_PATTERNS = {
    "AWS Access Key ID": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "AWS Secret Access Key": r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "GitHub Personal Access Token": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    "GitLab Access Token": r"\bglpat-[A-Za-z0-9_-]{20,}\b",
    "OpenAI API Key": r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b",
    "Stripe Secret Key": r"\bsk_(?:live|test)_[0-9a-zA-Z]{20,}\b",
    "Slack Token": r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b",
    "Google API Key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "Google OAuth Token": r"\bya29\.[0-9A-Za-z_-]{30,}\b",
    "PyPI Token": r"\bpypi-[A-Za-z0-9_-]{50,}\b",
    "npm Token": r"\bnpm_[A-Za-z0-9]{30,}\b",
    "SendGrid API Key": r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}\b",
    "Webhook Signing Secret": r"\bwhsec_[A-Za-z0-9_-]{20,}\b",
    "Database URL Credential": (
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^:\s/@]+:"
        r"[^@\s/]{8,}@[^/\s]+"
    ),
    "Azure Storage Account Key": (
        r"(?i)\bAccountKey\s*=\s*[A-Za-z0-9+/=]{30,}"
    ),
    "Private Key": (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        r"[\s\S]{1,12000}?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "Generic Credential Assignment": (
        r"""(?i)\b(?:api[_-]?key|client[_-]?secret|password|secret|access[_-]?token)\b"""
        r"""\s*[:=]\s*(?:"(?P<double>[^"\s]{12,})"|'(?P<single>[^'\s]{12,})'|"""
        r"""(?P<unquoted>[A-Za-z0-9_./+=:-]{12,}))"""
    ),
}

SECRET_PROVIDERS = {
    "AWS Access Key ID": "AWS",
    "AWS Secret Access Key": "AWS",
    "GitHub Personal Access Token": "GitHub",
    "GitLab Access Token": "GitLab",
    "OpenAI API Key": "OpenAI",
    "Stripe Secret Key": "Stripe",
    "Slack Token": "Slack",
    "Google API Key": "Google",
    "Google OAuth Token": "Google",
    "PyPI Token": "PyPI",
    "npm Token": "npm",
    "SendGrid API Key": "SendGrid",
    "Webhook Signing Secret": "Webhook Provider",
    "Database URL Credential": "Database",
    "Azure Storage Account Key": "Azure",
    "Private Key": "Unknown",
    "JWT": "Unknown",
    "Generic Credential Assignment": "Unknown",
}

VULN_PATTERNS = {
    "Potential SQL Injection": (
        r"""(?is)(?:["'`]\s*(?:SELECT\b[^"'`]{0,200}\bFROM\b|INSERT\s+INTO\b|"""
        r"""UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b)[^"'`]{0,200}?"""
        r"""(?:\$\{[^}]+\}|\$[A-Za-z_]\w*)[^"'`]*["'`]|"""
        r"""["'`]\s*(?:SELECT\b[^"'`]{0,200}\bFROM\b|INSERT\s+INTO\b|"""
        r"""UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b)[^"'`]{0,200}["'`]"""
        r"""\s*(?:\+|\.|%)\s*\$?[A-Za-z_]\w*)"""
    ),
    "Unsafe Command Execution": (
        r"(?i)\b(?:exec|eval|system|passthru|shell_exec|popen|"
        r"subprocess\.(?:run|Popen)|os\.system)\b\s*\([^)]*"
        r"(?:\$_(?:GET|POST|REQUEST)\b|req(?:uest)?\.(?:args|form|values|"
        r"query|body|params)\b)"
    ),
    "Potential SSRF": (
        r"(?i)\b(?:requests\.(?:get|post|put|delete)|fetch|axios\.(?:get|post)|"
        r"http\.get)\s*\(\s*(?:req(?:uest)?\.(?:query|body|params)|"
        r"request\.(?:args|values)|params\.)"
    ),
    "Potential Path Traversal": (
        r"(?i)\b(?:open|readFile|readFileSync|writeFile|writeFileSync)\s*"
        r"\([^)]*(?:req(?:uest)?\.(?:query|body|params)|request\.(?:args|values)|"
        r"\.\./|%2e%2e)"
    ),
    "Potential Unsafe Deserialization": (
        r"(?i)\b(?:pickle\.loads?|yaml\.load|unserialize|ObjectInputStream)\s*\("
    ),
    "Potential Server-Side Template Injection": (
        r"(?i)\b(?:render_template_string|Template|from_string)\s*\([^)]*"
        r"(?:req(?:uest)?\.(?:query|body|params)|request\.(?:args|values))"
    ),
    "Potential IDOR": (
        r"(?i)\b(?:findById|findOne|lookup)\s*\(\s*(?:req(?:uest)?\.params|"
        r"request\.view_args)"
    ),
    "Potential Sensitive Information Exposure": (
        r"(?i)\b(?:res|response)\.(?:json|send)\s*\([^)]*"
        r"(?:password|secret|access.?token|private.?key)"
    ),
    "Potential Insecure Cryptography": r"(?i)\b(?:md5|sha1)\s*\(",
    "Potential Authentication Misconfiguration": (
        r"(?i)\b(?:jwt\.decode|verify)\s*\([^)]*"
        r"(?:verify\s*[:=]\s*False|ignoreExpiration\s*[:=]\s*True)"
    ),
    "Potential Dangerous File Upload": (
        r"(?i)\b(?:writeFile|createWriteStream|move|save)\s*\([^)]*"
        r"(?:req(?:uest)?\.files?|request\.files)"
    ),
    "Potential Hardcoded Privileged Configuration": (
        r"(?i)\b(?:isAdmin|is_admin|adminEnabled|debug)\s*[:=]\s*True\b"
    ),
    "Potential Unsafe GitHub Actions Trigger": (
        r"(?im)^\s*(?:pull_request_target|workflow_run)\s*:"
    ),
    "Potential Untrusted GitHub Actions Checkout": (
        r"(?is)uses:\s*actions/checkout@[^ \r\n]+\s*\n"
        r"(?:[ \t]+with:\s*\n)?"
        r"(?:[ \t]+ref:\s*\$\{\{\s*github\.event\.pull_request\."
        r"(?:head\.(?:ref|sha)|head)\s*\}\})"
    ),
    "Potential Overprivileged GitHub Actions Permissions": (
        r"(?im)^\s*permissions\s*:\s*(?:write-all|\n(?:[ \t]+[A-Za-z_]+\s*:\s*write\b)+)"
    ),
    "Potential Public Cloud Storage": (
        r"(?is)(?:public-read|allUsers|Principal\s*=\s*['\"]\*['\"]|"
        r"acl\s*=\s*['\"]public-read['\"])"
    ),
    "Potential Public Network Exposure": (
        r"(?is)(?:0\.0\.0\.0/0|::/0).{0,120}(?:ingress|cidr|source)"
    ),
    "Potential Weak Cryptography": r"(?i)\b(?:MD5|SHA-1|DES|RC4)\b",
    "Potential XSS": (
        r"(?i)\b(?:innerHTML|dangerouslySetInnerHTML|document\.write)\b"
    ),
    "Potential Open Redirect": (
        r"(?i)\b(?:redirect|sendRedirect)\s*\(\s*(?:req(?:uest)?\."
        r"(?:query|body|params)|request\.(?:args|values))"
    ),
    "Sensitive/Internal Endpoint": (
        r"(?i)['\"]/api/(?:v1|v2|internal|admin|debug|test)/[a-zA-Z0-9_/-]+['\"]"
    ),
    "Insecure Permissive CORS": (
        r"(?i)Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]"
    ),
    "Disabled SSL Verification": (
        r"(?i)(?:verify\s*=\s*False|curl_setopt\([^)]*"
        r"CURLOPT_SSL_VERIFYPEER\s*,\s*0\))"
    ),
}

FALSE_POSITIVE_INDICATORS = (
    "placeholder",
    "your_api_key",
    "changeme",
    "change_me",
    "example",
    "dummy",
    "fake",
)
EXCLUDED_EXTENSIONS = (
    ".md", ".mdx", ".rst", ".txt", ".svg", ".map", ".png", ".jpg", ".jpeg",
    ".gif", ".lock",
)
_TEST_PATH_PARTS = {
    "__tests__", "test", "tests", "testing", "fixtures", "fixture", "mocks",
    "mock", "samples", "sample", "examples", "example",
}
_COMPILED_SECRET_PATTERNS = {
    name: re.compile(pattern) for name, pattern in SECRET_PATTERNS.items()
}
_COMPILED_VULN_PATTERNS = {
    name: re.compile(pattern) for name, pattern in VULN_PATTERNS.items()
}
_KNOWN_FAKE_SECRETS = {
    "akiaiosfodnn7example",
    "ghp_000000000000000000000000000000000000",
}
_PATCH_HUNK = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _is_test_path(file_path: str) -> bool:
    path = PurePosixPath(file_path.replace("\\", "/"))
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    return (
        bool(parts & _TEST_PATH_PARTS)
        or name.startswith(("test_", "test."))
        or name.endswith((".test.js", ".spec.js", ".test.ts", ".spec.ts", "_test.py"))
    )


def _is_documentation_or_sample(file_path: str) -> bool:
    path = PurePosixPath(file_path.replace("\\", "/"))
    name = path.name.lower()
    return (
        path.suffix.lower() in EXCLUDED_EXTENSIONS
        or name.startswith("readme")
        or name.endswith((".example", ".sample", ".template", ".dist"))
        or name in {".env.example", ".env.sample", ".env.template"}
    )


def should_skip_file(file_path: str) -> bool:
    if not file_path:
        return False
    return PurePosixPath(file_path.replace("\\", "/")).suffix.lower() in EXCLUDED_EXTENSIONS


def is_false_positive(text: str) -> bool:
    lowered = text.lower()
    return any(indicator in lowered for indicator in FALSE_POSITIVE_INDICATORS)


def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    length = len(data)
    frequencies: dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def _added_patch_text(text: str) -> tuple[str, list[int]]:
    lines = text.splitlines()
    if not any(line.startswith("@@ ") for line in lines):
        source_lines = text.splitlines()
        return text, list(range(1, len(source_lines) + 1))

    new_line_number = 0
    added_lines: list[str] = []
    line_numbers: list[int] = []
    in_hunk = False
    for line in lines:
        header = _PATCH_HUNK.match(line)
        if header:
            new_line_number = int(header.group(1))
            in_hunk = True
        elif not in_hunk or line.startswith("\\"):
            continue
        elif line.startswith("+++"):
            continue
        elif line.startswith("+"):
            added_lines.append(line[1:])
            line_numbers.append(new_line_number)
            new_line_number += 1
        elif line.startswith(" "):
            new_line_number += 1
    return "\n".join(added_lines), line_numbers


def _line_number_at(text: str, offset: int, line_numbers: list[int]) -> int:
    added_line_index = text.count("\n", 0, offset)
    if added_line_index < len(line_numbers):
        return line_numbers[added_line_index]
    return line_numbers[-1] if line_numbers else 0


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    return (
        is_false_positive(lowered)
        or lowered.strip() in _KNOWN_FAKE_SECRETS
        or bool(re.fullmatch(r"(.)\1{11,}", compact))
        or bool(re.fullmatch(r"(?:0{12,}|1{12,}|1234567890+)", compact))
    )


def _redact_secrets_in_text(context: str) -> str:
    for name, pattern in _COMPILED_SECRET_PATTERNS.items():
        if name == "Generic Credential Assignment":
            context = pattern.sub(_redact_generic_match, context)
        else:
            context = pattern.sub("[REDACTED_SECRET]", context)
    context = re.sub(
        r"[A-Za-z0-9+/=_\-]{24,}",
        lambda match: (
            "[REDACTED_SECRET]"
            if calculate_shannon_entropy(match.group(0)) >= 3.0
            else match.group(0)
        ),
        context,
    )
    return context


def _secret_match_span(name: str, match: re.Match[str]) -> tuple[int, int]:
    if name != "Generic Credential Assignment":
        return match.span()
    for group in ("double", "single", "unquoted"):
        if match.group(group) is not None:
            return match.span(group)
    return match.span()


def _redact_generic_match(match: re.Match[str]) -> str:
    start, end = _secret_match_span("Generic Credential Assignment", match)
    relative_start = start - match.start()
    relative_end = end - match.start()
    return (
        match.group(0)[:relative_start]
        + "[REDACTED_SECRET]"
        + match.group(0)[relative_end:]
    )


def redact_sensitive_text(text: str) -> str:
    return _redact_secrets_in_text(text)


def context_from_source(text: str, line_number: int, radius: int = 3) -> str:
    lines = text.splitlines()
    if line_number < 1 or line_number > len(lines):
        return ""
    start = max(0, line_number - 1 - radius)
    end = min(len(lines), line_number + radius)
    return _redact_secrets_in_text("\n".join(lines[start:end]))


def _redacted_context(text: str, start: int, end: int) -> str:
    left = text.rfind("\n", 0, start) + 1
    right = text.find("\n", end)
    if right < 0:
        right = len(text)
    context = text[left:right]
    context = _redact_secrets_in_text(context)
    return context.strip()


def _finding_context(text: str, start: int) -> str:
    lines = text.splitlines()
    line_index = text.count("\n", 0, start)
    begin = max(0, line_index - 3)
    finish = min(len(lines), line_index + 4)
    return _redact_secrets_in_text("\n".join(lines[begin:finish]).strip())


def _make_secret_finding(
    secret_type: str,
    text: str,
    start: int,
    end: int,
    file_path: str,
    line_number: int,
) -> dict:
    matched_value = text[start:end]
    is_test = _is_test_path(file_path)
    is_example = is_test or _is_documentation_or_sample(file_path)
    is_placeholder = _is_placeholder(matched_value)
    negative_evidence = []
    if is_test:
        negative_evidence.append("test_fixture_or_mock_path")
    elif is_example:
        negative_evidence.append("documentation_or_sample_path")
    if is_placeholder:
        negative_evidence.append("placeholder_or_known_fake_value")

    return {
        "type": secret_type,
        "category": "Secret Leak",
        "provider": SECRET_PROVIDERS.get(secret_type, "Unknown"),
        "secret_type": secret_type,
        "source_file": file_path,
        "line": line_number,
        "context": _redacted_context(text, start, end),
        "redacted_context": _redacted_context(text, start, end),
        "confidence": "LOW",
        "is_example": is_example,
        "is_test": is_test,
        "is_placeholder": is_placeholder,
        "evidence": [f"provider_pattern:{secret_type}"],
        "negative_evidence": negative_evidence,
        "status": "POTENTIAL",
        "secret_value": None,
        "detection_method": "Static secret candidate",
    }


def scan_text_for_secrets(text: str, file_path: str = "", commit: str = "") -> list[dict]:
    findings: list[dict] = []
    if not text or should_skip_file(file_path):
        return findings

    scan_text, line_numbers = _added_patch_text(text)
    if not scan_text:
        return findings

    protected_spans: list[tuple[int, int]] = []
    for name, pattern in _COMPILED_SECRET_PATTERNS.items():
        for match in pattern.finditer(scan_text):
            start, end = _secret_match_span(name, match)
            if name == "Generic Credential Assignment" and any(
                start < protected_end and end > protected_start
                for protected_start, protected_end in protected_spans
            ):
                continue
            protected_spans.append((start, end))
            findings.append(_make_secret_finding(name, scan_text, start, end, file_path, _line_number_at(scan_text, start, line_numbers)))

    for match in re.finditer(r"[A-Za-z0-9+/=_\-]{32,}", scan_text):
        if any(match.start() < end and match.end() > start for start, end in protected_spans):
            continue
        value = match.group(0)
        if _is_placeholder(value) or calculate_shannon_entropy(value) < 4.5:
            continue
        findings.append(
            _make_secret_finding(
                "Generic High-Entropy Secret",
                scan_text,
                match.start(),
                match.end(),
                file_path,
                _line_number_at(scan_text, match.start(), line_numbers),
            )
        )

    for name, pattern in _COMPILED_VULN_PATTERNS.items():
        for match in pattern.finditer(scan_text):
            if name == "Unsafe Command Execution":
                line_start = scan_text.rfind("\n", 0, match.start()) + 1
                line_end = scan_text.find("\n", match.end())
                if line_end < 0:
                    line_end = len(scan_text)
                matched_line = scan_text[line_start:line_end]
                if re.search(
                    r"(?i)(?:shlex\.quote|shell\s*=\s*False|"
                    r"create_subprocess_exec\s*\()",
                    matched_line,
                ):
                    continue
            line_number = _line_number_at(scan_text, match.start(), line_numbers)
            line_start = scan_text.rfind("\n", 0, match.start()) + 1
            findings.append(
                {
                    "type": name,
                    "category": "Code Vulnerability",
                    "provider": None,
                    "secret_type": None,
                    "source_file": file_path,
                    "line": line_number,
                    "context": _finding_context(scan_text, line_start),
                    "redacted_context": _finding_context(scan_text, line_start),
                    "confidence": "LOW",
                    "is_example": _is_documentation_or_sample(file_path),
                    "is_test": _is_test_path(file_path),
                    "is_placeholder": False,
                    "evidence": [f"static_candidate_pattern:{name}"],
                    "negative_evidence": [],
                    "status": "POTENTIAL",
                    "detection_method": "Static candidate pattern",
                }
            )

    for finding in findings:
        finding["commit"] = commit
        if finding["is_test"]:
            finding["status"] = "FALSE_POSITIVE"
            finding["negative_evidence"].append("test_fixture_or_mock_path")
        elif finding["is_example"]:
            finding["status"] = "FALSE_POSITIVE"
            finding["negative_evidence"].append("documentation_or_sample_path")
        if finding["is_placeholder"]:
            finding["status"] = "FALSE_POSITIVE"
    return findings


scan_file_content = scan_text_for_secrets
