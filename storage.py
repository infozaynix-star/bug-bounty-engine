import sqlite3
import json
import os
import tempfile
from pathlib import Path

from detector import redact_sensitive_text

DB_NAME = "bug_bounty_mvp.db"
STATE_FILE = Path(__file__).with_name("state.json")


def _redact_report_value(value):
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [_redact_report_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_report_value(item) for key, item in value.items()}
    return value


def get_db_connection():
    """إنشاء الاتصال بقاعدة البيانات SQLite"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """إنشاء الجداول إذا لم تكن موجودة"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # جدول الـ Commits المفحوصة لمنع التكرار
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processed_commits (
            commit_sha TEXT PRIMARY KEY,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS processed_repository_commits (
            repository TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (repository, commit_sha)
        )
        """
    )
    
    # جدول حفظ نتائج الثغرات والتسريبات المقبولة
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company TEXT,
            repo TEXT,
            commit_sha TEXT,
            type TEXT,
            context TEXT,
            confidence TEXT,
            ai_reason TEXT,
            commit_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    existing_columns = {
        row["name"] for row in cursor.execute("PRAGMA table_info(findings)").fetchall()
    }
    for column, definition in (
        ("fingerprint", "TEXT"),
        ("report_json", "TEXT"),
        ("status", "TEXT"),
        ("confidence_level", "TEXT"),
        ("first_commit", "TEXT"),
        ("last_commit", "TEXT"),
    ):
        if column not in existing_columns:
            cursor.execute(f"ALTER TABLE findings ADD COLUMN {column} {definition}")

    cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint "
        "ON findings(fingerprint) WHERE fingerprint IS NOT NULL"
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(fingerprint, commit_sha)
        )
        """
    )
    for row in cursor.execute(
        "SELECT id, context, ai_reason FROM findings"
    ).fetchall():
        safe_context = redact_sensitive_text(row["context"] or "")
        safe_reason = redact_sensitive_text(row["ai_reason"] or "")
        if safe_context != row["context"] or safe_reason != row["ai_reason"]:
            cursor.execute(
                "UPDATE findings SET context = ?, ai_reason = ? WHERE id = ?",
                (safe_context, safe_reason, row["id"]),
            )
    cursor.execute(
        """
        UPDATE findings
        SET status = 'LEGACY_UNVALIDATED', confidence_level = 'LOW'
        WHERE fingerprint IS NULL AND status IS NULL
        """
    )
    conn.commit()
    conn.close()

# تهيئة قاعدة البيانات فور استيراد الملف
init_db()


def _read_scanner_state() -> dict:
    try:
        with STATE_FILE.open(encoding="utf-8") as state_file:
            state = json.load(state_file)
    except FileNotFoundError:
        return {
            "processed_repository_commits": {},
            "finding_fingerprints": [],
        }
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Could not read scanner state file: {STATE_FILE}") from error

    if not isinstance(state, dict):
        raise RuntimeError(f"Invalid scanner state file format: {STATE_FILE}")

    processed = state.get("processed_repository_commits", {})
    fingerprints = state.get("finding_fingerprints", [])
    if any(
        not isinstance(repository, str)
        or not isinstance(commits, list)
        or any(not isinstance(commit, str) for commit in commits)
        for repository, commits in processed.items()
    ):
        raise RuntimeError(f"Invalid processed commit entries in {STATE_FILE}")
    if not isinstance(fingerprints, list) or any(
        not isinstance(fingerprint, str) for fingerprint in fingerprints
    ):
        raise RuntimeError(f"Invalid finding fingerprints in {STATE_FILE}")
    return {
        "processed_repository_commits": processed,
        "finding_fingerprints": fingerprints,
    }


def _write_scanner_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=STATE_FILE.parent,
            prefix=f".{STATE_FILE.name}.",
            suffix=".tmp",
            delete=False,
        ) as state_file:
            temporary_path = Path(state_file.name)
            json.dump(
                state,
                state_file,
                indent=2,
                sort_keys=True,
            )
            state_file.write("\n")
        os.replace(temporary_path, STATE_FILE)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


def is_commit_processed(commit_sha: str, repository: str | None = None) -> bool:
    """التحقق مما إذا كان الـ Commit مفحوصاً سابقاً"""
    if repository:
        state = _read_scanner_state()
        processed = state["processed_repository_commits"]
        return commit_sha in processed.get(repository, [])

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM processed_commits WHERE commit_sha = ?",
            (commit_sha,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()

def mark_commit_processed(commit_sha: str, repository: str | None = None):
    """تعليم الـ Commit كمفحوص"""
    if repository:
        state = _read_scanner_state()
        processed = state["processed_repository_commits"]
        commits = processed.setdefault(repository, [])
        if commit_sha not in commits:
            commits.append(commit_sha)
            _write_scanner_state(state)
        return

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO processed_commits (commit_sha) VALUES (?)",
            (commit_sha,),
        )
        conn.commit()
    finally:
        conn.close()

def save_finding(finding_data: dict):
    """حفظ نتيجة التسريب أو الثغرة المقبولة في قاعدة البيانات"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO findings (company, repo, commit_sha, type, context, confidence, ai_reason, commit_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding_data.get("company"),
            finding_data.get("repo"),
            finding_data.get("commit_sha"),
            finding_data.get("type"),
            redact_sensitive_text(str(finding_data.get("context") or "")),
            finding_data.get("confidence"),
            redact_sensitive_text(str(finding_data.get("ai_reason") or "")),
            finding_data.get("commit_url")
        ))
        conn.commit()
    except Exception as e:
        print(f"❌ خطأ أثناء حفظ التقرير في DB: {e}")
    finally:
        conn.close()


def is_finding_duplicate(fingerprint: str) -> bool:
    state = _read_scanner_state()
    if fingerprint in state["finding_fingerprints"]:
        return True

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def record_finding(report: dict) -> bool:
    """Persist a report and its commit observation; return True if it already existed."""
    report = _redact_report_value(report)
    fingerprint = report["fingerprint"]
    commit_sha = report.get("commit", "")
    state = _read_scanner_state()
    fingerprint_known = fingerprint in state["finding_fingerprints"]
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        existing = cursor.execute(
            "SELECT id FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if existing:
            cursor.execute(
                """
                INSERT OR IGNORE INTO finding_observations (fingerprint, commit_sha)
                VALUES (?, ?)
                """,
                (fingerprint, commit_sha),
            )
            cursor.execute(
                "UPDATE findings SET last_commit = ? WHERE fingerprint = ?",
                (commit_sha, fingerprint),
            )
            conn.commit()
            if not fingerprint_known:
                state["finding_fingerprints"].append(fingerprint)
                _write_scanner_state(state)
            return True

        if fingerprint_known:
            return True

        cursor.execute(
            """
            INSERT INTO findings (
                company, repo, commit_sha, type, context, confidence, ai_reason,
                commit_url, fingerprint, report_json, status, confidence_level,
                first_commit, last_commit
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.get("company"),
                report.get("repository"),
                commit_sha,
                report.get("type"),
                report.get("redacted_context"),
                report.get("confidence"),
                report.get("ai_reasoning"),
                report.get("commit_url"),
                fingerprint,
                json.dumps(report, ensure_ascii=False),
                report.get("status"),
                report.get("confidence_level"),
                commit_sha,
                commit_sha,
            ),
        )
        cursor.execute(
            "INSERT OR IGNORE INTO finding_observations (fingerprint, commit_sha) VALUES (?, ?)",
            (fingerprint, commit_sha),
        )
        conn.commit()
        state["finding_fingerprints"].append(fingerprint)
        _write_scanner_state(state)
        return False
    finally:
        conn.close()