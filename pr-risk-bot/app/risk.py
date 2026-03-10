from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Pre-compiled regex constants  (compiled once at import, not per-call)
# ---------------------------------------------------------------------------

_RISKY_PATH_RE = re.compile(
    r"(?i)\b(auth|security|payment|billing|crypto|permission|admin)\b"
)
_TEST_PATH_RE = re.compile(
    # Matches common test file/dir conventions while avoiding false positives
    # like "contest.py", "latest.py", "attestation/"
    r"(?i)(^|/)(tests?|specs?|__tests__|testing)[/.]"
    r"|(?i)_(test|spec)\.(py|js|ts|rb|java|go|kt|cs)$"
    r"|(?i)\.(test|spec)\.(js|ts|jsx|tsx)$"
)
_RESILIENCE_RE = re.compile(
    r"(?i)\b(timeout|retry|backoff|circuit.?breaker|rate.?limit)\b"
)
_SECURITY_WEAKEN_RE = re.compile(
    r"(?i)\b(permitAll|csrf\(\)\.disable|allowedOrigins\s*\(\s*['\"]?\*|@CrossOrigin\s*\(\s*['\"]?\*)\b"
)
_RISKY_SQL_RE = re.compile(
    r"(?i)\b(drop\s+table|truncate\s+table|delete\s+from|alter\s+table)\b"
)
_EXT_RE = re.compile(r"(\.[A-Za-z0-9]+)$")

# ---------------------------------------------------------------------------
# Constant sets
# ---------------------------------------------------------------------------

CODE_EXTS = frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".cs", ".go", ".rb", ".php"})
CONFIG_EXTS = frozenset({".yml", ".yaml", ".json", ".toml", ".properties", ".ini", ".env"})
MIGRATION_HINTS = frozenset({"migrations", "flyway", "liquibase", "alembic", "schema.sql"})
API_CONTRACT_HINTS = frozenset({"openapi", "swagger", ".proto", "graphql", "schema.graphql"})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RiskResult:
    score_100: int
    score_10: int
    level: str           # "LOW" | "MEDIUM" | "HIGH"
    confidence: str      # "High" | "Medium" | "Low"
    signals: List[str]
    impact_map: List[str]
    risk_drivers: List[str]
    review_focus: List[str]
    operational_notes: List[str]
    file_summary: str

    # Raw counts — useful for formatting / debugging
    changed_files: int
    additions: int
    deletions: int
    config_files: int
    sql_files: int
    test_touched: int
    risky_paths: int

    @property
    def score(self) -> int:
        """Alias for score_10, kept for backwards compatibility."""
        return self.score_10


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ext(path: str) -> str:
    m = _EXT_RE.search(path)
    return m.group(1).lower() if m else ""


def _top_level_dir(path: str) -> str:
    parts = path.strip("/").split("/")
    return parts[0] if len(parts) >= 2 else "(root)"


def _compute_confidence(
    changed_files: int,
    loc: int,
    test_touched: int,
    patch_missing: int,
) -> str:
    if loc > 4000 or changed_files > 120 or patch_missing >= 30:
        return "Low"
    if loc > 1500 or changed_files > 60 or patch_missing >= 10:
        return "Medium"
    if test_touched == 0 and loc > 300:
        return "Medium"
    return "High"


_DRIVER_WEIGHTS: List[tuple[str, int]] = [
    ("security",    100),
    ("auth",        100),
    ("sql",          90),
    ("migration",    90),
    ("schema",       90),
    ("config",       70),
    ("test",         65),
    ("large diff",   50),
    ("big edit",     50),
    ("many files",   40),
    ("removed",      25),
]


def _pick_risk_drivers(signals: List[str], max_items: int = 6) -> List[str]:
    if not signals:
        return []

    def weight(s: str) -> int:
        low = s.lower()
        return max((w for kw, w in _DRIVER_WEIGHTS if kw in low), default=0)

    seen: set[str] = set()
    drivers: List[str] = []
    for s in sorted(signals, key=weight, reverse=True):
        if s not in seen:
            drivers.append(s)
            seen.add(s)
        if len(drivers) >= max_items:
            break
    return drivers


def _review_focus(
    config_files: int,
    sql_files: int,
    test_touched: int,
    risky_paths: int,
    level: str,
) -> List[str]:
    items: List[str] = []
    if risky_paths:
        items.append("Review auth/security/payment-related changes carefully (sensitive area touched).")
    if sql_files:
        items.append("Verify migrations are reversible; check locks/indexes and rollout/rollback plan.")
    if config_files:
        items.append("Validate config defaults and environment overrides (staging vs prod).")
    if test_touched == 0:
        items.append("Request tests or a justification (code changed without test modifications).")
    if level in {"MEDIUM", "HIGH"}:
        items.append("Ask for monitoring/rollback notes for deploy (what to watch, how to revert).")
    if level == "HIGH":
        items.append("Consider splitting PR or requiring explicit sign-off (risk concentrated).")
    return items[:5]


def _operational_notes(
    sql_files: int,
    config_files: int,
    touched_migrations: bool,
    touched_api_contract: bool,
    level: str,
) -> List[str]:
    """Only emit notes when there is something actionable to flag."""
    notes: List[str] = []
    if sql_files or touched_migrations:
        notes.append("DB migration detected — confirm rollback script exists and migration is idempotent.")
    if config_files:
        notes.append("Config changes detected — verify no secret values are hardcoded.")
    if touched_api_contract:
        notes.append("API contract changed — check for breaking changes and notify downstream consumers.")
    if level == "HIGH":
        notes.append("High-risk PR — recommend notifying on-call before merging to production.")
    return notes[:5]


# ---------------------------------------------------------------------------
# Main scorer
# ---------------------------------------------------------------------------

def compute_risk(files: List[Dict[str, Any]], pr: Dict[str, Any]) -> RiskResult:
    additions    = int(pr.get("additions", 0) or 0)
    deletions    = int(pr.get("deletions", 0) or 0)
    changed_files = int(pr.get("changed_files", len(files)) or len(files))
    loc = additions + deletions

    score = 0
    signals: List[str] = []

    # -- Diff size ----------------------------------------------------------------
    if loc > 800:
        score += 30
        signals.append(f"Large diff ({additions}+/{deletions}-).")
    elif loc > 300:
        score += 18
        signals.append(f"Medium diff size ({additions}+/{deletions}-).")

    # -- File count ---------------------------------------------------------------
    if changed_files > 40:
        score += 20
        signals.append(f"Touches many files ({changed_files}).")
    elif changed_files > 15:
        score += 10
        signals.append(f"Touches multiple files ({changed_files}).")

    # -- Renames ------------------------------------------------------------------
    renames = sum(1 for f in files if f.get("status") == "renamed")
    if renames >= 5:
        score += 10
        signals.append(f"Multiple renames ({renames}) — review for missing references.")

    # -- Per-file pass ------------------------------------------------------------
    risky_paths = 0
    config_files = 0
    sql_files = 0
    test_touched = 0
    core_code_touched = 0
    patch_missing = 0
    touched_migrations = False
    touched_api_contract = False

    # Capped counters — prevent single-category score inflation
    big_edits_scored    = 0   # cap: 3 signals, 18 pts
    resilience_scored   = 0   # cap: 2 signals,  8 pts
    security_scored     = 0   # cap: 2 signals, 16 pts
    risky_sql_scored    = 0   # cap: 3 signals, 30 pts
    removed_scored      = 0   # cap: 5 signals, 15 pts

    ext_counts: Counter[str] = Counter()
    top_dirs:   Counter[str] = Counter()

    for f in files:
        path   = f.get("filename", "") or ""
        status = f.get("status", "") or ""
        ext    = _ext(path)
        low    = path.lower()

        ext_counts[ext or "(none)"] += 1
        top_dirs[_top_level_dir(path)] += 1

        patch = f.get("patch")
        if not patch:
            patch_missing += 1

        f_adds = int(f.get("additions", 0) or 0)
        f_dels = int(f.get("deletions", 0) or 0)

        # Tests
        if _TEST_PATH_RE.search(path):
            test_touched += 1

        # Core code
        if ext in CODE_EXTS:
            core_code_touched += 1

        # Config
        if ext in CONFIG_EXTS or "config" in low:
            config_files += 1

        # SQL
        if ext == ".sql":
            sql_files += 1

        # Migration / API contract (impact map signals only)
        if any(h in low for h in MIGRATION_HINTS):
            touched_migrations = True
        if any(h in low for h in API_CONTRACT_HINTS):
            touched_api_contract = True

        # Risky path
        if _RISKY_PATH_RE.search(path):
            risky_paths += 1

        # Removed files (capped)
        if status == "removed" and removed_scored < 5:
            score += 3
            signals.append(f"File removed: {path} — confirm no runtime dependency.")
            removed_scored += 1

        # Big single-file edits (capped at 3 files)
        if f_adds + f_dels > 250 and big_edits_scored < 3:
            score += 6
            signals.append(f"Big edit in {path} ({f_adds}+/{f_dels}-).")
            big_edits_scored += 1

        # Keyword heuristics inside patch
        if isinstance(patch, str) and patch:
            if _RESILIENCE_RE.search(patch) and resilience_scored < 2:
                score += 4
                signals.append(f"Resilience behaviour changed in {path} (timeouts/retries/rate limits).")
                resilience_scored += 1

            if _SECURITY_WEAKEN_RE.search(patch) and security_scored < 2:
                score += 8
                signals.append(f"Potential security-weakening pattern in {path}.")
                security_scored += 1

            if _RISKY_SQL_RE.search(patch) and risky_sql_scored < 3:
                score += 10
                signals.append(f"Destructive SQL pattern detected in {path}.")
                risky_sql_scored += 1

    # -- Aggregate signals (scored once, not per-file) ----------------------------
    if risky_paths > 0:
        score += min(20, 6 + 2 * risky_paths)
        signals.append(f"Touches {risky_paths} sensitive area path(s) (auth/security/billing/etc).")

    if config_files > 0:
        score += min(12, 4 + 2 * config_files)
        signals.append(f"Config changes detected ({config_files} file(s)).")

    if sql_files > 0:
        score += min(18, 6 + 4 * sql_files)
        signals.append(f"SQL changes detected ({sql_files} file(s)).")

    if core_code_touched > 0 and test_touched == 0:
        score += 18
        signals.append("Code changed with no test modifications — possible test gap.")

    # -- Final scoring ------------------------------------------------------------
    score = max(0, min(100, score))
    score_10 = max(0, min(10, round(score / 10)))

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    confidence = _compute_confidence(changed_files, loc, test_touched, patch_missing)

    # -- Impact map ---------------------------------------------------------------
    impact: List[str] = []
    for d, n in top_dirs.most_common(4):
        impact.append(f"{d}/ (files: {n})")
    if config_files:
        impact.append("Config touched (env defaults/overrides may change).")
    if sql_files or touched_migrations:
        impact.append("Database schema/migrations likely affected.")
    if touched_api_contract:
        impact.append("API contract files touched (OpenAPI/Proto/GraphQL).")
    if risky_paths:
        impact.append("Sensitive subsystem paths touched (auth/security/billing/etc).")

    # Dedup signals (preserving order) for display
    seen_s: set[str] = set()
    uniq_signals: List[str] = []
    for s in signals:
        if s not in seen_s:
            uniq_signals.append(s)
            seen_s.add(s)

    top_exts = ", ".join(f"{k}:{v}" for k, v in ext_counts.most_common(8))
    file_summary = f"{changed_files} files | {additions}+/{deletions}- | exts: {top_exts}"

    return RiskResult(
        score_100=score,
        score_10=score_10,
        level=level,
        confidence=confidence,
        signals=uniq_signals,
        impact_map=impact[:8],
        risk_drivers=_pick_risk_drivers(uniq_signals),
        review_focus=_review_focus(config_files, sql_files, test_touched, risky_paths, level),
        operational_notes=_operational_notes(sql_files, config_files, touched_migrations, touched_api_contract, level),
        file_summary=file_summary,
        changed_files=changed_files,
        additions=additions,
        deletions=deletions,
        config_files=config_files,
        sql_files=sql_files,
        test_touched=test_touched,
        risky_paths=risky_paths,
    )
