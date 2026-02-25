from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List
import re
from collections import Counter

RISKY_PATH_PATTERNS = [
    r"(?i)\bauth\b",
    r"(?i)\bsecurity\b",
    r"(?i)\bpayment\b",
    r"(?i)\bbilling\b",
    r"(?i)\bcrypto\b",
    r"(?i)\bpermission\b",
    r"(?i)\badmin\b",
]

CODE_EXTS = {".py", ".js", ".ts", ".java", ".kt", ".cs", ".go", ".rb", ".php"}

CONFIG_EXTS = {".yml", ".yaml", ".json", ".toml", ".properties", ".ini"}
MIGRATION_HINTS = {"migrations", "flyway", "liquibase", "alembic", "schema.sql"}
API_CONTRACT_HINTS = {"openapi", "swagger", "proto", "graphql", "schema.graphql"}

@dataclass(frozen=True)
class RiskResult:
    score_100: int
    score_10: int
    level: str
    confidence: str
    signals: List[str]
    impact_map: List[str]
    risk_drivers: List[str]
    review_focus: List[str]
    operational_notes: List[str]
    file_summary: str

    # raw counts (useful for formatting / debugging)
    changed_files: int
    additions: int
    deletions: int
    config_files: int
    sql_files: int
    test_touched: int
    risky_paths: int

def _ext(path: str) -> str:
    m = re.search(r"(\.[A-Za-z0-9]+)$", path)
    return m.group(1).lower() if m else ""

def _top_level_dir(path: str) -> str:
    p = path.strip("/").split("/")
    return p[0] if len(p) >= 2 else "(root)"

def _compute_confidence(changed_files: int, adds: int, dels: int, test_touched: int, patch_missing: int) -> str:
    """
    Confidence = how reliable our heuristic read is.
    Low confidence when diffs are huge or GitHub doesn't provide patches (often means large/binary).
    """
    loc = adds + dels
    confidence = "High"

    if loc > 1500 or changed_files > 60:
        confidence = "Medium"
    if loc > 4000 or changed_files > 120:
        confidence = "Low"

    # If tests aren’t touched and diff is sizeable, we’re less confident in “safety”
    if test_touched == 0 and loc > 300 and confidence == "High":
        confidence = "Medium"
    if test_touched == 0 and loc > 1500:
        confidence = "Low"

    # If many patches missing, our keyword-based detectors have less info
    if patch_missing >= 10 and confidence == "High":
        confidence = "Medium"
    if patch_missing >= 30:
        confidence = "Low"

    return confidence

def _pick_risk_drivers(signals: List[str], max_items: int = 6) -> List[str]:
    """
    Take the noisy signal list and pick the most decision-relevant reasons.
    """
    if not signals:
        return []

    def weight(s: str) -> int:
        s_low = s.lower()
        w = 0
        if "security" in s_low or "auth" in s_low:
            w += 100
        if "sql" in s_low or "migration" in s_low or "schema" in s_low:
            w += 90
        if "config" in s_low:
            w += 70
        if "no tests" in s_low or "test" in s_low:
            w += 65
        if "large diff" in s_low or "big edit" in s_low:
            w += 50
        if "touches many files" in s_low:
            w += 40
        if "removed" in s_low:
            w += 25
        return w

    ranked = sorted(signals, key=weight, reverse=True)
    # Dedup preserving order
    out: List[str] = []
    seen = set()
    for s in ranked:
        if s not in seen:
            out.append(s)
            seen.add(s)
        if len(out) >= max_items:
            break
    return out

def _review_focus_from_facts(config_files: int, sql_files: int, test_touched: int, risky_paths: int, level: str) -> List[str]:
    items: List[str] = []
    if risky_paths:
        items.append("Review auth/security/payment-related changes carefully (sensitive area touched).")
    if sql_files:
        items.append("Verify migrations are reversible; check locks/indexes and rollout/rollback plan.")
    if config_files:
        items.append("Validate config defaults and environment overrides (staging vs prod).")
    if test_touched == 0:
        items.append("Request tests or a justification (touched code without test changes).")
    if level in {"MEDIUM", "HIGH"}:
        items.append("Ask for monitoring/rollback notes for deploy (what to watch, how to revert).")
    if level == "HIGH":
        items.append("Consider splitting PR or requiring explicit sign-off (risk concentrated).")
    # Keep it short
    return items[:5]

def _operational_notes(config_files: int, sql_files: int) -> List[str]:
    notes: List[str] = []
    if sql_files == 0:
        notes.append("No DB migrations detected.")
    if config_files == 0:
        notes.append("No config changes detected.")
    return notes

def compute_risk(files: List[Dict[str, Any]], pr: Dict[str, Any]) -> RiskResult:
    additions = int(pr.get("additions", 0) or 0)
    deletions = int(pr.get("deletions", 0) or 0)
    changed_files = int(pr.get("changed_files", len(files)) or len(files))

    signals: List[str] = []
    score = 0

    loc = additions + deletions
    if loc > 800:
        score += 30
        signals.append(f"Large diff ({additions}+ / {deletions}-).")
    elif loc > 300:
        score += 18
        signals.append(f"Medium diff size ({additions}+ / {deletions}-).")

    if changed_files > 40:
        score += 20
        signals.append(f"Touches many files ({changed_files}).")
    elif changed_files > 15:
        score += 10
        signals.append(f"Touches multiple files ({changed_files}).")

    renames = sum(1 for f in files if f.get("status") == "renamed")
    if renames >= 5:
        score += 10
        signals.append(f"Multiple renames ({renames}). Review for missing references.")

    risky_paths = 0
    config_files = 0
    sql_files = 0
    test_touched = 0
    core_code_touched = 0
    patch_missing = 0

    ext_counts = Counter()
    top_dirs = Counter()

    # impact detectors
    touched_migrations = False
    touched_api_contract = False

    for f in files:
        path = f.get("filename", "") or ""
        status = f.get("status", "") or ""
        ext = _ext(path)

        ext_counts[ext or "(none)"] += 1
        top_dirs[_top_level_dir(path)] += 1

        patch = f.get("patch")
        if not patch:
            patch_missing += 1

        adds = int(f.get("additions", 0) or 0)
        dels = int(f.get("deletions", 0) or 0)

        # tests touched?
        if re.search(r"(?i)\btest\b", path) or re.search(r"(?i)\bspec\b", path):
            test_touched += 1

        if ext in CODE_EXTS:
            core_code_touched += 1

        # config
        if ext in CONFIG_EXTS or "config" in path.lower():
            config_files += 1

        # sql
        if ext == ".sql":
            sql_files += 1

        # migrations / api contract hints (impact map)
        low_path = path.lower()
        if any(h in low_path for h in MIGRATION_HINTS):
            touched_migrations = True
        if any(h in low_path for h in API_CONTRACT_HINTS):
            touched_api_contract = True

        # risky paths
        for pat in RISKY_PATH_PATTERNS:
            if re.search(pat, path):
                risky_paths += 1
                break

        # keyword heuristics inside patch (if present)
        if isinstance(patch, str) and patch:
            if re.search(r"(?i)\b(timeout|retry|backoff|circuit|rate\s*limit)\b", patch):
                score += 4
                signals.append(f"Changes resilience behavior hinted in {path} (timeouts/retries/rate limits).")
            if re.search(r"(?i)\b(permitAll|csrf\(\)\.disable|allowedOrigins|\*)\b", patch):
                score += 8
                signals.append(f"Potential security weakening patterns in {path}.")
            if re.search(r"(?i)\b(drop\s+table|truncate|delete\s+from|alter\s+table)\b", patch):
                score += 10
                signals.append(f"Potentially risky SQL pattern hinted in {path}.")

        # big edits
        if adds + dels > 250:
            score += 6
            signals.append(f"Big edit in {path} ({adds}+/{dels}-).")

        if status == "removed":
            score += 3
            signals.append(f"File removed: {path}. Confirm no runtime dependency.")

    if risky_paths > 0:
        score += min(20, 6 + 2 * risky_paths)
        signals.append(f"Touches sensitive area paths (count={risky_paths}).")

    if config_files > 0:
        score += min(12, 4 + 2 * config_files)
        signals.append(f"Config changes detected (count={config_files}).")

    if sql_files > 0:
        score += min(18, 6 + 4 * sql_files)
        signals.append(f"SQL changes detected (count={sql_files}).")

    if core_code_touched > 0 and test_touched == 0:
        score += 18
        signals.append("Touches code but no tests appear modified. Possible test gap.")

    # Clamp score and label
    score = max(0, min(100, score))
    score_10 = max(0, min(10, int(round(score / 10.0))))

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    confidence = _compute_confidence(changed_files, additions, deletions, test_touched, patch_missing)

    # Impact map: top touched areas + special “surface area” signals
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

    # Clean signals: dedup preserving original order
    seen = set()
    uniq_signals = []
    for s in signals:
        if s not in seen:
            uniq_signals.append(s)
            seen.add(s)

    risk_drivers = _pick_risk_drivers(uniq_signals, max_items=6)
    review_focus = _review_focus_from_facts(config_files, sql_files, test_touched, risky_paths, level)
    op_notes = _operational_notes(config_files, sql_files)

    top_exts = ", ".join(f"{k}:{v}" for k, v in ext_counts.most_common(8))
    file_summary = f"{changed_files} files | {additions}+/{deletions}- | by extension: {top_exts}"

    return RiskResult(
        score_100=score,
        score_10=score_10,
        level=level,
        confidence=confidence,
        signals=uniq_signals,
        impact_map=impact[:8],
        risk_drivers=risk_drivers,
        review_focus=review_focus,
        operational_notes=op_notes,
        file_summary=file_summary,
        changed_files=changed_files,
        additions=additions,
        deletions=deletions,
        config_files=config_files,
        sql_files=sql_files,
        test_touched=test_touched,
        risky_paths=risky_paths,
    )
