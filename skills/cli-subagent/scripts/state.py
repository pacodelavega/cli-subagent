"""Shared state, portable path helpers, host detection, and secret scrubbing for cli-subagent."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import time
import uuid
from typing import Any, Dict, Optional

SCHEMA_VERSION = 1

SECRET_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-+/=]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|secret)[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9._\-+/=]{10,}"), r"\1[REDACTED]"),
    (re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,}|xai-[A-Za-z0-9_\-]{16,}|AIza[0-9A-Za-z_\-]{25,})\b"), "[REDACTED_KEY]"),
    (re.compile(r"\[IP:[0-9a-fA-F.:]+\s*\|\s*Ray ID:[0-9a-fA-F]+\]"), "[IP:REDACTED | Ray ID:REDACTED]"),
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def get_user_home() -> Path:
    if os.name == "nt":
        userprofile = os.environ.get("USERPROFILE")
        if userprofile:
            return Path(userprofile).resolve()
    return Path.home().resolve()


def get_state_dir() -> Path:
    override = os.environ.get("CLI_SUBAGENT_HOME")
    if override:
        base = Path(override).expanduser().resolve()
    else:
        base = get_user_home() / ".cli-subagent"
    base.mkdir(parents=True, exist_ok=True)
    return base


def to_portable_path(path: Path | str) -> str:
    expanded = Path(os.path.abspath(str(Path(path).expanduser())))
    home = Path(os.path.abspath(str(get_user_home())))
    for candidate_home in (home, get_user_home()):
        try:
            rel = expanded.relative_to(candidate_home)
            rel_str = str(rel).replace("\\", "/")
            return "~" if rel_str == "." else f"~/{rel_str}"
        except ValueError:
            continue
    return str(expanded).replace("\\", "/")


def expand_portable_path(raw: Optional[str | Path]) -> Optional[Path]:
    if not raw:
        return None
    text = str(raw)
    if text == "~":
        return get_user_home()
    if text.startswith("~/") or text.startswith("~\\"):
        return (get_user_home() / text[2:]).resolve()
    return Path(text).expanduser().resolve()


def scrub_secrets(text: Optional[str], limit: Optional[int] = None) -> str:
    if not text:
        return ""
    cleaned = str(text)
    for pattern, repl in SECRET_PATTERNS:
        cleaned = pattern.sub(repl, cleaned)
    if limit and len(cleaned) > limit:
        half = limit // 2
        omitted = len(cleaned) - limit
        cleaned = f"{cleaned[:half]}\n...[truncated {omitted} chars]...\n{cleaned[-half:]}"
    return cleaned


def read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unique temp name per writer: concurrent dispatches must never share one temp file.
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    for attempt in range(5):
        try:
            tmp.replace(path)
            return
        except PermissionError:
            # Windows: target briefly locked by a concurrent reader/writer
            time.sleep(0.05 * (attempt + 1))
    tmp.replace(path)


def config_path() -> Path:
    return get_state_dir() / "config.json"


def catalog_path() -> Path:
    return get_state_dir() / "catalog.json"


def health_path() -> Path:
    return get_state_dir() / "health.json"


def runs_dir() -> Path:
    d = get_state_dir() / "runs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def backups_dir() -> Path:
    d = get_state_dir() / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def is_initialized() -> bool:
    cfg = read_json(config_path())
    return isinstance(cfg, dict) and bool(cfg.get("initialized")) and isinstance(cfg.get("providers"), dict)


def load_config() -> Optional[Dict[str, Any]]:
    cfg = read_json(config_path())
    if isinstance(cfg, dict) and cfg.get("initialized"):
        return cfg
    return None


def save_config(cfg: Dict[str, Any]) -> None:
    cfg["schema"] = SCHEMA_VERSION
    cfg["initialized"] = True
    cfg["updated_at"] = utc_now_iso()
    write_json(config_path(), cfg)


def load_catalog() -> Dict[str, Any]:
    data = read_json(catalog_path(), default={})
    return data if isinstance(data, dict) else {}


def save_catalog(data: Dict[str, Any]) -> None:
    write_json(catalog_path(), data)


def load_health() -> Dict[str, Any]:
    data = read_json(health_path(), default={"accounts": {}})
    if not isinstance(data, dict) or not isinstance(data.get("accounts"), dict):
        return {"accounts": {}}
    return data


def save_health(data: Dict[str, Any]) -> None:
    write_json(health_path(), data)


def detect_active_host() -> Dict[str, Optional[str]]:
    """Detect which AI coding environment invoked cli-subagent."""
    env = os.environ
    if env.get("CODEX_THREAD_ID") or env.get("CODEX_SANDBOX"):
        return {"host": "codex", "primary_provider": "codex", "primary_account": "codex"}
    if any(env.get(k) for k in ("ANTIGRAVITY_AGENT", "ANTIGRAVITY_CONVERSATION_ID", "ANTIGRAVITY_APP_DATA_DIR", "ANTIGRAVITY_GEMINI_DIR")):
        return {"host": "antigravity", "primary_provider": "agy", "primary_account": "agy"}
    if env.get("GEMINI_CLI"):
        return {"host": "gemini", "primary_provider": "gemini", "primary_account": "gemini"}
    if env.get("CLAUDECODE") or env.get("CLAUDE_CODE_ENTRYPOINT"):
        return {"host": "claude", "primary_provider": "claude", "primary_account": "claude"}
    if env.get("GROK_CLI_SESSION") or env.get("GROK_SANDBOX"):
        return {"host": "grok", "primary_provider": "grok", "primary_account": "grok"}
    if env.get("OPENCODE_CLIENT"):
        return {"host": "opencode", "primary_provider": "opencode", "primary_account": "opencode"}
    return {"host": "shell", "primary_provider": None, "primary_account": None}


def is_self_wrapper_script(path: Path) -> bool:
    """Return True if a .cmd/.bat/.sh script is a cli-subagent launcher shim rather than a real CLI."""
    if not path.is_file():
        return False
    suffix = path.suffix.lower()
    if suffix not in {".cmd", ".bat", ".ps1", ""} and os.name == "nt":
        return False
    try:
        if path.stat().st_size > 16384:
            return False
        body = path.read_text(encoding="utf-8", errors="ignore").lower()
        return "cli-subagent" in body
    except Exception:
        return False


def find_real_binary(candidates: list[str], extra_paths: Optional[list[Path]] = None) -> Optional[Path]:
    """Locate a genuine local CLI executable, skipping recursive wrapper scripts and preserving stable shim paths."""
    seen: set[str] = set()
    path_dirs = [Path(p) for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    for name in candidates:
        which_hit = shutil.which(name)
        if which_hit:
            p = Path(os.path.abspath(which_hit))
            key = str(p).lower()
            if key not in seen and not is_self_wrapper_script(p):
                return p
            seen.add(key)
        for directory in path_dirs:
            for ext in ((".exe", ".cmd", ".bat", "") if os.name == "nt" else ("",)):
                cand = directory / (name if name.lower().endswith(ext) and ext else f"{name}{ext}")
                if cand.is_file():
                    abs_cand = Path(os.path.abspath(str(cand)))
                    key = str(abs_cand).lower()
                    if key not in seen and not is_self_wrapper_script(abs_cand):
                        return abs_cand
                    seen.add(key)
    if extra_paths:
        for ep in extra_paths:
            expanded = Path(os.path.abspath(str(ep.expanduser())))
            if expanded.is_file() and not is_self_wrapper_script(expanded):
                return expanded
    return None


def file_fingerprint(path: Optional[Path]) -> Optional[str]:
    if not path or not path.exists():
        return None
    try:
        st = path.stat()
        return f"{st.st_mtime_ns}:{st.st_size}"
    except OSError:
        return None


def _ensure_ignore_guards(base_dir: Path) -> None:
    for ignore_name in (".gitignore", ".geminiignore", ".cursorignore", ".agignore"):
        ig = base_dir / ignore_name
        if not ig.exists():
            try:
                ig.write_text("*\n", encoding="utf-8")
            except OSError:
                pass


def logs_dir() -> Path:
    base = get_state_dir()
    _ensure_ignore_guards(base)
    d = base / "logs"
    d.mkdir(parents=True, exist_ok=True)
    _ensure_ignore_guards(d)
    return d


def journal_md_path() -> Path:
    return logs_dir() / "journal.md"


def telemetry_jsonl_path() -> Path:
    return logs_dir() / "warnings_errors.jsonl"


SEVERITY_TABLE_RE = re.compile(r"(?m)^\|\s*(Critical|High|Medium|Low|P0|P1|P2|ERROR|WARN)\s*\|\s*([^|\n]+)\|", re.IGNORECASE)
BULLET_DEFECT_RE = re.compile(
    r"(?m)^(?:[-*]|\d+\.)\s+\*\*([^*]{3,80})\*\*[:\s\u2014\-]*([^\n]{10,220})"
)
DOMAIN_IOC_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:ru|com|net|org|io|dev|internal)\b", re.IGNORECASE)
ERROR_LINE_RE = re.compile(r"(?m)^.*\b(?:ERROR|Exception|NullPointerException|FATAL|WARN|blocked|stalled|Reconnecting)\b.*$")


def harvest_zero_token_findings(
    *,
    output: str,
    raw_stdout: str = "",
    stderr: str = "",
    role: str = "worker",
    status: str = "ok",
    attempts: Optional[list[Dict[str, Any]]] = None,
    alerts: Optional[list[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Pure Python (0-token) extractor that returns a structured WARN/ERROR event ONLY if:
      1) Code/security/build defects or blocked verifications are present in the subagent output, OR
      2) Infrastructure errors/warnings/failovers occurred (429, WebSocket drop, auth expired, local cascade/offline).
    Returns None for clean/trivial 'OK' runs so green runs never pollute the log.
    """
    text = (output or "").strip()
    combined_raw = f"{raw_stdout or ''}\n{stderr or ''}"
    low_text = text.lower()

    # 1. Check infrastructure warnings/errors
    infra_issues: list[str] = []
    for att in (attempts or []):
        st = str(att.get("status") or "")
        if st and not st.startswith("SKIPPED_ACTIVE_HOST"):
            acc = att.get("account") or "?"
            det = att.get("detail") or ""
            infra_issues.append(f"{acc}: {st}" + (f" ({det[:90]})" if det else ""))

    for al in (alerts or []):
        st = str(al.get("status") or "")
        if st in ("LOCAL_OFFLINE", "LOCAL_NO_MODEL_LOADED", "LOCAL_MODEL_CASCADED", "QUOTA_429", "NETWORK_BLOCKED"):
            infra_issues.append(f"{al.get('account', 'custom')}: {st} - {scrub_secrets(al.get('message', ''), limit=120)}")

    if "reconnecting..." in combined_raw.lower() or "workspace routing discovery failed" in combined_raw.lower():
        infra_issues.append("WebSocket transport failed (Reconnecting 1..5/5 -> fell back to HTTPS / failed)")
    if "workspace reads did not return" in low_text or "workspace reads stalled" in low_text or "verification blocked" in low_text:
        infra_issues.append("Sandbox read-only shell stalled (workspace reads did not return)")

    # 2. Skip trivial pings or explicitly clean outputs unless infra_issues occurred
    trivial_clean = (
        len(text) < 45
        or low_text in ("ok", "pong", "clean_no_patch_ok", "hello_secops")
        or ("no secrets" in low_text and len(text) < 220)
    )
    if trivial_clean and status == "ok" and not infra_issues:
        return None

    # 3. Extract code/security/build findings (0 tokens, pure regex)
    defect_counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Error/Warn": 0}
    highlights: list[str] = []

    for m in SEVERITY_TABLE_RE.finditer(text):
        sev_raw = m.group(1).strip().capitalize()
        finding = " ".join(m.group(2).split())
        key = "Critical" if sev_raw in ("Critical", "P0") else ("High" if sev_raw in ("High", "P1") else ("Medium" if sev_raw in ("Medium", "P2") else "Error/Warn"))
        defect_counts[key] = defect_counts.get(key, 0) + 1
        if len(highlights) < 6:
            highlights.append(f"[{sev_raw.upper()}] {finding[:140]}")

    # Keyword, IOC and generic error-line heuristics removed after adversarial review (false positives).
    iocs: list[str] = []

    total_defects = sum(defect_counts.values())
    if total_defects == 0 and not infra_issues and status == "ok":
        return None

    r_low = (role or "").strip().lower()
    is_comp_role = r_low in ("compressor", "compress", "summarizer", "logs", "log-compressor", "compact") or r_low.endswith((":compress", ":compressor"))
    level = "ERROR" if (status != "ok" or defect_counts["Critical"] > 0 or defect_counts["High"] > 0 or (not is_comp_role and "ERROR:" in text) or any("LOCAL_OFFLINE" in x or "QUOTA_429" in x or "NETWORK_BLOCKED" in x for x in infra_issues)) else "WARN"
    return {
        "level": level,
        "defect_counts": {k: v for k, v in defect_counts.items() if v > 0},
        "total_defects": total_defects,
        "highlights": highlights,
        "iocs": iocs[:8],
        "infra_issues": infra_issues[:5],
    }


def record_telemetry_event(
    *,
    run_id: str,
    status: str,
    provider: str,
    account: str,
    model: str,
    role: str,
    tier: str,
    elapsed_seconds: float,
    task: str,
    output: str,
    response_obj: Any = None,
    raw_stdout: str = "",
    stderr: str = "",
    workspace: Optional[str] = None,
    artifacts_dir: Optional[str] = None,
    attempts: Optional[list[Dict[str, Any]]] = None,
    alerts: Optional[list[Dict[str, Any]]] = None,
    timestamp_override: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Zero-token WARN/ERROR logger. Ignores clean/OK runs completely.
    Writes only actionable code/security findings, compressed build errors, and infra failovers.
    """
    try:
        harvest = harvest_zero_token_findings(
            output=output,
            raw_stdout=raw_stdout,
            stderr=stderr,
            role=role,
            status=status,
            attempts=attempts,
            alerts=alerts,
        )
        if harvest is None:
            return None

        in_chars = len(task or "")
        out_chars = len(output or "")
        est_in_tokens = max(1, in_chars // 4)
        est_out_visible_tokens = max(1, out_chars // 4) if out_chars > 0 else 0

        prompt_tokens = est_in_tokens
        completion_tokens = est_out_visible_tokens
        reasoning_tokens = 0
        hidden_reasoning = ""

        if isinstance(response_obj, dict):
            usage = response_obj.get("usage")
            if isinstance(usage, dict):
                prompt_tokens = int(usage.get("prompt_tokens") or est_in_tokens)
                completion_tokens = int(usage.get("completion_tokens") or est_out_visible_tokens)
                details = usage.get("completion_tokens_details")
                if isinstance(details, dict):
                    reasoning_tokens = int(details.get("reasoning_tokens") or 0)
            choices = response_obj.get("choices")
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message") or {}
                hidden_reasoning = str(msg.get("reasoning_content") or "").strip()

        r_low = (role or "worker").strip().lower()
        is_compressor = r_low in {"compressor", "compress", "summarizer", "logs", "log-compressor"}

        compression_ratio_pct = 0.0
        if prompt_tokens > 0 and out_chars > 0 and (is_compressor or prompt_tokens > est_out_visible_tokens * 2):
            compression_ratio_pct = round(
                max(0.0, (1.0 - (est_out_visible_tokens / max(1, prompt_tokens))) * 100.0), 1
            )

        cloud_tokens_saved = 0
        if provider == "custom":
            cloud_tokens_saved = (
                max(0, prompt_tokens - est_out_visible_tokens) + prompt_tokens + completion_tokens
                if is_compressor
                else prompt_tokens + completion_tokens
            )

        record = {
            "timestamp": timestamp_override or utc_now_iso(),
            "run_id": run_id,
            "level": harvest["level"],
            "status": status,
            "provider": provider,
            "account": account,
            "model": model,
            "role": role,
            "tier": tier,
            "workspace": workspace or "",
            "elapsed_seconds": elapsed_seconds,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "reasoning_tokens": reasoning_tokens,
            "visible_output_tokens": est_out_visible_tokens,
            "compression_ratio_pct": compression_ratio_pct,
            "cloud_tokens_saved": cloud_tokens_saved,
            "defect_counts": harvest["defect_counts"],
            "total_defects": harvest["total_defects"],
            "highlights": harvest["highlights"],
            "iocs": harvest["iocs"],
            "infra_issues": harvest["infra_issues"],
            "hidden_reasoning_preview": scrub_secrets(" ".join(hidden_reasoning.split())[:220]) if hidden_reasoning else "",
            "artifacts_dir": artifacts_dir,
        }

        with telemetry_jsonl_path().open("a", encoding="utf-8") as jf:
            jf.write(json.dumps(record, ensure_ascii=False) + "\n")

        _rebuild_grouped_journal_md()
        return record
    except Exception:
        return None


def _rebuild_grouped_journal_md() -> None:
    """Render ~/.cli-subagent/logs/journal.md (WARN/ERROR only, zero green noise)."""
    jpath = telemetry_jsonl_path()
    if not jpath.is_file():
        return
    records: list[Dict[str, Any]] = []
    seen_runs: set[str] = set()
    for ln in jpath.read_text(encoding="utf-8", errors="replace").splitlines():
        if not ln.strip():
            continue
        try:
            obj = json.loads(ln)
            rid = obj.get("run_id")
            if rid and rid not in seen_runs:
                seen_runs.add(rid)
                records.append(obj)
        except Exception:
            continue

    total_saved = sum(int(r.get("cloud_tokens_saved") or 0) for r in records)
    total_defects = sum(int(r.get("total_defects") or 0) for r in records)

    lines = [
        "# Subagent WARN / ERROR Diagnostic Journal (Zero-Token Stream Digest)",
        "",
        f"- **Logged Warn/Error Events:** `{len(records)}` *(clean/OK runs suppressed)*",
        f"- **Total Code/SecOps Defects Extracted:** `{total_defects}`",
        f"- **Estimated Cloud Tokens Saved (Local Execution & Compression):** `~{total_saved}`",
        "",
    ]

    for r in reversed(records):
        ts = str(r.get("timestamp") or "")[:19].replace("T", " ")
        lvl = r.get("level", "WARN")
        prov = f"{r.get('provider')}/{r.get('account')}"
        model = r.get("model") or "?"
        role = r.get("role") or "worker"
        defs = r.get("defect_counts") or {}
        def_str = ", ".join(f"{k}: {v}" for k, v in defs.items()) if defs else "Infra/Stream Alert"
        comp = float(r.get("compression_ratio_pct") or 0)
        saved = int(r.get("cloud_tokens_saved") or 0)

        meta_parts = [f"`{prov}` (`{model}`)", f"role=`{role}`", f"**{def_str}**"]
        if comp >= 25.0:
            meta_parts.append(f"compressed=`{comp}%`")
        if saved > 0:
            meta_parts.append(f"saved=`~{saved}t`")

        lines.append(f"### [{lvl}] {ts} -- {' | '.join(meta_parts)}")
        for inf in (r.get("infra_issues") or []):
            lines.append(f"- **[INFRA]** {inf}")
        for hl in (r.get("highlights") or []):
            lines.append(f"- **[FINDING]** {hl}")
        if r.get("iocs"):
            lines.append(f"- **[IOC / ENDPOINTS]** `{', '.join(r['iocs'])}`")
        if r.get("hidden_reasoning_preview"):
            lines.append(f"- **[THINK DUMP]** _{r['hidden_reasoning_preview']}_")
        if r.get("artifacts_dir"):
            lines.append(f"- **[RAW]** `{r['artifacts_dir']}`")
        lines.append("")

    journal_md_path().write_text("\n".join(lines), encoding="utf-8")


def get_telemetry_summary(last_n: int = 12) -> Dict[str, Any]:
    """Return WARN/ERROR summary and grouped highlights on explicit /cli-subagent stats request."""
    jpath = telemetry_jsonl_path()
    records: list[Dict[str, Any]] = []
    if jpath.is_file():
        for ln in jpath.read_text(encoding="utf-8", errors="replace").splitlines():
            if ln.strip():
                try:
                    records.append(json.loads(ln))
                except Exception:
                    continue

    total_saved = sum(int(r.get("cloud_tokens_saved") or 0) for r in records)
    total_defects = sum(int(r.get("total_defects") or 0) for r in records)
    comp_records = [r for r in records if float(r.get("compression_ratio_pct") or 0) >= 25.0]
    avg_comp = (
        round(sum(float(r["compression_ratio_pct"]) for r in comp_records) / len(comp_records), 1)
        if comp_records
        else 0.0
    )

    return {
        "status": "ok",
        "policy": "WARN_AND_ERROR_ONLY (clean/OK runs suppressed; 0 tokens spent on logging)",
        "log_files": {
            "journal_md": to_portable_path(journal_md_path()),
            "warnings_errors_jsonl": to_portable_path(jpath),
            "indexed_by_workspace": False,
        },
        "totals": {
            "logged_warn_error_events": len(records),
            "total_defects_and_findings": total_defects,
            "compressed_error_logs": len(comp_records),
            "avg_compression_ratio_pct": avg_comp,
            "estimated_cloud_tokens_saved": total_saved,
        },
        "events": records[-last_n:],
    }
