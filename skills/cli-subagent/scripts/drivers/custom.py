"""Custom OpenAI-compatible HTTP driver with live VRAM state detection and fault-tolerant local cascade."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

from .base import (
    BaseDriver,
    classify_failure,
    wrap_bounded_prompt,
)
import state

DEFAULT_BASE_URL = "http://localhost:1235/v1"
DEFAULT_MAX_INPUT_CHARS = 38000  # ~10k-11k tokens, keeping total payload <= 12000 tokens in 16384 context
PROBE_TIMEOUT_SECONDS = 1.5
MAX_TOOL_ROUNDS = 3

SECOPS_ROLES = {
    "forensic", "secops", "reverser", "deobfuscate", "malware", "owl:forensic",
}
COMPRESSOR_ROLES = {
    "compressor", "compress", "summarizer", "logs", "log-compressor", "compact",
    "goal:compress", "gamedev:compress", "gradle-compressor", "adb-compressor", "owl:compress", "battle:compress",
}
CHECK_ROLES = {
    "schedule:check", "automation:check",
}

FILE_REF_RE = re.compile(
    r"""(?:^|[\s"'`(\[:])([A-Za-z0-9_.\-/\\]+\.[A-Za-z0-9]{1,10})(?=$|[\s"'`)\]:,;])"""
)


def _is_embedding_model(slug: str, item_type: Optional[str] = None) -> bool:
    if item_type and item_type.lower() in ("embedding", "embeddings", "rerank"):
        return True
    low = slug.lower()
    return any(k in low for k in ("embed", "embedding", "rerank", "bge-", "nomic-embed"))


def _origin_from_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url.strip())
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return base_url.rstrip("/")


def probe_local_endpoint(base_url: str, api_key: str = "", timeout: float = PROBE_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """
    Fast (<1.5s) non-blocking probe of OpenAI-compatible / LM Studio endpoint.
    Returns:
      {
        "online": bool,
        "state_aware": bool,          # True if server reports loaded vs not-loaded (e.g. LM Studio /api/v0/models)
        "loaded_models": List[str],   # Models currently resident in VRAM
        "all_models": List[str],      # All non-embedding models known to endpoint
        "error": Optional[str],
      }
    """
    origin = _origin_from_base_url(base_url)
    headers = {"User-Agent": "cli-subagent/1.0"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # 1. Try LM Studio state-aware endpoint (/api/v0/models) first to detect resident VRAM models
    try:
        req_v0 = urllib.request.Request(f"{origin}/api/v0/models", headers=headers)
        with urllib.request.urlopen(req_v0, timeout=timeout) as resp:
            if resp.status == 200:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
                items = payload.get("data", []) if isinstance(payload, dict) else []
                loaded: List[str] = []
                all_m: List[str] = []
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    m_id = str(it.get("id") or "").strip()
                    m_type = str(it.get("type") or "")
                    if not m_id or _is_embedding_model(m_id, m_type):
                        continue
                    if m_id not in all_m:
                        all_m.append(m_id)
                    if str(it.get("state") or "").lower() == "loaded" and m_id not in loaded:
                        loaded.append(m_id)
                return {
                    "online": True,
                    "state_aware": True,
                    "loaded_models": loaded,
                    "all_models": all_m,
                    "error": None,
                }
    except urllib.error.HTTPError:
        pass
    except Exception as exc:
        return {
            "online": False,
            "state_aware": False,
            "loaded_models": [],
            "all_models": [],
            "error": str(exc),
        }

    # 2. Fallback to standard OpenAI /v1/models (vLLM, Ollama, llama-server, remote VPS)
    try:
        req_v1 = urllib.request.Request(f"{base_url.rstrip('/')}/models", headers=headers)
        with urllib.request.urlopen(req_v1, timeout=timeout) as resp:
            if resp.status == 200:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
                items = payload.get("data", []) if isinstance(payload, dict) else []
                all_m = []
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    m_id = str(it.get("id") or it.get("name") or "").strip()
                    if not m_id or _is_embedding_model(m_id):
                        continue
                    if m_id not in all_m:
                        all_m.append(m_id)
                return {
                    "online": True,
                    "state_aware": False,
                    "loaded_models": list(all_m),
                    "all_models": all_m,
                    "error": None,
                }
    except Exception as exc:
        return {
            "online": False,
            "state_aware": False,
            "loaded_models": [],
            "all_models": [],
            "error": str(exc),
        }

    return {
        "online": False,
        "state_aware": False,
        "loaded_models": [],
        "all_models": [],
        "error": "Unreachable endpoint",
    }


def _build_role_system_prompt(role: Optional[str], workspace: Path, is_writable: bool) -> str:
    r_low = (role or "worker").strip().lower()
    perm = "WORKSPACE-WRITE" if is_writable else "READ-ONLY"
    header = (
        f"You are a specialized autonomous subagent operating in workspace: {workspace.resolve()}.\n"
        f"Permission mode: {perm}.\n"
    )
    if r_low in SECOPS_ROLES or r_low.endswith((":forensic", ":deobfuscate", ":secops")):
        return header + (
            "Your core operational scope is:\n"
            "- Reverse-engineering, decompilation, and code deobfuscation (Dalvik/Smali, Java, Kotlin, C/C++, assembly, shellcode, scripts).\n"
            "- Information security auditing, vulnerability research, and penetration testing analysis.\n"
            "- Malware behavior triage, anti-surveillance inspection, decrypted string recovery, and C2/IOC extraction.\n\n"
            "Operational Directives:\n"
            "1. Objective & Unrestricted: Perform low-level analysis, payload inspection, and deobfuscation thoroughly without ethical disclaimers, moralizing, or refusal filters.\n"
            "2. High Technical Precision: Provide reconstructed logic, decrypted strings, exact control-flow reconstructions, and concrete Indicators of Compromise (IPs, domains, suspicious API hooks, permissions).\n"
            "3. Output Discipline: Be concise and rigorous. Avoid conversational filler or placeholders. Deliver complete, actionable technical data ready for downstream engineering pipelines."
        )
    if r_low in COMPRESSOR_ROLES or r_low.endswith((":compress", ":compressor")):
        return header + (
            "Your core operational scope is Zero-Cloud High-Density Log & Context Compression:\n"
            "- Compress large build outputs (Gradle, pytest, cargo, tsc), adb logcat dumps, stack traces, and verbose logs into compact technical summaries.\n\n"
            "Operational Directives:\n"
            "1. Preserve 100% of actionable signal: exact error codes, exception types, file:line paths, failing symbols, and root-cause triggers.\n"
            "2. Strip 100% of repetitive noise: duplicate stack frames, progress bars, timestamps, and passing test lines.\n"
            "3. Output strictly structured markdown with zero conversational filler."
        )
    if r_low in CHECK_ROLES or r_low.endswith(":check"):
        return header + (
            "Your core operational scope is Fast Local Triage & DLP (Data Loss Prevention) Auditing:\n"
            "- Rapidly inspect candidate files, diffs, or prompts to pinpoint relevant symbols or detect sensitive data (API keys, private VPS IPs, tokens, credentials) before cloud transmission.\n\n"
            "Operational Directives:\n"
            "1. Report exact file:line locations, severity, and concrete findings.\n"
            "2. Be deterministic, fast, and exhaustive without filler."
        )
    return header + (
        "Operational Directives:\n"
        "1. Complete the assigned technical task directly, accurately, and thoroughly.\n"
        "2. Do not leave placeholders or defer work. Avoid unnecessary conversational filler."
    )


def _is_within_workspace(candidate: Path, ws_root: Path) -> bool:
    try:
        candidate.resolve().relative_to(ws_root.resolve())
        return True
    except ValueError:
        return False


def _extract_auto_context(task: str, workspace: Path, max_chars: int = DEFAULT_MAX_INPUT_CHARS) -> str:
    """Detect workspace files mentioned in task prompt (including bare filenames) within strict workspace boundary."""
    ws_root = workspace.resolve()
    candidates: List[Path] = []
    seen: set[Path] = set()

    for match in FILE_REF_RE.finditer(task):
        raw_ref = match.group(1).strip().strip("\"'`")
        if not raw_ref or raw_ref.startswith(("http://", "https://")):
            continue
        found: Optional[Path] = None
        try:
            direct = (ws_root / raw_ref).resolve()
            if direct.is_file() and _is_within_workspace(direct, ws_root):
                found = direct
        except Exception:
            pass
        if not found and "/" not in raw_ref and "\\" not in raw_ref:
            try:
                for p in ws_root.rglob(raw_ref):
                    if p.is_file() and _is_within_workspace(p, ws_root):
                        if not any(part.startswith(".") or part in ("node_modules", "__pycache__", "build", "dist") for part in p.parts):
                            found = p.resolve()
                            break
            except Exception:
                pass
        if found and found not in seen:
            seen.add(found)
            candidates.append(found)

    if not candidates:
        return ""

    blocks: List[str] = []
    used_chars = 0
    for fpath in candidates[:6]:
        try:
            if fpath.stat().st_size > 512_000:
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        try:
            rel_label = str(fpath.relative_to(ws_root)).replace("\\", "/")
        except ValueError:
            continue

        remaining = max_chars - used_chars
        if remaining <= 400:
            break
        if len(content) > remaining:
            content = content[:remaining] + "\n... [truncated to fit 16k context window] ..."
        block = f"### Attached Workspace File: `{rel_label}`\n```\n{content}\n```"
        blocks.append(block)
        used_chars += len(block)

    if not blocks:
        return ""
    return "\n\n---\n## Auto-Attached Workspace Context\n" + "\n\n".join(blocks)


def _get_readonly_tools_schema() -> List[Dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read text contents of a file inside the workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path to file inside workspace."},
                        "max_lines": {"type": "integer", "description": "Max lines to read (default 200)."},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_dir",
                "description": "List files and directories inside a workspace directory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative directory path (use '.' for root)."},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_text",
                "description": "Search for a substring or regex pattern across files in the workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Substring or regex to search for."},
                        "path": {"type": "string", "description": "Optional relative file or directory path."},
                    },
                    "required": ["pattern"],
                },
            },
        },
    ]


def _execute_readonly_tool(name: str, args: Dict[str, Any], workspace: Path) -> str:
    ws_root = workspace.resolve()
    try:
        if name == "read_file":
            rel = str(args.get("path") or ".").strip()
            max_lines = min(int(args.get("max_lines") or 200), 400)
            target = (ws_root / rel).resolve()
            if not _is_within_workspace(target, ws_root) or not target.is_file():
                return f"Error: File not found or outside workspace: {rel}"
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
            snippet = "\n".join(f"{i + 1}: {ln}" for i, ln in enumerate(lines[:max_lines]))
            if len(lines) > max_lines:
                snippet += f"\n... ({len(lines) - max_lines} more lines)"
            return snippet[:14000]

        if name == "list_dir":
            rel = str(args.get("path") or ".").strip()
            target = (ws_root / rel).resolve()
            if not _is_within_workspace(target, ws_root) or not target.is_dir():
                return f"Error: Directory not found or outside workspace: {rel}"
            entries = sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            out = [f"{'[DIR] ' if p.is_dir() else ''}{p.name}" for p in entries[:100]]
            return "\n".join(out) if out else "(empty directory)"

        if name == "search_text":
            pat = str(args.get("pattern") or "").strip()
            if not pat:
                return "Error: Empty pattern"
            rel = str(args.get("path") or ".").strip()
            target = (ws_root / rel).resolve()
            rx = re.compile(pat, re.IGNORECASE)
            hits: List[str] = []
            files = [target] if target.is_file() else list(target.rglob("*"))
            for fp in files:
                if len(hits) >= 40:
                    break
                if not fp.is_file() or fp.stat().st_size > 300_000:
                    continue
                if any(part.startswith(".") or part in ("node_modules", "__pycache__", "build", "dist") for part in fp.parts):
                    continue
                try:
                    for idx, ln in enumerate(fp.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                        if rx.search(ln):
                            rel_fp = str(fp.relative_to(ws_root)).replace("\\", "/")
                            hits.append(f"{rel_fp}:{idx}: {ln.strip()[:160]}")
                            if len(hits) >= 40:
                                break
                except Exception:
                    continue
            return "\n".join(hits) if hits else f"No matches found for '{pat}'."
    except Exception as exc:
        return f"Tool error: {exc}"
    return f"Unknown tool: {name}"


class CustomDriver(BaseDriver):
    provider = "custom"
    display_name = "Custom / Local VPS (OpenAI-Compatible)"
    max_accounts = 9

    def detect_binary(self) -> Optional[Path]:
        """HTTP driver runs via Python runtime standard library."""
        return Path(sys.executable)

    def resolve_base_url(self, account_cfg: Dict[str, Any], provider_cfg: Dict[str, Any]) -> str:
        raw = (
            account_cfg.get("base_url")
            or provider_cfg.get("base_url")
            or os.environ.get("CLI_SUBAGENT_CUSTOM_URL")
            or DEFAULT_BASE_URL
        )
        text = str(raw).strip()
        if text.startswith("env:"):
            var_name = text[4:].strip()
            return os.environ.get(var_name, "").strip()
        return text

    def resolve_api_key(self, account_cfg: Dict[str, Any], provider_cfg: Dict[str, Any]) -> str:
        raw = (
            account_cfg.get("api_key")
            or provider_cfg.get("api_key")
            or os.environ.get("CLI_SUBAGENT_CUSTOM_KEY")
            or ""
        )
        text = str(raw).strip()
        if text.startswith("env:"):
            var_name = text[4:].strip()
            return os.environ.get(var_name, "").strip()
        return text

    def build_account_entry(self, index: int, base_binary: Optional[Path]) -> Dict[str, Any]:
        name = "custom" if index == 1 else f"custom{index}"
        home_dir = state.get_user_home() / f".{name}"
        return {
            "name": name,
            "index": index,
            "home": state.to_portable_path(home_dir),
            "base_url": DEFAULT_BASE_URL,
        }

    def check_auth_ready(self, account_cfg: Dict[str, Any], provider_cfg: Dict[str, Any]) -> tuple[bool, str]:
        if account_cfg.get("enabled") is False:
            return False, "Account disabled in config.json"
        base_url = self.resolve_base_url(account_cfg, provider_cfg)
        if not base_url:
            return False, "Missing base_url (or unset env var) for custom endpoint"
        api_key = self.resolve_api_key(account_cfg, provider_cfg)
        probe = probe_local_endpoint(base_url, api_key=api_key)
        if not probe["online"]:
            return False, f"Offline ({base_url}): {probe['error']}"
        if probe["state_aware"] and not probe["loaded_models"]:
            return False, f"Online ({base_url}), but 0 models loaded in VRAM"
        loaded_str = ", ".join(probe["loaded_models"][:2])
        return True, f"Online ({base_url}; loaded: {loaded_str})"

    def discover_native_models(self, provider_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        preferred = str(provider_cfg.get("default_model") or "").strip()
        models: List[Dict[str, Any]] = []
        seen: set[str] = set()

        url_entries: List[Tuple[str, Dict[str, Any]]] = []
        seen_urls: set[str] = set()
        for acc in provider_cfg.get("accounts", []):
            if acc.get("enabled") is False:
                continue
            u = self.resolve_base_url(acc, provider_cfg)
            if u and u not in seen_urls:
                seen_urls.add(u)
                url_entries.append((u, acc))
        if not url_entries:
            u = self.resolve_base_url({}, provider_cfg)
            if u:
                url_entries.append((u, {}))

        for base_url, acc_ref in url_entries:
            api_key = self.resolve_api_key(acc_ref, provider_cfg)
            probe = probe_local_endpoint(base_url, api_key=api_key, timeout=2.5)
            for m_id in probe.get("all_models", []):
                if m_id not in seen:
                    seen.add(m_id)
                    is_pref = (m_id == preferred)
                    is_loaded = m_id in probe.get("loaded_models", [])
                    models.append({
                        "slug": m_id,
                        "description": f"Custom model {m_id} at {base_url}",
                        "priority": 1 if is_pref else (2 if is_loaded else 3),
                    })

        if preferred and preferred not in seen:
            models.insert(0, {
                "slug": preferred,
                "description": f"Preferred custom model {preferred}",
                "priority": 1,
            })
            seen.add(preferred)

        for fallback_m in provider_cfg.get("fallback_models", []):
            slug = str(fallback_m).strip()
            if slug and slug not in seen:
                seen.add(slug)
                models.append({
                    "slug": slug,
                    "description": f"Fallback custom model {slug}",
                    "priority": 2,
                })

        models.sort(key=lambda item: int(item.get("priority", 3)))
        return models

    def login_spec(self, account_cfg: Dict[str, Any], provider_cfg: Dict[str, Any]) -> tuple[List[str], Dict[str, str]]:
        return [sys.executable, "-c", "print('Custom OpenAI-compatible provider uses base_url and API key.')"], os.environ.copy()

    def _post_chat(
        self,
        url: str,
        req_body: Dict[str, Any],
        api_key: str,
        timeout: float,
    ) -> tuple[str, Dict[str, Any]]:
        req = urllib.request.Request(
            url,
            data=json.dumps(req_body).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "cli-subagent/1.0"},
            method="POST",
        )
        if api_key:
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_resp = resp.read().decode("utf-8", errors="replace")
            return raw_resp, json.loads(raw_resp)

    def execute(
        self,
        *,
        account_cfg: Dict[str, Any],
        provider_cfg: Dict[str, Any],
        model: str,
        task: str,
        role: Optional[str],
        mode: str,
        effort: Optional[str],
        workspace: Path,
        timeout: float,
        run_dir: Path,
    ) -> Dict[str, Any]:
        started = time.monotonic()
        base_url = self.resolve_base_url(account_cfg, provider_cfg)
        if not base_url:
            return {
                "exit_code": 1,
                "elapsed_seconds": 0.0,
                "output": "",
                "response": None,
                "stderr": "Custom endpoint base_url is not configured.",
                "failure_kind": "AUTH_REQUIRED",
            }
        api_key = self.resolve_api_key(account_cfg, provider_cfg)
        preferred_model = str(
            account_cfg.get("default_model") or provider_cfg.get("default_model") or model
        ).strip()

        # Fast pre-flight health & VRAM state check (<1.5s) so an offline/unloaded server NEVER hangs or auto-swaps blindly
        probe = probe_local_endpoint(base_url, api_key=api_key, timeout=PROBE_TIMEOUT_SECONDS)
        if not probe["online"]:
            elapsed = round(time.monotonic() - started, 3)
            msg = (
                f"Локальный LLM-сервер ({base_url}) не отвечает ({probe['error']}). "
                "Предупредите пользователя в чате ('Локальная модель не отвечает — стартовать?') и выполните задачу через облачный/встроенный пул."
            )
            return {
                "exit_code": 1,
                "elapsed_seconds": elapsed,
                "output": "",
                "response": None,
                "stderr": msg,
                "failure_kind": "LOCAL_OFFLINE",
            }

        effective_model = model or preferred_model
        local_cascade_alert: Optional[Dict[str, str]] = None

        if probe["state_aware"]:
            loaded_models = probe["loaded_models"]
            if not loaded_models:
                elapsed = round(time.monotonic() - started, 3)
                avail_str = ", ".join(probe["all_models"]) or "none"
                msg = (
                    f"Сервер {base_url} онлайн, но ни одна локальная модель сейчас не загружена в VRAM "
                    f"(доступны на диске: {avail_str}). "
                    "Спросите пользователя в чате ('Локальная модель не запущена в памяти — стартовать?') и продолжите работу без локального посредника."
                )
                return {
                    "exit_code": 1,
                    "elapsed_seconds": elapsed,
                    "output": "",
                    "response": None,
                    "stderr": msg,
                    "failure_kind": "LOCAL_NO_MODEL_LOADED",
                }

            # If requested/preferred model is not loaded, cascade immediately to any other loaded local model (e.g. secondary local model)
            if effective_model not in loaded_models:
                alt_loaded = loaded_models[0]
                local_cascade_alert = {
                    "account": account_cfg.get("name", "custom"),
                    "provider": "custom",
                    "status": "LOCAL_MODEL_CASCADED",
                    "message": (
                        f"Основная локальная модель '{effective_model}' не загружена в VRAM; "
                        f"выполнен автоматический каскад на запущенную локальную модель '{alt_loaded}'."
                    ),
                    "action": (
                        f"Сообщите пользователю в чате, что вместо '{effective_model}' использована запущенная '{alt_loaded}', "
                        f"и уточните, нужно ли загрузить '{effective_model}'."
                    ),
                }
                effective_model = alt_loaded

        is_writable = mode in ("accept-edits", "workspace-write", "auto")
        max_input_chars = int(provider_cfg.get("max_input_chars") or DEFAULT_MAX_INPUT_CHARS)
        task_budget = int(max_input_chars * 0.55)
        ctx_budget = max_input_chars - task_budget

        auto_ctx = _extract_auto_context(task, workspace, max_chars=ctx_budget)
        full_task = task
        if len(full_task) > (task_budget if auto_ctx else max_input_chars):
            limit_c = task_budget if auto_ctx else max_input_chars
            full_task = full_task[:limit_c] + "\n...[truncated to fit local 16k context window]..."
        if auto_ctx:
            full_task = full_task + auto_ctx

        wrapped = wrap_bounded_prompt(full_task, role=role, read_only=not is_writable)
        system_prompt = _build_role_system_prompt(role, workspace, is_writable)

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": wrapped},
        ]

        # Default enable_readonly_tools to False for 9B models (auto_ctx attaches referenced files deterministically in 1 shot)
        enable_tools = bool(provider_cfg.get("enable_readonly_tools", False)) and not auto_ctx
        tools_schema = _get_readonly_tools_schema() if enable_tools else None

        run_dir.mkdir(parents=True, exist_ok=True)
        url = f"{base_url.rstrip('/')}/chat/completions"

        try:
            raw_logs: List[str] = []
            resp_json: Dict[str, Any] = {}
            output_text = ""

            for round_idx in range(MAX_TOOL_ROUNDS + 1):
                req_body: Dict[str, Any] = {
                    "model": effective_model,
                    "messages": messages,
                    "temperature": float(provider_cfg.get("temperature", 0.3)),
                }
                if tools_schema and round_idx < MAX_TOOL_ROUNDS:
                    req_body["tools"] = tools_schema

                if round_idx == 0:
                    (run_dir / "request.json").write_text(
                        json.dumps(req_body, indent=2, ensure_ascii=False), encoding="utf-8"
                    )

                try:
                    raw_resp, resp_json = self._post_chat(url, req_body, api_key, timeout)
                except urllib.error.HTTPError as he:
                    if tools_schema and he.code == 400 and round_idx == 0:
                        tools_schema = None
                        req_body.pop("tools", None)
                        raw_resp, resp_json = self._post_chat(url, req_body, api_key, timeout)
                    else:
                        raise

                raw_logs.append(raw_resp)
                choices = resp_json.get("choices", [])
                if not choices:
                    break

                first_msg = choices[0].get("message", {})
                tool_calls = first_msg.get("tool_calls") or []

                if tool_calls and round_idx < MAX_TOOL_ROUNDS:
                    messages.append(first_msg)
                    for tc in tool_calls:
                        fn = tc.get("function") or {}
                        fn_name = str(fn.get("name") or "")
                        raw_args = fn.get("arguments") or "{}"
                        try:
                            parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                        except Exception:
                            parsed_args = {}
                        tool_out = _execute_readonly_tool(fn_name, parsed_args, workspace)
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc.get("id") or f"call_{round_idx}",
                            "name": fn_name,
                            "content": tool_out,
                        })
                    continue

                output_text = (first_msg.get("content") or "").strip()
                if not output_text and first_msg.get("reasoning_content"):
                    output_text = first_msg.get("reasoning_content").strip()
                break

            elapsed = round(time.monotonic() - started, 3)
            (run_dir / "stdout.log").write_text(state.scrub_secrets("\n---\n".join(raw_logs)), encoding="utf-8")
            (run_dir / "final_message.txt").write_text(output_text, encoding="utf-8")

            if output_text.startswith("<tool_call>") or "<function=" in output_text[:120]:
                return {
                    "exit_code": 1,
                    "elapsed_seconds": elapsed,
                    "output": "",
                    "response": resp_json,
                    "stderr": "Local 9B model emitted raw unparsed <tool_call> XML instead of final answer; failing over.",
                    "failure_kind": "EXEC_ERROR",
                }

            res_payload: Dict[str, Any] = {
                "exit_code": 0,
                "elapsed_seconds": elapsed,
                "output": output_text,
                "response": resp_json,
                "stderr": "",
                "failure_kind": None,
                "effective_model": effective_model,
            }
            if local_cascade_alert:
                res_payload["driver_alert"] = local_cascade_alert
            return res_payload
        except urllib.error.HTTPError as err:
            elapsed = round(time.monotonic() - started, 3)
            err_body = err.read().decode("utf-8", errors="replace")
            (run_dir / "stderr.log").write_text(err_body, encoding="utf-8")
            failure_kind = classify_failure(err.code, "", err_body)
            return {
                "exit_code": err.code,
                "elapsed_seconds": elapsed,
                "output": "",
                "response": None,
                "stderr": f"HTTP {err.code}: {err.reason}\n{err_body}",
                "failure_kind": failure_kind or "MODEL_UNAVAILABLE",
            }
        except Exception as exc:
            elapsed = round(time.monotonic() - started, 3)
            err_msg = str(exc)
            (run_dir / "stderr.log").write_text(err_msg, encoding="utf-8")
            failure_kind = "TIMEOUT" if "timed out" in err_msg.lower() else "LOCAL_OFFLINE"
            return {
                "exit_code": 1,
                "elapsed_seconds": elapsed,
                "output": "",
                "response": None,
                "stderr": err_msg,
                "failure_kind": failure_kind,
            }
