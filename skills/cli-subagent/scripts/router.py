"""Tier-strict multi-account router, circuit-breaker health manager, and dispatch tagger."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import uuid

import catalog
from drivers import DRIVER_ORDER, create_driver_registry
import provision
import state

SPECIALIST_CUSTOM_ROLES = {
    # 1. Uncensored Bytecode/Binary Forensics, Deobfuscation & Malware Triage
    "forensic",
    "secops",
    "reverser",
    "deobfuscate",
    "malware",
    "owl:forensic",
    # 2. Zero-Cloud High-Density Log & Stacktrace Compression
    "compressor",
    "compress",
    "summarizer",
    "logs",
    "log-compressor",
    "compact",
    "goal:compress",
    "gamedev:compress",
    "gradle-compressor",
    "adb-compressor",
    "owl:compress",
    "battle:compress",
    # 3. Zero-Token Standing Cron / Health Gate
    "schedule:check",
    "automation:check",
}

SPECIALIST_CUSTOM_SUFFIXES = (
    ":compress",
    ":compressor",
    ":forensic",
    ":deobfuscate",
    ":check",
)


def is_specialist_custom_role(role: Optional[str]) -> bool:
    r_low = (role or "").strip().lower()
    if not r_low:
        return False
    return r_low in SPECIALIST_CUSTOM_ROLES or r_low.endswith(SPECIALIST_CUSTOM_SUFFIXES)


def _select_models_for_tier(
    prov_catalog: Dict[str, Any],
    tier: str,
    explicit_model: Optional[str],
    allow_frontier_fallback: bool,
) -> List[str]:
    if explicit_model:
        return [explicit_model]

    tiers = prov_catalog.get("tiers", {}) if isinstance(prov_catalog, dict) else {}
    fast_list = list(tiers.get("fast") or [])
    workhorse_list = list(tiers.get("workhorse") or [])
    frontier_list = list(tiers.get("frontier") or [])

    queue: List[str] = []
    if tier == "fast":
        for m in fast_list + workhorse_list:
            if m not in queue:
                queue.append(m)
        if allow_frontier_fallback:
            for m in frontier_list:
                if m not in queue:
                    queue.append(m)
    elif tier == "frontier":
        for m in frontier_list + workhorse_list:
            if m not in queue:
                queue.append(m)
    else:
        for m in workhorse_list + fast_list:
            if m not in queue:
                queue.append(m)
        if allow_frontier_fallback:
            for m in frontier_list:
                if m not in queue:
                    queue.append(m)
    return queue


def _sort_key_last_used(health_accounts: Dict[str, Any], acc_name: str, index: int) -> Tuple[int, str, int]:
    entry = health_accounts.get(acc_name, {})
    last_used = entry.get("last_used_at")
    if not last_used:
        return (0, "", index)
    return (1, str(last_used), index)


def get_status_report() -> Dict[str, Any]:
    """Return complete diagnostic status of configuration, catalog tiers, account health, and host."""
    host = state.detect_active_host()
    if not state.is_initialized():
        return {
            "initialized": False,
            "active_host": host,
            "message": "cli-subagent is not initialized yet. Run with --discover and --init.",
            "discovery": provision.discover_environment(),
        }

    cfg = state.load_config() or {}
    drivers = create_driver_registry()
    cat = catalog.ensure_catalog(cfg, drivers=drivers, force=False)
    health = state.load_health()
    h_accounts = health.get("accounts", {})
    now = datetime.now(timezone.utc)

    providers_report: Dict[str, Any] = {}
    alerts: List[Dict[str, Any]] = []

    for prov, pcfg in cfg.get("providers", {}).items():
        if not isinstance(pcfg, dict) or not pcfg.get("enabled"):
            continue
        drv = drivers.get(prov)
        prov_cat = cat.get("providers", {}).get(prov, {})
        acc_list: List[Dict[str, Any]] = []

        for acc in pcfg.get("accounts", []):
            name = acc["name"]
            h_entry = dict(h_accounts.get(name, {}))
            if acc.get("enabled") is False:
                acc_list.append({
                    "name": name,
                    "index": acc.get("index", 1),
                    "status": "STANDBY_DISABLED",
                    "detail": acc.get("description") or "Standby slot (enabled: false)",
                    "last_used_at": h_entry.get("last_used_at"),
                    "last_model": h_entry.get("last_model"),
                })
                continue
            status = h_entry.get("status", "HEALTHY")

            if status == "AUTH_REQUIRED" and drv:
                cur_fp = drv.auth_fingerprint(acc, pcfg)
                if cur_fp != h_entry.get("auth_fingerprint"):
                    is_ready, detail = drv.check_auth_ready(acc, pcfg)
                    if is_ready:
                        status = "HEALTHY"
                        h_entry["status"] = "HEALTHY"
                        h_entry["auth_fingerprint"] = cur_fp
                        h_entry["detail"] = detail
                        h_accounts[name] = h_entry
                        state.save_health(health)

            if status == "COOLDOWN_429":
                until = state.parse_iso(h_entry.get("cooldown_until"))
                if not until or now >= until:
                    status = "HEALTHY"

            if status == "NETWORK_BLOCKED":
                until = state.parse_iso(h_entry.get("blocked_until"))
                if not until or now >= until:
                    status = "HEALTHY"

            is_host_primary = (name == host.get("primary_account"))
            acc_list.append({
                "name": name,
                "home": acc.get("home"),
                "status": status,
                "host_primary_skipped_by_default": is_host_primary,
                "last_used_at": h_entry.get("last_used_at"),
                "detail": h_entry.get("detail"),
            })

            if status in ("AUTH_REQUIRED", "NETWORK_BLOCKED"):
                alerts.append({
                    "account": name,
                    "provider": prov,
                    "status": status,
                    "message": h_entry.get("detail") or f"{name} is {status}",
                    "action": (
                        f"Offer user prompt-driven login for '{name}' (--login --account {name})."
                        if status == "AUTH_REQUIRED"
                        else f"Check network/VPN reachability for '{prov}' ({name})."
                    ),
                })

        providers_report[prov] = {
            "binary": pcfg.get("binary"),
            "tiers": prov_cat.get("tiers", {}),
            "accounts": acc_list,
        }

    offer = provision.build_host_integration_offer(cfg, host)
    return {
        "initialized": True,
        "verified": bool(cfg.get("verified_at")),
        "verified_at": cfg.get("verified_at"),
        "state_dir": state.to_portable_path(state.get_state_dir()),
        "active_host": host,
        "host_integration": provision.inspect_host_integration(host.get("host")),
        "host_integration_offer": offer,
        "providers": providers_report,
        "alerts": alerts,
    }


def verify_pool(workspace: Path = Path.cwd(), timeout: float = 60.0) -> Dict[str, Any]:
    """Execute a real minimal-token subagent pass to verify initialization before offering host integration."""
    if not state.is_initialized():
        return {
            "status": "uninitialized",
            "exit_code": 2,
            "error": "cli-subagent is not initialized yet. Run --discover and --init first.",
            "discovery": provision.discover_environment(),
        }

    res = route_and_execute(
        task="Reply with the single word OK.",
        provider="auto",
        tier="fast",
        mode="plan",
        role="init-verify",
        isolate_context=False,
        workspace=workspace,
        timeout=timeout,
        dry_run=False,
        is_verification=True,
    )
    if res.get("status") == "ok":
        return res

    # If external accounts were skipped/unavailable, verify the host's own local CLI account if enabled
    cfg = state.load_config() or {}
    host = state.detect_active_host()
    primary_acc = host.get("primary_account")
    primary_prov = host.get("primary_provider")
    pcfg = (cfg.get("providers") or {}).get(primary_prov or "", {})
    if primary_acc and isinstance(pcfg, dict) and pcfg.get("enabled"):
        prior_alerts = list(res.get("alerts") or [])
        prior_history = list(res.get("failover_history") or [])
        host_res = route_and_execute(
            task="Reply with the single word OK.",
            provider=primary_prov or "auto",
            account=primary_acc,
            tier="fast",
            mode="plan",
            role="init-verify",
            isolate_context=True,
            workspace=workspace,
            timeout=timeout,
            dry_run=False,
            is_verification=True,
        )
        seen_keys = {f"{a.get('account')}:{a.get('status')}" for a in (host_res.get("alerts") or [])}
        merged_alerts = list(host_res.get("alerts") or [])
        for al in prior_alerts:
            k = f"{al.get('account')}:{al.get('status')}"
            if k not in seen_keys:
                seen_keys.add(k)
                merged_alerts.append(al)
        host_res["alerts"] = merged_alerts
        host_res["failover_history"] = prior_history + list(host_res.get("failover_history") or [])
        return host_res

    return res


def route_and_execute(
    *,
    task: str,
    provider: str = "auto",
    account: Optional[str] = None,
    tier: str = "workhorse",
    model: Optional[str] = None,
    effort: Optional[str] = None,
    mode: str = "plan",
    role: str = "worker",
    isolate_context: bool = False,
    allow_frontier_fallback: bool = False,
    workspace: Path = Path.cwd(),
    timeout: float = 1200.0,
    dry_run: bool = False,
    is_verification: bool = False,
) -> Dict[str, Any]:
    """Select optimal healthy local CLI account + tier-matched model and execute with auto-failover."""
    if not state.is_initialized():
        return {
            "status": "uninitialized",
            "exit_code": 2,
            "error": "cli-subagent is not initialized yet. Ask the user to confirm initial setup counts via prompt.",
            "discovery": provision.discover_environment(),
        }

    cfg = state.load_config() or {}
    drivers = create_driver_registry()
    cat = catalog.ensure_catalog(cfg, drivers=drivers, force=False)
    health = state.load_health()
    h_accounts = health.setdefault("accounts", {})
    host = state.detect_active_host()
    now = datetime.now(timezone.utc)

    req_prov = (provider or "auto").lower()
    enabled_provs = {
        p: pcfg
        for p, pcfg in cfg.get("providers", {}).items()
        if isinstance(pcfg, dict) and pcfg.get("enabled") and pcfg.get("accounts")
    }

    if account:
        matched_prov = None
        for p, pcfg in enabled_provs.items():
            if any(a.get("name") == account for a in pcfg.get("accounts", [])):
                matched_prov = p
                break
        if not matched_prov:
            return {
                "status": "error",
                "exit_code": 1,
                "error": f"Account '{account}' is not enabled in ~/.cli-subagent/config.json.",
                "alerts": [],
            }
        candidate_provs = [matched_prov]
    elif req_prov in ("auto", "custom"):
        if req_prov == "custom":
            candidate_provs = (
                (["custom"] if "custom" in enabled_provs else [])
                + [p for p in DRIVER_ORDER if p != "custom" and p in enabled_provs]
            )
        else:
            candidate_provs = [p for p in DRIVER_ORDER if p in enabled_provs]
    else:
        if req_prov not in enabled_provs:
            return {
                "status": "error",
                "exit_code": 1,
                "error": f"Provider '{req_prov}' is not enabled or has 0 configured accounts.",
                "enabled_providers": list(enabled_provs.keys()),
                "alerts": [],
            }
        candidate_provs = [req_prov]

    alerts: List[Dict[str, Any]] = []
    alert_seen: set[str] = set()

    def record_alert(acc_name: str, prov_name: str, st_code: str, msg: str) -> None:
        key = f"{acc_name}:{st_code}"
        if key in alert_seen:
            return
        alert_seen.add(key)
        if st_code == "AUTH_REQUIRED":
            action_msg = f"Offer prompt-driven login for '{acc_name}' (--login --account {acc_name})."
        elif st_code in ("LOCAL_OFFLINE", "LOCAL_NO_MODEL_LOADED", "LOCAL_MODEL_CASCADED"):
            action_msg = (
                "Предупредите пользователя в чате ('Локальная модель не отвечает / не загружена — стартовать?') "
                "и продолжите выполнение без сбоев через облачный/встроенный пул."
            )
        else:
            action_msg = f"Inform user of network/regional block on '{prov_name}' ({acc_name})."
        alerts.append({
            "account": acc_name,
            "provider": prov_name,
            "status": st_code,
            "message": msg,
            "action": action_msg,
        })

    primary_candidates: List[Tuple[Tuple[int, str, int], str, Dict[str, Any], List[str]]] = []
    fallback_candidates: List[Tuple[Tuple[int, str, int], str, Dict[str, Any], List[str]]] = []
    skipped_history: List[Dict[str, Any]] = []
    is_specialist_role = is_specialist_custom_role(role)

    for prov_name in candidate_provs:
        pcfg = enabled_provs[prov_name]
        drv = drivers[prov_name]
        prov_cat = cat.get("providers", {}).get(prov_name, {})
        eff_explicit_model = model if (req_prov == prov_name or (req_prov == "auto" and prov_name == "custom")) else None
        models_queue = _select_models_for_tier(prov_cat, tier, eff_explicit_model, allow_frontier_fallback)
        if not models_queue:
            continue

        for acc_cfg in pcfg.get("accounts", []):
            if acc_cfg.get("enabled") is False:
                continue
            acc_name = acc_cfg["name"]
            if account and acc_name != account:
                continue

            h_entry = h_accounts.get(acc_name, {})
            st = h_entry.get("status", "HEALTHY")

            is_fallback_prov = (req_prov == "custom" and prov_name != "custom") or (
                req_prov == "auto" and is_specialist_role and prov_name != "custom"
            )
            if st == "AUTH_REQUIRED":
                cur_fp = drv.auth_fingerprint(acc_cfg, pcfg)
                if cur_fp == h_entry.get("auth_fingerprint"):
                    detail = h_entry.get("detail") or f"{acc_name} requires authentication"
                    if not is_fallback_prov:
                        record_alert(acc_name, prov_name, "AUTH_REQUIRED", detail)
                        skipped_history.append({"account": acc_name, "status": "SKIPPED_AUTH_REQUIRED_0MS"})
                    continue
                st = "HEALTHY"

            if st == "NETWORK_BLOCKED":
                until_dt = state.parse_iso(h_entry.get("blocked_until"))
                if until_dt and now < until_dt:
                    detail = h_entry.get("detail") or f"{acc_name} is network-blocked until {until_dt.isoformat()}"
                    if not is_fallback_prov:
                        record_alert(acc_name, prov_name, "NETWORK_BLOCKED", detail)
                        skipped_history.append({"account": acc_name, "status": "SKIPPED_NETWORK_BLOCKED_0MS"})
                    continue
                st = "HEALTHY"

            if st == "COOLDOWN_429" and not account:
                until_dt = state.parse_iso(h_entry.get("cooldown_until"))
                if until_dt and now < until_dt:
                    skipped_history.append({"account": acc_name, "status": "SKIPPED_COOLDOWN_429"})
                    continue

            is_host_self = (acc_name == host.get("primary_account"))
            if is_host_self and not isolate_context and account != acc_name:
                skipped_history.append({"account": acc_name, "status": "SKIPPED_ACTIVE_HOST_PRIMARY"})
                continue

            sort_key = _sort_key_last_used(h_accounts, acc_name, int(acc_cfg.get("index", 1)))
            if req_prov == "custom":
                if prov_name == "custom":
                    primary_candidates.append(((-1, "", int(acc_cfg.get("index", 1))), prov_name, acc_cfg, models_queue))
                else:
                    fallback_candidates.append((sort_key, prov_name, acc_cfg, models_queue))
            elif req_prov == "auto" and prov_name == "custom":
                # Narrow coprocessor only: specialist roles. Never a silent general-purpose fallback,
                # because the host-native fallback (a frontier model) is stronger than a small local model.
                if is_specialist_role and tier != "frontier":
                    primary_candidates.append(((-1, "", int(acc_cfg.get("index", 1))), prov_name, acc_cfg, models_queue))
            else:
                primary_candidates.append((sort_key, prov_name, acc_cfg, models_queue))

    primary_candidates.sort(key=lambda item: item[0])
    fallback_candidates.sort(key=lambda item: item[0])
    execution_plan: List[Tuple[str, Dict[str, Any], List[str]]] = [
        (prov_name, acc_cfg, m_queue)
        for _, prov_name, acc_cfg, m_queue in (primary_candidates + fallback_candidates)
    ]

    ws_resolved = workspace.resolve()
    if dry_run:
        first = execution_plan[0] if execution_plan else None
        return {
            "status": "planned",
            "active_host": host,
            "requested_tier": tier,
            "selected": (
                {
                    "provider": first[0],
                    "account": first[1]["name"],
                    "model_queue": first[2],
                }
                if first
                else None
            ),
            "candidate_count": len(execution_plan),
            "skipped": skipped_history,
            "alerts": alerts,
            "workspace": str(ws_resolved),
            "notice": "Dry-run plan preview. Pass --run to execute.",
        }

    if not execution_plan:
        reason = "no_healthy_profiles_available"
        fallback_tag = (
            f"[DISPATCH: role={role}, tier=FALLBACK, tool=invoke_subagent, model=host-native, "
            f"settings=tier={tier},mode={mode}, reason={reason}]"
        )
        return {
            "status": "pool_exhausted",
            "exit_code": 1,
            "fallback_recommended": True,
            "dispatch_tag": fallback_tag,
            "error": "No healthy local CLI accounts available for the requested route.",
            "failover_history": skipped_history,
            "alerts": alerts,
        }

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    base_run_dir = state.runs_dir() / run_id
    attempts: List[Dict[str, Any]] = list(skipped_history)
    cooldown_sec = int(cfg.get("cooldown_429_seconds", 300))
    net_ttl_sec = int(cfg.get("network_block_ttl_seconds", 1800))

    attempt_num = 0
    net_blocked_providers: set[str] = set()
    is_writable_mode = mode in ("accept-edits", "workspace-write", "auto")
    # Failures that happen before any work starts are safe to fail over even in write modes.
    pre_exec_failures = {"AUTH_REQUIRED", "NETWORK_BLOCKED", "LOCAL_OFFLINE", "LOCAL_NO_MODEL_LOADED", "MODEL_UNAVAILABLE"}
    write_abort = False
    for prov_name, acc_cfg, models_queue in execution_plan:
        acc_name = acc_cfg["name"]
        if prov_name in net_blocked_providers:
            attempts.append({"account": acc_name, "status": "SKIPPED_PROVIDER_NETWORK_BLOCKED"})
            continue
        pcfg = enabled_provs[prov_name]
        drv = drivers[prov_name]
        account_aborted = False

        all_prov_models = list((cat.get("providers", {}).get(prov_name, {}).get("models") or {}).keys())
        effective_models = list(models_queue)

        m_idx = 0
        while m_idx < len(effective_models) and not account_aborted:
            cur_model = effective_models[m_idx]
            m_idx += 1
            attempt_num += 1
            attempt_dir = base_run_dir / f"{attempt_num:02d}_{acc_name}"

            exec_res = drv.execute(
                account_cfg=acc_cfg,
                provider_cfg=pcfg,
                model=cur_model,
                task=task,
                role=role,
                mode=mode,
                effort=effort,
                workspace=ws_resolved,
                timeout=timeout,
                run_dir=attempt_dir,
            )

            f_kind = exec_res.get("failure_kind")
            if exec_res["exit_code"] == 0 and f_kind is None:
                cur_model = str(exec_res.get("effective_model") or cur_model)
                drv_alert = exec_res.get("driver_alert")
                if isinstance(drv_alert, dict):
                    record_alert(
                        drv_alert.get("account", acc_name),
                        drv_alert.get("provider", prov_name),
                        drv_alert.get("status", "LOCAL_MODEL_CASCADED"),
                        drv_alert.get("message", ""),
                    )
                now_iso = state.utc_now_iso()
                h_accounts[acc_name] = {
                    "provider": prov_name,
                    "status": "HEALTHY",
                    "auth_fingerprint": drv.auth_fingerprint(acc_cfg, pcfg),
                    "detail": f"OK ({cur_model})",
                    "last_checked_at": now_iso,
                    "last_used_at": now_iso,
                    "last_model": cur_model,
                }
                state.save_health(health)

                cfg_dirty = False
                if not cfg.get("verified_at"):
                    cfg["verified_at"] = now_iso
                    cfg_dirty = True

                offer = provision.build_host_integration_offer(cfg, host)
                host_name = (host.get("host") or "").lower()
                if offer and not is_verification:
                    hi_state = cfg.setdefault("host_integration", {})
                    offered_hosts = list(hi_state.get("offered_hosts") or [])
                    if host_name in offered_hosts:
                        offer = None
                    else:
                        offered_hosts.append(host_name)
                        hi_state["offered_hosts"] = offered_hosts
                        cfg_dirty = True

                if cfg_dirty:
                    state.save_config(cfg)

                eff_part = f",effort={effort}" if effort else ""
                note_part = f",reason=failover_after_{attempt_num - 1}_attempts" if attempt_num > 1 else ""
                dispatch_tag = (
                    f"[DISPATCH: role={role}, tier=PRIMARY, tool={prov_name}/{acc_name}, "
                    f"model={cur_model}, settings=tier={tier},mode={mode}{eff_part}{note_part}]"
                )
                art_portable = state.to_portable_path(attempt_dir)
                state.record_telemetry_event(
                    run_id=run_id,
                    status="ok",
                    provider=prov_name,
                    account=acc_name,
                    model=cur_model,
                    role=role,
                    tier=tier,
                    elapsed_seconds=exec_res["elapsed_seconds"],
                    task=task,
                    output=exec_res["output"],
                    response_obj=exec_res.get("response"),
                    stderr=exec_res.get("stderr") or "",
                    workspace=str(ws_resolved),
                    artifacts_dir=art_portable,
                    attempts=[a for a in attempts if not str(a.get("status", "")).startswith("SKIPPED_")],
                    alerts=alerts,
                )
                payload: Dict[str, Any] = {
                    "status": "ok",
                    "provider": prov_name,
                    "account": acc_name,
                    "model": cur_model,
                    "tier": tier,
                    "exit_code": 0,
                    "elapsed_seconds": exec_res["elapsed_seconds"],
                    "dispatch_tag": dispatch_tag,
                    "output": exec_res["output"],
                }
                if alerts:
                    payload["alerts"] = alerts
                if offer:
                    payload["host_integration_offer"] = offer
                return payload

            attempts.append({
                "account": acc_name,
                "provider": prov_name,
                "model": cur_model,
                "status": f_kind or "EXEC_ERROR",
                "exit_code": exec_res["exit_code"],
                "elapsed_seconds": exec_res["elapsed_seconds"],
                "detail": state.scrub_secrets(exec_res.get("stderr") or exec_res.get("output"), limit=300),
            })

            if is_writable_mode and f_kind not in pre_exec_failures:
                # Possible partial edits: do not replay the same write task on another worker.
                write_abort = True
                account_aborted = True
                break

            if f_kind == "AUTH_REQUIRED":
                fp = drv.auth_fingerprint(acc_cfg, pcfg)
                detail = state.scrub_secrets(exec_res.get("stderr") or "Authentication required", limit=240)
                h_accounts[acc_name] = {
                    "provider": prov_name,
                    "status": "AUTH_REQUIRED",
                    "auth_fingerprint": fp,
                    "detail": detail,
                    "last_checked_at": state.utc_now_iso(),
                    "last_used_at": h_accounts.get(acc_name, {}).get("last_used_at"),
                }
                state.save_health(health)
                record_alert(acc_name, prov_name, "AUTH_REQUIRED", f"{acc_name}: {detail}")
                account_aborted = True

            elif f_kind == "NETWORK_BLOCKED":
                until_iso = (datetime.now(timezone.utc) + timedelta(seconds=net_ttl_sec)).isoformat()
                detail = state.scrub_secrets(exec_res.get("stderr") or "Network or regional block", limit=240)
                for sib in pcfg.get("accounts", []):
                    sib_name = sib["name"]
                    h_accounts[sib_name] = {
                        "provider": prov_name,
                        "status": "NETWORK_BLOCKED",
                        "blocked_until": until_iso,
                        "auth_fingerprint": drv.auth_fingerprint(sib, pcfg),
                        "detail": detail,
                        "last_checked_at": state.utc_now_iso(),
                        "last_used_at": h_accounts.get(sib_name, {}).get("last_used_at"),
                    }
                state.save_health(health)
                record_alert(acc_name, prov_name, "NETWORK_BLOCKED", f"{acc_name}: {detail}")
                net_blocked_providers.add(prov_name)
                account_aborted = True

            elif f_kind == "QUOTA_429":
                until_iso = (datetime.now(timezone.utc) + timedelta(seconds=cooldown_sec)).isoformat()
                h_accounts[acc_name] = {
                    "provider": prov_name,
                    "status": "COOLDOWN_429",
                    "cooldown_until": until_iso,
                    "auth_fingerprint": drv.auth_fingerprint(acc_cfg, pcfg),
                    "detail": f"Rate-limited (429) on {cur_model}",
                    "last_checked_at": state.utc_now_iso(),
                    "last_used_at": h_accounts.get(acc_name, {}).get("last_used_at"),
                }
                state.save_health(health)
                account_aborted = True

            elif f_kind in ("LOCAL_OFFLINE", "LOCAL_NO_MODEL_LOADED"):
                detail = state.scrub_secrets(exec_res.get("stderr") or "Local LLM endpoint unavailable", limit=320)
                h_accounts[acc_name] = {
                    "provider": prov_name,
                    "status": "HEALTHY",
                    "auth_fingerprint": drv.auth_fingerprint(acc_cfg, pcfg),
                    "detail": detail,
                    "last_checked_at": state.utc_now_iso(),
                    "last_used_at": h_accounts.get(acc_name, {}).get("last_used_at"),
                }
                state.save_health(health)
                record_alert(acc_name, prov_name, f_kind, detail)
                account_aborted = True

            elif f_kind == "MODEL_UNAVAILABLE":
                if tier != "frontier":
                    for alt, meta in (cat.get("providers", {}).get(prov_name, {}).get("models") or {}).items():
                        if alt not in effective_models and meta.get("tier") in ("workhorse", "fast"):
                            effective_models.append(alt)
                else:
                    for alt in all_prov_models:
                        if alt not in effective_models:
                            effective_models.append(alt)
            else:
                account_aborted = True
        if write_abort:
            break

    last_status = attempts[-1]["status"] if attempts else "pool_exhausted"
    if write_abort:
        last_status = f"WRITE_ABORTED_{last_status}"
    state.record_telemetry_event(
        run_id=run_id,
        status=last_status,
        provider=req_prov,
        account=account or "pool",
        model=model or "auto",
        role=role,
        tier=tier,
        elapsed_seconds=0.0,
        task=task,
        output="",
        workspace=str(ws_resolved),
        artifacts_dir=state.to_portable_path(base_run_dir),
        attempts=attempts,
        alerts=alerts,
    )
    fallback_tag = (
        f"[DISPATCH: role={role}, tier=FALLBACK, tool=invoke_subagent, model=host-native, "
        f"settings=tier={tier},mode={mode}, reason={last_status}]"
    )
    return {
        "status": "pool_exhausted",
        "exit_code": 1,
        "fallback_recommended": True,
        "dispatch_tag": fallback_tag,
        "error": (
            f"Write-mode attempt failed mid-run ({last_status}); not replayed to avoid duplicate/partial edits. "
            "Inspect `git status`/diff before re-dispatching."
            if write_abort
            else f"All candidate local CLI profiles failed or exhausted quotas (last status: {last_status})."
        ),
        "partial_write_risk": write_abort,
        "artifacts_dir": state.to_portable_path(base_run_dir),
        "failover_history": attempts,
        "alerts": alerts,
    }
