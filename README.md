# Universal Multi-Account Local & CLI Subagent Router (`/cli-subagent`)

> **Stop juggling terminals, re-logging into accounts, and hitting rate limits.**
> One unified subagent router to delegate parallel tasks, balance quotas (including free tiers!), and call any CLI or local model from any environment: **OpenAI Codex (`codex`), xAI Grok (`grok`), Google Antigravity (`agy`), Claude Code CLI, Qwen CLI, and OpenCode**, plus any local OpenAI-compatible inference engine. Zero API proxies, zero context pollution in your main session.

---

## Prompt-Only Import

No sketchy `curl | bash` installer scripts. No reading walls of GPT-generated markdown.

Just paste this single prompt directly into your AI coding assistant (Antigravity, Codex, Claude Code, etc.):

```text
What useful things can be extracted from https://github.com/pacodelavega/cli-subagent
```

Your assistant will audit the pure-Python code, explain how it complements your locally installed CLIs, and guide you through an interactive setup.

---

## The Know-How (Why This Is a Game-Changer)

### 1. Multi-Profile Official CLI Pool (Zero Proxies, Zero Scrapers)
- **Quota Balancing & Rate-Limit Scaling:** Each account runs in its own isolated home directory using official CLI binaries. The router distributes tasks across your pool via LRU, maximizing free and subscription quotas without sharing session states.
- **Parallel Isolated Contexts:** Each subagent executes in an independent process and context window. Your main chat session receives only the final verified diff or summary—eliminating hundreds of lines of exploration noise.
- **`<0.1ms` Circuit Breakers:** Credential file fingerprints (`mtime_ns:size`) detect expired logins in under 0.1ms without network probes; provider-wide quarantine halts sibling cascades on regional/WAF blocks.
- **Host Self-Call Avoidance:** Detects your active environment and preserves your interactive session's quota by delegating background tasks to external tools.

### 2. Cross-Vendor Rivalry & Role Separation (`/owl`, `/battle`, `/goal`, `/teamwork`)
- **Eliminate Single-Vendor Blind Spots:** Dispatches competing model families against each other in `/battle` (Arm Alpha on one engine, Arm Beta on another, judged by an independent referee).
- **Decoupled Engineering (`/owl`):** Directs `DeepInvestigator` root-cause falsification on one vendor and `DeepCoder` synthesis on another.
- **Uninterrupted Autonomous Loops:** Runs `/goal` and `/teamwork` background waves across healthy profiles, surviving single-account `429` limits.

### 3. Have an Optional Local Model? Supercharge as a Coprocessor
Connect any local OpenAI-compatible inference engine (LM Studio, Ollama, vLLM, llama.cpp) to gain on-device speed without burning cloud quotas:
- **Instant Speed for Routine Heavy Tasks:** Process high-volume local tasks with zero network latency and zero cloud roundtrips.
- **Zero-Cloud Log & Context Compression:** Multi-hundred-line build outputs, test runner errors, or crash traces are condensed locally into concise root causes before entering expensive cloud context.
- **Uncensored White-Hat / Pen-Test / Infosec Coprocessor:** Commercial cloud models frequently refuse legitimate requests to inspect decompiled bytecode, anti-tamper logic, shellcode, or hardcoded API endpoints. With an uncensored local model, `/cli-subagent` routes deobfuscation and malware triage with zero safety refusals—while **100% of sensitive binaries and proprietary code remain strictly on your local machine**.
- **Zero-Breakage Fail-Open Cascade:** Probes your local server in `<1.5s`. If it is offline or unloaded, the router alerts you in chat and completes the task seamlessly via your cloud CLI pool without crashing or stalling.

---

## Any reading of GPT-texts below is unnecessary

*The sections below contain developer reference, internal routing flags, architecture, and configuration mechanics.*

### Architecture & Tier Firewall

1. **Universal & Self-Updating Across Model Generations:**
   - Zero hardcoded personal paths, zero static model slugs, zero cloud API relays, and zero binary modifications.
   - Automatically classifies any current or future model family into semantic tiers (`fast`, `workhorse`, `frontier`) from native CLI model caches and zero-token `models` CLI subcommands.

2. **`<1ms` Routine Overhead & Strict Cost Protection:**
   - Routine subagent calls validate binary and cache `mtime:size` fingerprints in under `1ms` without re-initializing catalogs or spending tokens.
   - Default `--tier workhorse` and `--tier fast` dispatches **never** invoke scarce `frontier` models unless explicitly requested.

3. **Circuit-Breaker Health & Actionable User Alerts:**
   - Unauthenticated profiles (`401 / session expired`) are recorded as `AUTH_REQUIRED` tied to their credential fingerprint, skipping them in `0ms` until re-authenticated; regional/network blocks (`403`) trip a provider-wide `NETWORK_BLOCKED` circuit breaker so sibling accounts never stall on duplicate retries.
   - Never masks broken auth silently behind fallback: completes the task via healthy profiles/fallback AND alerts the user in chat with an offer for prompt-driven browser sign-in.

4. **Write-Mode Safety (No Blind Retries):**
   - For write tasks (`workspace-write`), if a worker fails mid-execution, the task is **not** replayed on another worker (`partial_write_risk: true`), preventing duplicate mutations or conflicted git diffs.

5. **Verified Host Global Instructions Integration:**
   - Strictly after first-run initialization (`--init`) and a verified live subagent run (`--verify`), `/cli-subagent` offers via prompt to wire subagent delegation into your active host environment's configuration (saving automatic timestamped backups before applying any edits).

### Key Flags (`scripts/cli.py`)

- `--provider {auto,agy,codex,grok,gemini,claude,qwen,opencode,custom}`: `auto` round-robins across healthy enabled pools; specify a provider when cross-vendor diversity is required (`custom` routes to local/VPS OpenAI-compatible endpoints).
- `--tier {fast,workhorse,frontier}`: Dynamic model selection across current and future model families.
- `--mode {plan,accept-edits,read-only,workspace-write}`: Execution mode.
- `--role <label>`: Sets `role=<label>` in `dispatch_tag` (specialist roles like `forensic`, `deobfuscate`, `compressor`, `*:check` auto-prioritize local coprocessor).
- `--task "<prompt>"` or `--task-file <path>`: Pass prompt inline or via UTF-8 file.
- `--status` / `--refresh`: Inspect pool health, verification state, or force a zero-token native catalog rescan.

### Standard Host Workflows Matrix

| Environment | Standard Workflows | `/cli-subagent` Role | Default Tier |
| :--- | :--- | :--- | :--- |
| **Antigravity** | `/goal` & `/teamwork` | Offloads autonomous implementation, audit, and verification waves across external local CLI pools without single-account `429` stalls. | `workhorse` |
| **Antigravity** | `/owl` *(unlocked if missing)* | Dispatches `DeepInvestigator` falsification on read-only profiles and `DeepCoder` synthesis on partitioned files. | `workhorse` / `frontier` |
| **Antigravity** | `/battle` *(unlocked if missing)* | Pairs the active host model against competing families first, cascading to external `/cli-subagent` pools on quota limits. | `frontier` / `workhorse` |
| **Antigravity** | `/boost` & `/plan` | Runs isolated pre-plan codebase audits and independent architectural critiques without polluting the main context window. | `fast` / `workhorse` |
| **Codex** | `review-agent` & subagents | Routes independent defect-first code reviews and parallel subagent exploration across isolated secondary profiles and external local CLIs. | `workhorse` / `fast` |

### Repository Structure

```text
cli-subagent/
├── .gitignore
├── LICENSE                        # MIT License
├── README.md                      # Prompt-only import & architecture
└── skills/
    └── cli-subagent/              # Universal local CLI subagent skill
        ├── SKILL.md               # Agent operational protocol
        └── scripts/               # Internal engine (invoked by agents via prompts)
            ├── catalog.py         # <1ms fingerprint cache & dynamic model tiering
            ├── cli.py             # Unified internal entrypoint
            ├── provision.py       # Profile provisioner & host global instructions manager
            ├── router.py          # Tier-strict load balancer, verifier & circuit breaker
            ├── state.py           # Portable state & secret scrubber
            └── drivers/           # Local CLI drivers (agy, codex, grok, gemini, claude, qwen, opencode, custom)
```

---

[![Platform: Cross-Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue.svg)](#)
[![Dependencies: Standard Python 3](https://img.shields.io/badge/Dependencies-Zero%20Third--Party%20Packages-brightgreen.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
