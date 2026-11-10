---
name: cli-subagent
description: Delegate bounded Codex work when isolated context, a different model, or a configured local worker adds value. Use for parallel investigation, independent review, and approved fallback between worker routes.
---

# CLI Subagent

Keep planning, edits, and acceptance with the primary agent unless the caller explicitly delegates an isolated write. When a Codex skill or workflow already calls for subagents, use its native delegation path and preserve its permissions and completion criteria. If that workflow forbids further delegation, the parent can request a separate second opinion. This skill does not register commands, configure accounts, or install workers.

## Choose the work and worker

| Task | Route |
| --- | --- |
| Lint, coverage counts, mechanical migrations | Run the existing project tools. Give a fast agent a bounded batch of failures or repetitive edits when judgment is needed. |
| Test coverage gaps | Use a normal coding agent for known behavior in a small module. Use a stronger model to find missing invariants, integration cases, or risky test assumptions. Measure coverage with the test runner. |
| Complex refactoring | Use a strong model to map boundaries, invariants, and migration order. Use fast native explorers for independent dependency scans. Assign one writer per affected area or work sequentially. Ask a separate reviewer to check the final diff and test evidence. |
| Independent critique | When a different model family could find materially different issues, give an approved reviewer a small input and a specific question. |
| High-volume text triage | Filter deterministically first. If the remainder is still large, use an approved local model for a summary with source references; verify important claims against the original. |

When selecting a new route, choose the least costly approved route that meets the task's requirements for tools, context, permissions, and reasoning. Check the current host controls or provider catalog for the exact model and supported settings. A listing or a release announcement does not establish account access or quota. Use a host default only when the task permits it.

Treat newly exposed model IDs as candidates. Use declared capabilities and small representative checks to decide where they fit; do not infer rank from names, versions, or release dates. Raise reasoning or change models when evidence warrants it, such as an unresolved migration invariant or a failed representative check. Stay within the approved scope.

## Reuse the last successful route

Honor an explicit account or model pin and any no-fallback instruction. Otherwise reuse the most recently successful route for the same task type and data boundary if it is still eligible. A route identifies the worker, account or API profile, model, allowed inputs, and cost scope. Update the choice only after a usable result, in a configured private store or the current chat. If no prior choice exists, use the native route or the first approved route for that task. Do not rotate accounts merely to spread usage.

## Retry within the approved scope

- An added account or API is eligible for automatic fallback only if the user approved it for this task or a standing policy covers the same inputs, permissions, and cost. Use accounts the user is authorized to use under the provider's terms.
- For read-only work, try at most one approved alternative by default when the first route is unavailable or returns no usable result. Keep the same bounded input and do not ask again within that scope. Ask before sending data to an unapproved provider, using unapproved API credits, or expanding file access. If no approved worker is available, continue in the host when allowed or report the blocker.
- A process on this machine may still use remote inference. Keep local-only inputs and outputs in a verified local route, including tool output that would otherwise enter a hosted chat. Fail closed if that boundary cannot be enforced. For text workers, pass only explicit inputs and reject unsolicited tool calls. Verify workspace restrictions before dispatch.
- A read-only retry can reuse the same verified read-only input. After a write-capable worker starts, never replay the task automatically. Confirm the first worker stopped, inspect the existing diff, and continue from that state. Use separate worktrees only for independent concurrent edits that would otherwise interfere.

Give each worker a concrete question and the smallest input it needs. Ask for findings with evidence and the checks it actually ran. Verify the result before relying on it.
