# CLI Subagent

An instruction-only Codex skill for bounded delegation, isolated context, independent review, and approved worker fallback.

To inspect the skill, ask your coding assistant:

```text
What useful things can be extracted from https://github.com/pacodelavega/cli-subagent?
```

To use it in a Codex project, place [skills/cli-subagent](skills/cli-subagent/SKILL.md) under the project's `.agents/skills/` and invoke `$cli-subagent`. Native subagents depend on the host's available controls. External or local workers require an existing callable route and an approved scope.

[MIT License](LICENSE)
