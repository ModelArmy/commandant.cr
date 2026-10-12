# Scope

Outstanding work, tracked in two buckets. **Completed items are deleted, not
ticked** — this file is a worklist, not a changelog. It should grow through the
early phases and dissolve as the design settles.

- **MUST FIX** — blocks progress, or is cheap now and expensive later.
- **WILL FIX** — real, but deliberately not now.

Anything settled belongs in code comments or design documentation; anything
outstanding belongs here, because nobody greps a codebase for open questions.

Reproduction commands use [`commandant-bench`](https://github.com/ModelArmy/commandant-bench) with `RULESETS_PATH` pointing at `commandant-rules-core/rulesets`.

---

## MUST FIX

- **Agree the next ruleset schema version** — One change, so every ruleset in `commandant-rules-core` is edited once (commandant-bench `BENCH_DESIGN.md` sections 8.1 and 8.2):
  - Add per-rule `examples` (`fires`, `does_not_fire`), inline in each rule; remove each pattern's `example`.
  - Add `flags` (aliases, `takes_value`), `subcommands` and `unrecognised_severity`; remove `option_abbreviations` and `unknown_flags`.
  - Decide whether the staleness `verification` fields (`STALENESS_MGMT_DESIGN.md`) and the `scope` field (`SCOPE_AND_RATE_CONTROL_DESIGN.md`) join this version or come later at the cost of a second pass.
  - Decide whether `default_rule` gains `reversible_note`: 29 default rules are `depends` with nowhere to say on what.

- **The ruleset schema is written down only in `commandant-rules-core`** — The format is defined by this shard's Crystal types, while the only JSON Schema is `skills/draft-tool-ruleset/tool_risk_ruleset_schema.json` in the rules repository, and nothing checks that they agree. Move it here as `schema/ruleset_schema.json`, beside `assessment_response_schema.json`, with a spec that fails when the types and the schema disagree. The skill keeps a copy, checked from the rules repository. Do this with the schema version above.

- **`RulePattern#example` is required** — The corpus is moving to per-rule `examples` (commandant-bench `BENCH_DESIGN.md` section 8.1), and a ruleset whose patterns lack `example` fails to load with `Missing JSON attribute: example`. Make the field optional before the corpus migrates; the engine already tolerates the other new fields (`flags`, `subcommands`, `unrecognised_severity`, `examples`).

- **An unknown first command hides the rest of a compound** — The unknown-tool response returns before compounds are assessed, so `cd x && rm -rf /` is WARNING while `ls && rm -rf /` is ERROR. Assess every compound even when the primary tool is unknown.
  Reproduce: `commandant-bench try 'cd x && rm -rf /'`

- **An environment-variable prefix becomes the binary** — `FOO=1 rm -rf build/` resolves the tool `FOO=1`, so no ruleset applies and the verdict is the unknown-tool WARNING. Skip leading `NAME=value` assignments when choosing the binary.
  Reproduce: `commandant-bench try 'GOPROXY=off go build ./...'`

- **An absolute binary path is an unknown tool** — `/usr/bin/rm -rf build/` looks up `/usr/bin/rm.json`. Resolve rulesets by the binary's base name.
  Reproduce: `commandant-bench try '/usr/bin/rm -rf build/'`

- **`.exe`, `.cmd` and `.bat` suffixes are never stripped** — `rm.exe -rf build` looks up `rm.exe.json` and falls through to unknown-tool handling. Strip the suffix case-insensitively, preferably once in `RulesetStore` lookup rather than in each Windows parser.
  Reproduce: `commandant-bench try 'rm.exe -rf build' -p windows-powershell`

- **`cmd.exe` flags never match Windows rulesets** — `CmdParser` uppercases flag canonicals (`/S`) while every Windows ruleset matches lowercase (`/s`), so no Windows rule fires: `dir /s C:\Users` falls to the INFO default. Decide which side normalises before the corpus migrates, since the answer may change the Windows rulesets.
  Reproduce: `commandant-bench try 'dir /s C:\Users' -p windows-cmd`

- **`cmd.exe` never treats `-` or `--` tokens as flags** — `CmdParser` classifies only `/`-prefixed tokens as flags, so POSIX-ported tools run from `cmd.exe` match no flag rule: `rm -rf build` gets `rm`'s default instead of `rm-recursive-force`. Blanket treatment of `-` tokens would misread negative numbers and dash-prefixed file names; the `flags` declaration below allows classifying a token as a flag when the tool's ruleset declares it.
  Reproduce: `commandant-bench try 'rm -rf build' -p windows-cmd`

- **Flag declaration and the unrecognised-flag check** — Read each ruleset's `flags` (aliases, `takes_value`) and `subcommands`, as specified in commandant-bench `BENCH_DESIGN.md` section 8.2:
  - Split combined short flags and assign flag values using the declaration, replacing the heuristic that splits only all-letter tokens of four characters or fewer (`-lash` is read today as one word flag).
  - Canonicalise aliases from `flags`; `option_abbreviations` is removed.
  - Run the unrecognised-flag check on every command, contributing `WARNING` or the ruleset's `unrecognised_severity` when a flag or subcommand is undeclared, and combine it with the rules' verdict by highest severity.
  - Report the undeclared tokens and whether the baseline default applied in `AssessmentResponse`; remove `unknown_flags`.

- **Design documents live outside the repository** — `STALENESS_MGMT_DESIGN.md` and `SCOPE_AND_RATE_CONTROL_DESIGN.md` exist only as delivered files. Commit them here, with the schema they propose to extend; the schema version decision above depends on them.

---

## WILL FIX

- **Rules fired in compound commands are not reported** — `AssessmentResponse#matched_rules` covers the primary command only; compounds raise the severity but are not attributed, so `ls && rm -rf /` is ERROR with no rule named.

- **Quoted `&&` splits a command** — `ls "x && rm -rf /"` is ERROR while `ls "x"` is INFO, because compound splitting ignores quotes. The error escalates rather than misses, but rules matching a quoted payload (`sh -c '…'`) see fragments.
  Reproduce: `commandant-bench try 'ls "x && rm -rf /"'`

- **`raw_pattern` compiles a `Regex` on every evaluation** — `MatchSpec#matches?` calls `Regex.new` each time. Cache the compiled pattern before any performance work; retiring catch-all rules removes many `raw_pattern` uses.

- **Multiplexer unwrapping and script inspection** — At least a dozen rulesets (shells, script interpreters, `sudo`, `su`, `chroot`, `xargs`, `bundle exec`, `find -exec`) cite unwrapping the wrapped command, or inspecting a script line by line, as their real fix.

- **Wrapped-command extraction schema** — A way for a rule to declare "this command runs another command, extracted like this", covering `find -exec`, `xargs`, `sh -c` and `bundle exec`. Needs a design document; scope and rate control depend on it.

- **Staleness tracking and detection** — Designed in `STALENESS_MGMT_DESIGN.md`: tracking is ready to implement; detection has no selected approach.

- **Scope and rate control** — Designed in `SCOPE_AND_RATE_CONTROL_DESIGN.md`; depends on wrapped-command extraction.
