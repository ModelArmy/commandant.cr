# Known issues

> **Not yet released** — API is not stable; breaking changes expected as implementation matures. All known issues that gate the first release are identified here, and will checked off as completed.

- [ ] **POSIX parser combined-flag heuristic is approximate** — flags are split into individual characters only when the token is ≤ 4 chars total and all-alpha (e.g. `-rf`, `-la`). Longer all-alpha tokens are treated as single word flags (`-exec`, `-name`). Edge cases exist: `-lash` would be treated as a word flag rather than combined `-l -a -s -h`. A proper solution requires a per-tool flag registry, which is deferred.
- [ ] **Compound command constraint checking is shallow** — the `ConstraintChecker` recurses into `ParsedCommand#compounds` but subshell contents in `ParsedCommand#subshells` are not assessed; commands embedded in `$(...)` are extracted as strings but not parsed and evaluated.
- [ ] **No Windows platform or CMD/PowerShell parser** — `Platform::Windows` and `Parser::Cmd`/`Parser::PowerShell` are designed but not yet implemented.
- [ ] **`raw_pattern` in `MatchSpec` compiles a new `Regex` on every evaluation** — no caching; acceptable for now given hot-path frequency but worth addressing before any performance benchmarking.
- [ ] **Lint warnings** - Fix to address all lint warnings before release.
