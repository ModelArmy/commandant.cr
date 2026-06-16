# Known issues

> **Release** — API is stable. Remaining issues are manageable.

- [ ] **POSIX parser combined-flag heuristic is approximate** — flags are split into individual characters only when the token is ≤ 4 chars total and all-alpha (e.g. `-rf`, `-la`). Longer all-alpha tokens are treated as single word flags (`-exec`, `-name`). Edge cases exist: `-lash` would be treated as a word flag rather than combined `-l -a -s -h`. A proper solution requires a per-tool flag registry, which is deferred.
- [ ] **`raw_pattern` in `MatchSpec` compiles a new `Regex` on every evaluation** — no caching; acceptable for now given hot-path frequency but worth addressing before any performance benchmarking.
- [x] **Line continuation detection** - detect and handle line-breaks in commands
- [x] **Missing usage in `README.md`**
- [x] **No Windows platform or CMD/PowerShell parser** — `Platform::Windows` and `Parser::Cmd`/`Parser::PowerShell` are designed but not yet implemented.
- [x] **Missing `DEVELOPMENT.md`**
- [x] **Compound command constraint checking is shallow** — the `ConstraintChecker` recurses into `ParsedCommand#compounds` but subshell contents in `ParsedCommand#subshells` are not assessed; commands embedded in `$(...)` are extracted as strings but not parsed and evaluated.
- [x] **Unsure about the assessment for arbitrary command line combos** - Add property-based invariant tests that generate random command strings from a grammar covering the interesting variation space and assert structural invariants on every response
- [x] **Lint warnings** - Fix to address all lint warnings before release.
