module Commandant
  # The primary API entry point for commandant.
  #
  # Orchestrates parsing, ruleset evaluation, constraint checking,
  # and persistence tracking to produce a structured `AssessmentResponse`.
  #
  # Usage:
  # ```
  # assessor = Commandant::Assessor.new(
  #   ruleset_path: Path["./rulesets"],
  #   sandbox_root: Path["/home/user/project"],
  #   allowed_tools: %w[find grep sed cat ls]
  # )
  #
  # response = assessor.assess("find . -exec rm {} \\;")
  # ```
  class Assessor
    RULESET_VERSION = "0.1.0"

    getter platform : Platform::Base
    getter ruleset_store : RulesetStore
    getter constraint_checker : ConstraintChecker
    getter parser : Parser::Base
    getter persistence_tracker : PersistenceTracker

    @evaluator : Evaluator

    def initialize(
      ruleset_path : Path,
      sandbox_root : Path,
      allowed_tools : Array(String),
      platform : Platform::Base = Platform.default,
      parser : Parser::Base? = nil,
    )
      @platform = platform
      @parser = parser || platform.default_parser
      @ruleset_store = RulesetStore.new(
        base_path: ruleset_path,
        platform: platform.ruleset_folder
      )
      @constraint_checker = ConstraintChecker.new(
        sandbox_root: sandbox_root,
        allowed_tools: allowed_tools
      )
      @persistence_tracker = PersistenceTracker.new
      @evaluator = Evaluator.new
    end

    # Assesses a raw command string and returns a structured response.
    #
    # This is the hot path. For known tools with committed rulesets,
    # no external processes or LLM calls are made.
    def assess(raw : String) : AssessmentResponse
      start_time = Time.instant

      cmd = @parser.parse(raw)

      tool_known = @ruleset_store.known?(cmd.binary)

      # Fail-closed: unknown tools always escalate
      unless tool_known
        latency = (Time.instant - start_time).total_milliseconds
        response = unknown_tool_response(cmd, latency)
        # Record for persistence tracking even for unknown tools —
        # repeated attempts at blocked capabilities should surface a signal.
        @persistence_tracker.record_blocked([RiskTag::ExecutesCode])
        return response
      end

      ruleset = @ruleset_store.load(cmd.binary) ||
                raise "Ruleset for '#{cmd.binary}' was found during lookup but could not be loaded"

      # Expand abbreviations using the ruleset's option_abbreviations
      expanded_cmd = expand_abbreviations(cmd, ruleset)

      # Evaluate against ruleset
      matched, used_default = @evaluator.evaluate(expanded_cmd, ruleset)

      risk_tags = @evaluator.union_risk_tags(matched, ruleset, used_default)
      severity = @evaluator.max_severity(matched, ruleset, used_default)
      reversible = @evaluator.min_reversibility(matched, ruleset, used_default)
      consequences = @evaluator.union_consequences(matched, ruleset)

      # Union risk from compound commands — a compound like `ls . && rm -rf /`
      # should surface rm's risk tags alongside ls's.
      expanded_cmd.compounds.each do |compound|
        compound_ruleset = @ruleset_store.load(compound.binary)
        next unless compound_ruleset

        compound_expanded = expand_abbreviations(compound, compound_ruleset)
        compound_matched, compound_default = @evaluator.evaluate(compound_expanded, compound_ruleset)
        risk_tags = (risk_tags + @evaluator.union_risk_tags(compound_matched, compound_ruleset, compound_default)).uniq
        compound_severity = @evaluator.max_severity(compound_matched, compound_ruleset, compound_default)
        severity = compound_severity if compound_severity.value > severity.value
        compound_reversible = @evaluator.min_reversibility(compound_matched, compound_ruleset, compound_default)
        reversible = compound_reversible if compound_reversible.value > reversible.value
        consequences = (consequences + @evaluator.union_consequences(compound_matched, compound_ruleset)).uniq
      end

      # Runtime constraint evaluation
      violations = @constraint_checker.check(expanded_cmd)

      # Non-bypassable tags
      non_bypassable = risk_tags.select(&.non_bypassable?)
      non_bypassable << RiskTag::Irreversible if reversible == Reversibility::No
      non_bypassable.concat(
        violations.compact_map { |violation| violation.constraint == "escapes-sandbox" ? RiskTag::ExecutesCode : nil }
      )
      non_bypassable = non_bypassable.uniq

      # Decision
      decision = derive_decision(non_bypassable, violations, tool_known)

      # Record blocked assessments before checking the signal — the signal
      # threshold is >= 2, so we record the current attempt first, then check.
      # This means the signal fires on the second blocked attempt, not the third.
      if decision.escalate? || decision.deny?
        @persistence_tracker.record_blocked(risk_tags)
      end

      # Persistence signal — checked after recording so current attempt counts
      signal = @persistence_tracker.signal_for(risk_tags)

      overall_risk = derive_overall_risk(decision, severity, risk_tags, reversible)

      matched_rules = matched.map do |matched_rule|
        MatchedRule.new(
          rule_id: matched_rule.rule_id,
          ruleset_tool: matched_rule.ruleset_tool,
          matched_pattern: matched_rule.matched_pattern
        )
      end

      latency = (Time.instant - start_time).total_milliseconds

      AssessmentResponse.new(
        command: expanded_cmd,
        decision: decision,
        risk_tags: risk_tags,
        likely_consequences: consequences,
        severity: severity,
        overall_risk: overall_risk,
        reversible: reversible,
        constraint_violations: violations,
        non_bypassable_tags: non_bypassable,
        matched_rules: matched_rules,
        persistence_signal: signal,
        tool_known: true,
        ruleset_version: RULESET_VERSION,
        assessment_latency_ms: latency
      )
    end

    private def expand_abbreviations(cmd : ParsedCommand, ruleset : Ruleset) : ParsedCommand
      return cmd if ruleset.option_abbreviations.empty?

      expanded_flags = cmd.flags.map do |flag|
        canonical = ruleset.option_abbreviations[flag.raw]?
        if canonical
          Flag.new(raw: flag.raw, canonical: canonical, abbreviated: true)
        else
          flag
        end
      end

      ParsedCommand.new(
        raw: cmd.raw,
        binary: cmd.binary,
        flags: expanded_flags,
        arguments: cmd.arguments,
        binary_raw: cmd.binary_raw,
        compounds: cmd.compounds,
        subshells: cmd.subshells
      )
    end

    private def derive_decision(
      non_bypassable : Array(RiskTag),
      violations : Array(ConstraintViolation),
      tool_known : Bool,
    ) : Decision
      # DENY: escapes-sandbox is a hard block
      return Decision::Deny if violations.any? { |violation| violation.constraint == "escapes-sandbox" }

      # ESCALATE: any non-bypassable tag or constraint violation
      return Decision::Escalate unless non_bypassable.empty?
      return Decision::Escalate unless violations.empty?

      Decision::Allow
    end

    private def derive_overall_risk(
      decision : Decision,
      severity : Severity,
      risk_tags : Array(RiskTag),
      reversible : Reversibility,
    ) : OverallRisk
      return OverallRisk::Critical if decision.deny?
      return OverallRisk::High if severity == Severity::Error
      return OverallRisk::High if risk_tags.includes?(RiskTag::Irreversible) && risk_tags.includes?(RiskTag::Recursive)
      return OverallRisk::Medium if severity == Severity::Warning
      OverallRisk::Low
    end

    private def unknown_tool_response(cmd : ParsedCommand, latency : Float64) : AssessmentResponse
      AssessmentResponse.new(
        command: cmd,
        decision: Decision::Escalate,
        risk_tags: [] of RiskTag,
        likely_consequences: [] of String,
        severity: Severity::Warning,
        overall_risk: OverallRisk::Medium,
        reversible: Reversibility::Depends,
        constraint_violations: [] of ConstraintViolation,
        non_bypassable_tags: [] of RiskTag,
        matched_rules: [] of MatchedRule,
        persistence_signal: nil,
        tool_known: false,
        ruleset_version: RULESET_VERSION,
        assessment_latency_ms: latency
      )
    end
  end
end
