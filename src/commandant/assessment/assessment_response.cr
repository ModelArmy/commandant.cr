require "json"

require "../bundle/*"

module Commandant
  # The decision outcome of an assessment.
  enum Decision
    # Command is safe under configured policy — no confirmation needed.
    Allow
    # Present to user for confirmation (OAP ESCALATE).
    Escalate
    # Hard block — non-bypassable tag triggered or fail-closed condition.
    Deny
  end

  # Overall risk level derived from the assessment.
  enum OverallRisk
    Low
    Medium
    High
    Critical
  end

  # The structured payload returned by `Assessor#assess`.
  #
  # This is the OAP ESCALATE evidence record for shell commands.
  # The host application controls presentation — this struct provides
  # all data needed to render a confirmation table or make an auto-approve
  # decision.
  class AssessmentResponse
    include JSON::Serializable

    getter command : ParsedCommand
    getter decision : Decision
    getter risk_tags : Array(RiskTag)
    getter likely_consequences : Array(String)
    getter severity : Severity
    getter overall_risk : OverallRisk
    getter reversible : Reversibility
    getter constraint_violations : Array(ConstraintViolation)
    getter non_bypassable_tags : Array(RiskTag)
    getter matched_rules : Array(MatchedRule)
    getter persistence_signal : PersistenceSignal?
    getter? tool_known : Bool
    getter ruleset_version : String
    getter assessment_latency_ms : Float64
    # MITRE ATT&CK technique IDs unioned across all matched rules.
    # nil means no rule in the matched ruleset had the mitre_attack field
    # (pre-backfill rulesets). [] means evaluated with no applicable technique.
    getter mitre_attack : Array(String)?
    # The level of checksum verification performed on the ruleset source.
    # None when using the directory-based loader or no checksum was provided.
    getter ruleset_verification : RulesetVerification

    def initialize(
      @command : ParsedCommand,
      @decision : Decision,
      @risk_tags : Array(RiskTag),
      @likely_consequences : Array(String),
      @severity : Severity,
      @overall_risk : OverallRisk,
      @reversible : Reversibility,
      @constraint_violations : Array(ConstraintViolation),
      @non_bypassable_tags : Array(RiskTag),
      @matched_rules : Array(MatchedRule),
      @persistence_signal : PersistenceSignal?,
      @tool_known : Bool,
      @ruleset_version : String,
      @assessment_latency_ms : Float64,
      @mitre_attack : Array(String)?,
      @ruleset_verification : RulesetVerification,
    )
    end

    # Returns true if the decision is ALLOW.
    def allow? : Bool
      decision == Decision::Allow
    end

    # Returns true if the decision is ESCALATE.
    def escalate? : Bool
      decision == Decision::Escalate
    end

    # Returns true if the decision is DENY.
    def deny? : Bool
      decision == Decision::Deny
    end

    # Returns true if the command is safe to run in a read-only context.
    #
    # All three conditions must hold:
    # - decision is Allow
    # - mitre_attack is [] (evaluated with no applicable technique; nil means
    #   pre-backfill/unknown and is treated as unsafe)
    # - no matched rule introduced a write-side risk tag
    #
    # Note: Recursive is intentionally excluded from the write-side set —
    # a recursive read (e.g. `grep -r`) is still read-only.
    def readonly? : Bool
      return false unless allow?
      return false unless mitre_attack == [] of String

      WRITE_SIDE_TAGS.none? { |tag| risk_tags.includes?(tag) }
    end

    private WRITE_SIDE_TAGS = {
      RiskTag::WritesFiles,
      RiskTag::DeletesFiles,
      RiskTag::ExecutesCode,
      RiskTag::NetworkEgress,
      RiskTag::ElevatedPrivilege,
      RiskTag::ModifiesEnvironment,
      RiskTag::Subshell,
      RiskTag::Irreversible,
    }
  end
end
