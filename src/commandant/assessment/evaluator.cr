require "json"

module Commandant
  # A matched rule result — which rule fired and which pattern matched.
  record MatchedRule,
    rule_id : String,
    ruleset_tool : String,
    matched_pattern : String? do
    include JSON::Serializable
  end

  # Evaluates a parsed command against a ruleset, returning all rules that fired.
  #
  # Rules are evaluated top-to-bottom. All matching rules are returned —
  # the caller (Assessor) unions the risk tags across all matches.
  class Evaluator
    # Evaluates `cmd` against `ruleset`.
    # Returns the list of rules that matched, plus the default rule if none matched.
    def evaluate(cmd : ParsedCommand, ruleset : Ruleset) : {Array(MatchedRule), Bool}
      matched = [] of MatchedRule
      used_default = false

      ruleset.rules.each do |rule|
        if rule.matches?(cmd)
          firing_pattern = rule.patterns.find(&.match.matches?(cmd))
          matched << MatchedRule.new(
            rule_id: rule.id,
            ruleset_tool: ruleset.tool,
            matched_pattern: firing_pattern.try(&.pattern)
          )
        end
      end

      if matched.empty?
        used_default = true
      end

      {matched, used_default}
    end

    # Unions risk tags from a set of matched rules.
    # Falls back to the default rule's tags if no rules matched.
    def union_risk_tags(
      matched : Array(MatchedRule),
      ruleset : Ruleset,
      used_default : Bool,
    ) : Array(RiskTag)
      if used_default
        return ruleset.default_rule.risk_tags.dup
      end

      tags = [] of RiskTag
      matched.each do |matched_rule|
        if found = ruleset.rules.find { |rule| rule.id == matched_rule.rule_id }
          tags.concat(found.risk_tags)
        end
      end
      tags.uniq
    end

    # Returns the highest severity across matched rules.
    def max_severity(matched : Array(MatchedRule), ruleset : Ruleset, used_default : Bool) : Severity
      return ruleset.default_rule.severity if used_default

      matched.map do |matched_rule|
        ruleset.rules.find { |rule| rule.id == matched_rule.rule_id }.try(&.severity) || Severity::Info
      end.max_by?(&.value) || Severity::Info
    end

    # Returns the most conservative reversibility across matched rules.
    # "no" > "depends" > "yes"
    def min_reversibility(matched : Array(MatchedRule), ruleset : Ruleset, used_default : Bool) : Reversibility
      return ruleset.default_rule.reversible if used_default

      values = matched.map do |matched_rule|
        ruleset.rules.find { |rule| rule.id == matched_rule.rule_id }.try(&.reversible) || Reversibility::Yes
      end

      return Reversibility::No if values.includes?(Reversibility::No)
      return Reversibility::Depends if values.includes?(Reversibility::Depends)
      Reversibility::Yes
    end

    # Unions likely_consequences across matched rules.
    def union_consequences(matched : Array(MatchedRule), ruleset : Ruleset) : Array(String)
      consequences = [] of String
      matched.each do |matched_rule|
        if found = ruleset.rules.find { |rule| rule.id == matched_rule.rule_id }
          consequences.concat(found.likely_consequences)
        end
      end
      consequences.uniq
    end
  end
end
