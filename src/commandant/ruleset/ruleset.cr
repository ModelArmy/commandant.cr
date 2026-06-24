require "json"

module Commandant
  # A minimal default rule — applies when no specific rule matches.
  class DefaultRule
    include JSON::Serializable

    getter risk_tags : Array(RiskTag)
    getter reversible : Reversibility
    getter severity : Severity
    # MITRE ATT&CK technique IDs for the default (no-flag) invocation.
    # nil means the field was absent (pre-backfill); [] means evaluated with no applicable technique.
    getter mitre_attack : Array(String)?
  end

  # A loaded ruleset for a single tool on a single platform.
  class Ruleset
    include JSON::Serializable

    getter tool : String
    getter platform : String
    getter tool_summary : String
    getter rules : Array(Rule)
    getter default_rule : DefaultRule

    @[JSON::Field(key: "is_multiplexer")]
    getter? is_multiplexer : Bool = false

    getter option_abbreviations : Hash(String, String) = {} of String => String
    getter llm_confidence : String = "high"
    getter unknown_flags : Array(String) = [] of String
    getter platform_notes : String?

    # Loads a Ruleset from a JSON file path.
    def self.from_file(path : Path | String) : Ruleset
      from_json(File.read(path.to_s))
    end
  end
end
