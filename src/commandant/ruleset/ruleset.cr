require "json"

module Commandant
  # A minimal default rule — applies when no specific rule matches.
  record DefaultRule,
    risk_tags : Array(RiskTag),
    reversible : Reversibility,
    severity : Severity

  # A loaded ruleset for a single tool on a single platform.
  class Ruleset
    getter tool : String
    getter platform : String
    getter tool_summary : String
    getter rules : Array(Rule)
    getter default_rule : DefaultRule
    getter? is_multiplexer : Bool
    getter option_abbreviations : Hash(String, String)
    getter llm_confidence : String
    getter unknown_flags : Array(String)
    getter platform_notes : String?

    def initialize(
      @tool : String,
      @platform : String,
      @tool_summary : String,
      @rules : Array(Rule),
      @default_rule : DefaultRule,
      @is_multiplexer : Bool = false,
      @option_abbreviations : Hash(String, String) = {} of String => String,
      @llm_confidence : String = "high",
      @unknown_flags : Array(String) = [] of String,
      @platform_notes : String? = nil,
    )
    end

    # Loads a Ruleset from a JSON file path.
    def self.from_file(path : Path | String) : Ruleset
      from_json(File.read(path.to_s))
    end

    # Loads a Ruleset from a JSON string.
    def self.from_json(json : String) : Ruleset
      pull = JSON::PullParser.new(json)
      from_pull(pull)
    end

    private def self.from_pull(pull : JSON::PullParser) : Ruleset
      tool = ""
      platform = ""
      tool_summary = ""
      rules = [] of Rule
      default_rule = nil
      is_multiplexer = false
      option_abbreviations = {} of String => String
      llm_confidence = "high"
      unknown_flags = [] of String
      platform_notes = nil

      pull.read_object do |key|
        case key
        when "tool"           then tool = pull.read_string
        when "platform"       then platform = pull.read_string
        when "tool_summary"   then tool_summary = pull.read_string
        when "llm_confidence" then llm_confidence = pull.read_string
        when "platform_notes" then platform_notes = pull.read_string
        when "is_multiplexer" then is_multiplexer = pull.read_bool
        when "unknown_flags"
          pull.read_array { unknown_flags << pull.read_string }
        when "option_abbreviations"
          pull.read_object { |k| option_abbreviations[k] = pull.read_string }
        when "rules"
          pull.read_array { rules << Rule.from_json(pull) }
        when "default_rule"
          default_rule = parse_default_rule(pull)
        else pull.skip
        end
      end

      raise ArgumentError.new("Ruleset missing 'default_rule'") unless default_rule

      new(tool, platform, tool_summary, rules, default_rule,
        is_multiplexer, option_abbreviations, llm_confidence,
        unknown_flags, platform_notes)
    end

    private def self.parse_default_rule(pull : JSON::PullParser) : DefaultRule
      risk_tags = [] of RiskTag
      reversible = Reversibility::Yes
      severity = Severity::Info

      pull.read_object do |key|
        case key
        when "risk_tags"
          pull.read_array { risk_tags << RiskTag.from_json_string(pull.read_string) }
        when "reversible" then reversible = Reversibility.from_json_string(pull.read_string)
        when "severity"   then severity = Severity.from_json_string(pull.read_string)
        else                   pull.skip
        end
      end

      DefaultRule.new(risk_tags, reversible, severity)
    end
  end
end
