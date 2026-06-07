require "json"

module Commandant
  # Intrinsic risk categories — what a command does.
  enum RiskTag
    ReadsFiles
    WritesFiles
    DeletesFiles
    Recursive
    Irreversible
    ExecutesCode
    NetworkEgress
    ElevatedPrivilege
    ModifiesEnvironment
    Subshell

    def self.from_json_string(s : String) : RiskTag
      # `Enum.parse` treats `-` and `_` identically when parsing strings to match enum names, so:
      parse(s)
    end

    # Hyphenated lower case risk names
    def to_s : String
      super.underscore.gsub('_', '-')
    end

    # Returns true if this tag is non-bypassable — always forces ESCALATE or DENY.
    def non_bypassable? : Bool
      self == ExecutesCode || self == Irreversible
    end

    def self.from_json(pull : JSON::PullParser) : RiskTag
      RiskTag.from_json_string(pull.read_string)
    end

    def self.to_json(value : RiskTag, json : JSON::Builder)
      json.string(value.to_s)
    end
  end

  enum Severity
    Info
    Warning
    Error

    def self.from_json_string(s : String) : Severity
      case s
      when "INFO"    then Info
      when "WARNING" then Warning
      when "ERROR"   then Error
      else                raise ArgumentError.new("Unknown severity: #{s}")
      end
    end

    def to_s : String
      case self
      when Info    then "INFO"
      when Warning then "WARNING"
      when Error   then "ERROR"
      else              super
      end
    end

    def self.from_json(pull : JSON::PullParser) : Severity
      Severity.from_json_string(pull.read_string)
    end

    def self.to_json(value : Severity, json : JSON::Builder)
      json.string(value.to_s)
    end
  end

  enum Reversibility
    Yes
    No
    Depends

    def self.from_json_string(s : String) : Reversibility
      case s
      when "yes"     then Yes
      when "no"      then No
      when "depends" then Depends
      else                raise ArgumentError.new("Unknown reversibility: #{s}")
      end
    end

    def to_s : String
      case self
      when Yes     then "yes"
      when No      then "no"
      when Depends then "depends"
      else              super
      end
    end

    def self.from_json(pull : JSON::PullParser) : Reversibility
      Reversibility.from_json_string(pull.read_string)
    end

    def self.to_json(value : Reversibility, json : JSON::Builder)
      json.string(value.to_s)
    end
  end

  # A single pattern within a rule, pairing the Semgrep string (offline)
  # with a MatchSpec (runtime).
  record RulePattern,
    pattern : String,
    pattern_type : String,
    example : String,
    match : MatchSpec do
    include JSON::Serializable
  end

  # A single rule within a ruleset.
  class Rule
    include JSON::Serializable

    getter id : String
    getter description : String
    getter patterns : Array(RulePattern)

    getter risk_tags : Array(RiskTag)
    getter reversible : Reversibility
    getter severity : Severity

    @[JSON::Field(key: "all_match")]
    getter? all_match : Bool = false

    getter reversible_note : String?
    getter notes : String?
    getter likely_consequences : Array(String) = [] of String

    # MITRE ATT&CK technique IDs applicable to this rule.
    # nil means the field was absent from the ruleset (pre-mitre_attack rulesets).
    # [] means the field was present but no technique was identified.
    getter mitre_attack : Array(String)?

    # Returns true if this rule fires against the given parsed command.
    def matches?(cmd : ParsedCommand) : Bool
      if all_match?
        patterns.all?(&.match.matches?(cmd))
      else
        patterns.any?(&.match.matches?(cmd))
      end
    end
  end
end
