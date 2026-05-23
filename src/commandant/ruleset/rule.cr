require "json"

module Commandant
  # Intrinsic risk categories — what a command does.
  # These are stable across all deployment contexts.
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
      case s
      when "reads-files"          then ReadsFiles
      when "writes-files"         then WritesFiles
      when "deletes-files"        then DeletesFiles
      when "recursive"            then Recursive
      when "irreversible"         then Irreversible
      when "executes-code"        then ExecutesCode
      when "network-egress"       then NetworkEgress
      when "elevated-privilege"   then ElevatedPrivilege
      when "modifies-environment" then ModifiesEnvironment
      when "subshell"             then Subshell
      else                             raise ArgumentError.new("Unknown risk tag: #{s}")
      end
    end

    def to_s : String
      case self
      when ReadsFiles          then "reads-files"
      when WritesFiles         then "writes-files"
      when DeletesFiles        then "deletes-files"
      when Recursive           then "recursive"
      when Irreversible        then "irreversible"
      when ExecutesCode        then "executes-code"
      when NetworkEgress       then "network-egress"
      when ElevatedPrivilege   then "elevated-privilege"
      when ModifiesEnvironment then "modifies-environment"
      when Subshell            then "subshell"
      else                          super
      end
    end

    # Returns true if this tag is non-bypassable — always forces ESCALATE or DENY.
    def non_bypassable? : Bool
      self == ExecutesCode || self == Irreversible
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
  end

  # A single pattern within a rule, pairing the Semgrep string (offline)
  # with a MatchSpec (runtime).
  record RulePattern,
    pattern : String,
    pattern_type : String,
    example : String,
    match : MatchSpec

  # A single rule within a ruleset.
  class Rule
    getter id : String
    getter description : String
    getter patterns : Array(RulePattern)
    getter risk_tags : Array(RiskTag)
    getter reversible : Reversibility
    getter severity : Severity
    getter? all_match : Bool
    getter reversible_note : String?
    getter notes : String?
    getter likely_consequences : Array(String)

    def initialize(
      @id : String,
      @description : String,
      @patterns : Array(RulePattern),
      @risk_tags : Array(RiskTag),
      @reversible : Reversibility,
      @severity : Severity,
      @all_match : Bool = false,
      @reversible_note : String? = nil,
      @notes : String? = nil,
      @likely_consequences : Array(String) = [] of String,
    )
    end

    # Returns true if this rule fires against the given parsed command.
    # `all_match: true` requires ALL patterns to match (AND).
    # `all_match: false` (default) requires ANY pattern to match (OR).
    def matches?(cmd : ParsedCommand) : Bool
      if all_match?
        patterns.all?(&.match.matches?(cmd))
      else
        patterns.any?(&.match.matches?(cmd))
      end
    end

    # Deserialises a Rule from a JSON::PullParser.
    def self.from_json(pull : JSON::PullParser) : Rule
      id = ""
      description = ""
      patterns = [] of RulePattern
      risk_tags = [] of RiskTag
      reversible = Reversibility::Yes
      severity = Severity::Info
      all_match = false
      reversible_note = nil
      notes = nil
      likely_consequences = [] of String

      pull.read_object do |key|
        case key
        when "id"          then id = pull.read_string
        when "description" then description = pull.read_string
        when "patterns"
          pull.read_array { patterns << parse_pattern(pull) }
        when "risk_tags"
          pull.read_array { risk_tags << RiskTag.from_json_string(pull.read_string) }
        when "reversible"      then reversible = Reversibility.from_json_string(pull.read_string)
        when "severity"        then severity = Severity.from_json_string(pull.read_string)
        when "all_match"       then all_match = pull.read_bool
        when "reversible_note" then reversible_note = pull.read_string
        when "notes"           then notes = pull.read_string
        when "likely_consequences"
          pull.read_array { likely_consequences << pull.read_string }
        else pull.skip
        end
      end

      new(id, description, patterns, risk_tags, reversible, severity,
        all_match, reversible_note, notes, likely_consequences)
    end

    private def self.parse_pattern(pull : JSON::PullParser) : RulePattern
      pattern = ""
      pattern_type = ""
      example = ""
      match = MatchSpec.new

      pull.read_object do |key|
        case key
        when "pattern"      then pattern = pull.read_string
        when "pattern_type" then pattern_type = pull.read_string
        when "example"      then example = pull.read_string
        when "match"        then match = MatchSpec.from_json(pull)
        else                     pull.skip
        end
      end

      RulePattern.new(pattern, pattern_type, example, match)
    end
  end
end
