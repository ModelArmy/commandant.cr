module Commandant
  # The runtime-evaluable form of a pattern's match criteria.
  #
  # All string values are matched as **exact strings**, not regex.
  # Use `raw_pattern` for regex matching against the raw command string.
  #
  # At least one field must be populated (enforced by schema `minProperties: 1`).
  record MatchSpec,
    flags_any : Array(String) = [] of String,
    flags_all : Array(String) = [] of String,
    args_any : Array(String) = [] of String,
    args_none : Array(String) = [] of String,
    raw_pattern : String? = nil do
    # Evaluates this match spec against a parsed command.
    # Returns true if all present criteria are satisfied.
    def matches?(cmd : ParsedCommand) : Bool
      canonicals = cmd.flag_canonicals

      return false if !flags_any.empty? && !flags_any.any? { |f| canonicals.includes?(f) }
      return false if !flags_all.empty? && !flags_all.all? { |f| canonicals.includes?(f) }
      return false if !args_any.empty? && !args_any.any? { |a| cmd.arguments.includes?(a) }
      return false if !args_none.empty? && args_none.any? { |a| cmd.arguments.includes?(a) }

      if pat = raw_pattern
        return false unless cmd.raw.matches?(Regex.new(pat))
      end

      true
    end

    # Deserialises from a JSON::PullParser positioned at the match object.
    def self.from_json(pull : JSON::PullParser) : MatchSpec
      flags_any = [] of String
      flags_all = [] of String
      args_any = [] of String
      args_none = [] of String
      raw_pattern = nil

      pull.read_object do |key|
        case key
        when "flags_any"   then flags_any = Array(String).new(pull)
        when "flags_all"   then flags_all = Array(String).new(pull)
        when "args_any"    then args_any = Array(String).new(pull)
        when "args_none"   then args_none = Array(String).new(pull)
        when "raw_pattern" then raw_pattern = pull.read_string
        else                    pull.skip
        end
      end

      new(flags_any: flags_any, flags_all: flags_all,
        args_any: args_any, args_none: args_none,
        raw_pattern: raw_pattern)
    end
  end
end
