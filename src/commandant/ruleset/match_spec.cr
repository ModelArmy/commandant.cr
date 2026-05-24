require "json"

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
    flags_none : Array(String) = [] of String,
    args_any : Array(String) = [] of String,
    args_none : Array(String) = [] of String,
    raw_pattern : String? = nil do
    include JSON::Serializable

    # Evaluates this match spec against a parsed command.
    # Returns true if all present criteria are satisfied.
    def matches?(cmd : ParsedCommand) : Bool
      canonicals = cmd.flag_canonicals

      return false if !flags_any.empty? && !flags_any.any? { |f| canonicals.includes?(f) }
      return false if !flags_all.empty? && !flags_all.all? { |f| canonicals.includes?(f) }
      return false if !flags_none.empty? && flags_none.any? { |f| canonicals.includes?(f) }
      return false if !args_any.empty? && !args_any.any? { |a| cmd.arguments.includes?(a) }
      return false if !args_none.empty? && args_none.any? { |a| cmd.arguments.includes?(a) }

      if pat = raw_pattern
        return false unless cmd.raw.matches?(Regex.new(pat))
      end

      true
    end
  end
end
