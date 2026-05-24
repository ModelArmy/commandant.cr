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

      # return false if !flags_any.empty? && !flags_any.any? { |flag| canonicals.includes?(flag) }
      # return false if !flags_all.empty? && !flags_all.all? { |flag| canonicals.includes?(flag) }
      # return false if !flags_none.empty? && flags_none.any? { |flag| canonicals.includes?(flag) }
      # return false if !args_any.empty? && !args_any.any? { |arg| cmd.arguments.includes?(arg) }
      # return false if !args_none.empty? && args_none.any? { |arg| cmd.arguments.includes?(arg) }

      return false if flags_and_args_dont_match_any?(canonicals, cmd)

      if pat = raw_pattern
        return false unless cmd.raw.matches?(Regex.new(pat))
      end

      true
    end

    private def flags_and_args_dont_match_any?(canonicals, cmd)
      (!flags_any.empty? && !flags_any.any? { |flag| canonicals.includes?(flag) }) ||
        (!flags_all.empty? && !flags_all.all? { |flag| canonicals.includes?(flag) }) ||
        (!flags_none.empty? && flags_none.any? { |flag| canonicals.includes?(flag) }) ||
        (!args_any.empty? && !args_any.any? { |arg| cmd.arguments.includes?(arg) }) ||
        (!args_none.empty? && args_none.any? { |arg| cmd.arguments.includes?(arg) })
    end
  end
end
