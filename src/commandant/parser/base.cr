module Commandant
  module Parser
    # Abstract base for all platform-specific command parsers.
    #
    # Parsers are responsible for tokenisation only — extracting binary,
    # flags, arguments, compound commands, and subshell contents.
    # They do not evaluate risk or apply policy.
    #
    # Flag prefixes are preserved exactly as written. Platform-neutrality
    # is in the struct shape, not the values — a `/S` flag from a CMD parser
    # and a `-r` flag from a POSIX parser are both stored as-is.
    abstract class Base
      # Parses a raw command string into a `ParsedCommand`.
      abstract def parse(raw : String) : ParsedCommand

      # Expands a flag string using the ruleset's option abbreviations map.
      # Returns the canonical form, or the original string if not found.
      protected def expand_abbreviation(flag : String, abbreviations : Hash(String, String)) : String
        abbreviations[flag]? || flag
      end
    end
  end
end
