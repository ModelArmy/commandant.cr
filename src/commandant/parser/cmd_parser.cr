module Commandant
  module Parser
    # Parses cmd.exe command strings (Windows Command Prompt).
    #
    # Handles:
    # - Flags: `/FLAG`, `/FLAG:VALUE`
    # - Escape character: `^` (caret escapes the next character)
    # - Compound commands: `&`, `&&`, `||`, `|` (pipe)
    # - Environment variables: `%VAR%` (extracted as subshell-like content)
    # - Quoted arguments: double-quoted strings only (no single-quote quoting)
    #
    # Flag canonicals are uppercased so rulesets can use consistent uppercase
    # values in `flags_any` (e.g. `/C`, `/S`, `/P`).
    class CmdParser < Base
      # Parses a cmd.exe command string into a `ParsedCommand`.
      #
      # Example flow for `forfiles /P . /S /M *.log /C "cmd /c del @file"`:
      #
      #   1. extract_subshells → ["PATH"] (if %PATH% present; none here)
      #   2. split_compounds   → ["forfiles /P . /S /M *.log /C \"cmd /c del @file\""]
      #                           (no compound operators)
      #   3. tokenise          → ["forfiles", "/P", ".", "/S", "/M", "*.log",
      #                           "/C", "cmd /c del @file"]
      #                           (double-quoted string content preserved, quotes stripped)
      #   4. binary            = "forfiles"
      #   5. flags             = [Flag("/P" → "/P"), Flag("/S" → "/S"),
      #                           Flag("/M" → "/M"), Flag("/C" → "/C")]
      #   6. arguments         = [".", "*.log", "cmd /c del @file"]
      def parse(raw : String) : ParsedCommand
        return ParsedCommand.new(raw: raw, binary: "", flags: [] of Flag, arguments: [] of String) if raw.strip.empty?

        subshells = extract_subshells(raw)
        parts = split_compounds(raw)

        return ParsedCommand.new(raw: raw, binary: "", flags: [] of Flag, arguments: [] of String) if parts.empty?

        primary_raw = parts.first
        compound_raws = parts[1..]

        tokens = tokenise(primary_raw)
        return ParsedCommand.new(raw: raw, binary: "", flags: [] of Flag, arguments: [] of String) if tokens.empty?

        binary = tokens.first
        flags = [] of Flag
        arguments = [] of String

        i = 1
        while i < tokens.size
          token = tokens[i]
          if token.starts_with?("/")
            # `/FLAG` or `/FLAG:VALUE` — colon separates flag from its value.
            # `/C "cmd /c del @file"` → Flag("/C"), argument already tokenised
            # `/FLAG:VALUE`           → Flag("/FLAG"), argument "VALUE"
            # Canonical is uppercased: `/s` → stored as "/S" for ruleset matching.
            if colon = token.index(':', 1)
              flag_part = token[0...colon]
              value_part = token[(colon + 1)..]
              flags << Flag.new(raw: flag_part, canonical: flag_part.upcase)
              arguments << value_part unless value_part.empty?
            else
              flags << Flag.new(raw: token, canonical: token.upcase)
            end
          else
            arguments << token
          end
          i += 1
        end

        compounds = compound_raws.map { |raw_cmd| parse(raw_cmd) }

        ParsedCommand.new(
          raw: raw,
          binary: binary,
          flags: flags,
          arguments: arguments,
          compounds: compounds,
          subshells: subshells
        )
      end

      private def tokenise(raw : String) : Array(String)
        # Splits the command string into tokens by whitespace, respecting
        # cmd.exe quoting and caret escaping.
        #
        # Examples:
        #   "forfiles /S /P ."            → ["forfiles", "/S", "/P", "."]
        #   "forfiles /C \"cmd /c del\""  → ["forfiles", "/C", "cmd /c del"]
        #   "echo hello^&world"           → ["echo", "hello&world"]
        #
        # cmd.exe quoting rules:
        # - Double quotes: everything inside is one token; quotes stripped.
        #   `"cmd /c del @file"` → "cmd /c del @file" as a single argument.
        # - No single-quote quoting in cmd.exe.
        # - Caret `^`: escapes the next character, making it literal.
        #   `^&` → literal `&` (not a compound operator).
        #   `^ ` → literal space inside a token.
        tokens = [] of String
        current = String::Builder.new
        in_double = false
        i = 0

        while i < raw.size
          char = raw[i]
          case char
          when '^'
            # Caret escapes the next character — consume `^`, include next char literally.
            # `echo hello^&world` → `^&` becomes `&` in the token, not a separator.
            if !in_double && i + 1 < raw.size
              i += 1
              current << raw[i]
            else
              current << char
            end
          when '"'
            # Toggle double-quote mode. Quote char itself is not added to token.
            in_double = !in_double
          when ' ', '\t'
            if in_double
              # Space inside double quotes is part of the token.
              current << char
            else
              token = current.to_s
              tokens << token unless token.empty?
              current = String::Builder.new
            end
          else
            current << char
          end
          i += 1
        end

        token = current.to_s
        tokens << token unless token.empty?
        tokens
      end

      private def extract_subshells(raw : String) : Array(String)
        # Extracts `%VAR%` environment variable names as subshell-like content.
        # These are scanned for blocked tool names by ConstraintChecker.
        #
        # `echo %COMSPEC%` → subshells: ["COMSPEC"]
        # `forfiles /C "cmd /c %SystemRoot%\del @file"` → subshells: ["SystemRoot"]
        subshells = [] of String
        raw.scan(/%([^%]+)%/) { |match| subshells << match[1] }
        subshells
      end

      # ameba:disable Metrics/CyclomaticComplexity: State machine for compound splitting — clear as-is
      private def split_compounds(raw : String) : Array(String)
        # Splits on cmd.exe compound operators: `&&`, `||`, `&`, `|`.
        # Uses a state machine to avoid splitting inside double quotes or on
        # caret-escaped operators.
        #
        # `echo foo & echo bar`  → ["echo foo", "echo bar"]   (& separator)
        # `echo foo && echo bar` → ["echo foo", "echo bar"]   (&& separator)
        # `echo "foo & bar"`     → ["echo \"foo & bar\""]     (& inside quotes — no split)
        # `echo foo^&bar`        → ["echo foo^&bar"]          (^& escaped — no split)
        #
        # The `^` + next-char pair is preserved in `current` here so that
        # `tokenise` can later strip the `^` and keep the escaped character.
        parts = [] of String
        current = String::Builder.new
        in_double = false
        i = 0

        while i < raw.size
          char = raw[i]
          case char
          when '^'
            # Caret-escaped char: include both `^` and the next char in current
            # so this sequence is not interpreted as an operator.
            # `tokenise` will later strip the `^` and keep the next char.
            if !in_double && i + 1 < raw.size
              current << char
              i += 1
              current << raw[i]
            else
              current << char
            end
          when '"'
            in_double = !in_double
            current << char
          when '&', '|'
            if !in_double
              next_char = i + 1 < raw.size ? raw[i + 1] : '\0'
              if (char == '&' && next_char == '&') || (char == '|' && next_char == '|')
                # Two-char operator: `&&` or `||`
                part = current.to_s.strip
                parts << part unless part.empty?
                current = String::Builder.new
                i += 2
                next
              elsif char == '&'
                # Single `&` — sequential execution
                part = current.to_s.strip
                parts << part unless part.empty?
                current = String::Builder.new
                i += 1
                next
              else
                # Single `|` — pipe
                part = current.to_s.strip
                parts << part unless part.empty?
                current = String::Builder.new
                i += 1
                next
              end
            else
              current << char
            end
          else
            current << char
          end
          i += 1
        end

        part = current.to_s.strip
        parts << part unless part.empty?
        parts
      end
    end
  end
end
