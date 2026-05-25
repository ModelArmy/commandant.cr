module Commandant
  module Parser
    # Parses POSIX shell command strings (bash, zsh, sh).
    #
    # Handles:
    # - Short flags: `-r`, `-rf`, `-i.bak`
    # - Long flags: `--recursive`, `--exec`
    # - Flag-value pairs: `-d recurse`, `--color=always`
    # - Arguments: paths, patterns, expressions
    # - Subshell extraction: `$(...)`, backtick expressions
    # - Compound commands: `;`, `&&`, `||` (returns first command; stores compounds)
    #
    # Does not handle here-docs or process substitution `<(...)`.
    class PosixParser < Base
      # Parses the raw command string into a `ParsedCommand`.
      def parse(raw : String) : ParsedCommand
        # Extract subshell contents before tokenising
        subshells = extract_subshells(raw)

        # Split on compound operators — assess the first command,
        # recursively parse the rest into compounds
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
          if token.starts_with?("--")
            flags << Flag.new(raw: token, canonical: token)
          elsif token.starts_with?("-") && token.size > 1
            # Handle combined short flags: -rf → -r, -f
            # Handle flag with attached value: -i.bak
            parse_short_flags(token, flags, arguments)
          else
            arguments << token
          end
          i += 1
        end

        compounds = compound_raws.map { |cmd| parse(cmd) }

        ParsedCommand.new(
          raw: raw,
          binary: binary,
          flags: flags,
          arguments: arguments,
          compounds: compounds,
          subshells: subshells
        )
      end

      # ameba:disable Metrics/CyclomaticComplexity: Despite complexity, this is very clear and best in this form
      private def tokenise(raw : String) : Array(String)
        tokens = [] of String
        current = String::Builder.new
        in_single = false
        in_double = false
        i = 0

        while i < raw.size
          char = raw[i]
          case char
          when '\''
            if !in_double
              in_single = !in_single
            else
              current << char
            end
          when '"'
            if !in_single
              in_double = !in_double
            else
              current << char
            end
          when ' ', '\t'
            if in_single || in_double
              current << char
            else
              token = current.to_s
              tokens << token unless token.empty?
              current = String::Builder.new
            end
          when '\\'
            if !in_single && i + 1 < raw.size
              i += 1
              current << raw[i]
            else
              current << char
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

      private def parse_short_flags(token : String, flags : Array(Flag), arguments : Array(String)) : Nil
        # POSIX short flags are single characters: -r, -f, -l
        # Combined short flags are multiple single chars: -rf, -la (each char is a flag)
        # Flag with attached value: -i.bak (single flag char + non-alpha remainder)
        # Multi-char words like -exec, -name, -delete are single flags — NOT combined chars.
        #
        # Rule: split into individual flags only when ALL chars after the dash are
        # single ASCII letters AND there are exactly 2 or more of them (e.g. -rf, -la).
        # Any non-alpha char in the remainder means it's a flag+attached-value (-i.bak).
        # A multi-char all-alpha remainder longer than ~2 is almost certainly a word
        # flag (-exec, -name) — store as-is.
        if token.size > 2 && token[1].ascii_letter?
          rest = token[2..]
          all_alpha = rest.chars.all?(&.ascii_letter?)

          # Heuristic: combined flags are typically 1-3 chars total (e.g. -rf, -la, -lah).
          # Words like -exec (4+ chars) are single flags. Threshold: <= 3 total chars = combine.
          if all_alpha && token.size <= 4
            # Combined short flags: -rf → -r, -f  or  -la → -l, -a
            token[1..].each_char { |char| flags << Flag.new(raw: "-#{char}", canonical: "-#{char}") }
          elsif all_alpha
            # Multi-char word flag: -exec, -name, -delete — store whole token as single flag
            flags << Flag.new(raw: token, canonical: token)
          else
            # Flag with attached non-alpha value: -i.bak
            flag_char = token[1]
            attached_value = rest
            flags << Flag.new(raw: "-#{flag_char}", canonical: "-#{flag_char}")
            arguments << attached_value unless attached_value.empty?
          end
        else
          flags << Flag.new(raw: token, canonical: token)
        end
      end

      private def extract_subshells(raw : String) : Array(String)
        subshells = [] of String
        # $(...) extraction
        raw.scan(/\$\(([^)]*)\)/) { |match| subshells << match[1] }
        # backtick extraction
        raw.scan(/`([^`]*)`/) { |match| subshells << match[1] }
        subshells
      end

      private def split_compounds(raw : String) : Array(String)
        # Naive split on ; | && || — does not handle quoting around operators
        # Returns the primary command and any trailing compounds
        raw.split(/\s*(?:&&|\|\||;|\|)\s*/).map(&.strip).reject(&.empty?)
      end
    end
  end
end
