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
      #
      # Example flow for `grep -r 'foo bar' . && cat README.md`:
      #
      #   1. extract_subshells → [] (no $() or backticks)
      #   2. split_compounds   → ["grep -r 'foo bar' .", "cat README.md"]
      #   3. primary_raw       = "grep -r 'foo bar' ."
      #   4. tokenise          → ["grep", "-r", "foo bar", "."]
      #                           (quotes stripped, space inside quotes preserved)
      #   5. binary            = "grep"
      #   6. flags             = [Flag("-r")]
      #   7. arguments         = ["foo bar", "."]
      #   8. compounds         = [ParsedCommand(binary: "cat", ...)]
      def parse(raw : String) : ParsedCommand
        # Extract subshell contents before tokenising so we don't confuse
        # `$(whoami)` with ordinary parentheses.
        subshells = extract_subshells(raw)

        # Split on compound operators first. Each part is independently parsed.
        # `grep foo . && rm -rf .` → ["grep foo .", "rm -rf ."]
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
            # Long flag: --recursive, --color=always
            # Stored as-is; the `=value` portion stays attached.
            # `--color=always` → Flag(raw: "--color=always", canonical: "--color=always")
            flags << Flag.new(raw: token, canonical: token)
          elsif token.starts_with?("-") && token.size > 1
            # Short flag, combined flags, or flag with attached value.
            # Dispatched to parse_short_flags — see that method for details.
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
        # Splits the command string into tokens by whitespace, respecting quoting.
        #
        # Examples:
        #   "grep foo bar"          → ["grep", "foo", "bar"]
        #   "grep 'foo bar' baz"    → ["grep", "foo bar", "baz"]   # single quotes strip
        #   "grep \"foo bar\" baz"  → ["grep", "foo bar", "baz"]   # double quotes strip
        #   "sed -i.bak 's/a/b/'"  → ["sed", "-i.bak", "s/a/b/"]  # quote inside kept
        #
        # Quoting rules:
        # - Single quotes: everything inside is literal; no escaping possible.
        #   The quotes themselves are stripped from the token.
        # - Double quotes: spaces are preserved; backslash escapes the next char.
        #   The quotes themselves are stripped.
        # - Backslash outside quotes: escapes the next character.
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
              # Toggle single-quote mode. The quote char itself is not added.
              in_single = !in_single
            else
              # Inside double quotes, single quote is literal.
              current << char
            end
          when '"'
            if !in_single
              # Toggle double-quote mode. The quote char itself is not added.
              in_double = !in_double
            else
              # Inside single quotes, double quote is literal.
              current << char
            end
          when ' ', '\t'
            if in_single || in_double
              # Space inside quotes is part of the token.
              current << char
            else
              # Space outside quotes ends the current token.
              token = current.to_s
              tokens << token unless token.empty?
              current = String::Builder.new
            end
          when '\\'
            if !in_single && i + 1 < raw.size
              # Backslash outside single quotes escapes the next character.
              # `hello\ world` → one token "hello world"
              i += 1
              current << raw[i]
            else
              # Inside single quotes, backslash is literal.
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
        # Classifies a dash-prefixed token into one of three forms:
        #
        # 1. Combined single-char flags: `-rf`, `-la`
        #    Each letter after the dash is its own flag.
        #    `-rf` → Flag("-r"), Flag("-f")
        #    Condition: all chars after dash are alpha AND token is ≤ 4 chars total.
        #
        # 2. Multi-char word flag: `-exec`, `-name`, `-delete`
        #    Stored as a single flag — these are NOT combined chars.
        #    `-exec` → Flag("-exec")
        #    Condition: all chars after dash are alpha AND token is > 4 chars total.
        #    (Heuristic: `-lah` = 4 chars = still combined; `-exec` = 5 chars = word flag)
        #
        # 3. Flag with attached non-alpha value: `-i.bak`, `-I/usr/include`
        #    The single flag char is separated from the attached value.
        #    `-i.bak` → Flag("-i"), argument ".bak"
        #    Condition: second char is alpha, remainder contains non-alpha chars.
        if token.size > 2 && token[1].ascii_letter?
          rest = token[2..]
          all_alpha = rest.chars.all?(&.ascii_letter?)

          if all_alpha && token.size <= 4
            # Form 1: combined short flags
            # `-rf` → [Flag("-r"), Flag("-f")]
            token[1..].each_char { |char| flags << Flag.new(raw: "-#{char}", canonical: "-#{char}") }
          elsif all_alpha
            # Form 2: word flag
            # `-exec` → [Flag("-exec")]
            flags << Flag.new(raw: token, canonical: token)
          else
            # Form 3: flag with attached value
            # `-i.bak` → [Flag("-i")], arguments << ".bak"
            flag_char = token[1]
            attached_value = rest
            flags << Flag.new(raw: "-#{flag_char}", canonical: "-#{flag_char}")
            arguments << attached_value unless attached_value.empty?
          end
        else
          # Simple single-char flag: `-r`, `-i`
          flags << Flag.new(raw: token, canonical: token)
        end
      end

      private def extract_subshells(raw : String) : Array(String)
        # Extracts the content of subshell expressions for constraint scanning.
        #
        # `echo $(whoami)` → subshells: ["whoami"]
        # `echo `date``    → subshells: ["date"]
        # `grep $(cat f)`  → subshells: ["cat f"]
        #
        # The content is used by ConstraintChecker to parse the inner command
        # and check for blocked tools or sandbox escapes.
        subshells = [] of String
        raw.scan(/\$\(([^)]*)\)/) { |match| subshells << match[1] }
        raw.scan(/`([^`]*)`/) { |match| subshells << match[1] }
        subshells
      end

      private def split_compounds(raw : String) : Array(String)
        # Splits a command string on compound operators into individual commands.
        # Each part is later parsed independently and stored in `compounds`.
        #
        # `ls . && rm -rf tmp` → ["ls .", "rm -rf tmp"]
        # `cat f; grep foo f`  → ["cat f", "grep foo f"]
        # `ls | grep foo`      → ["ls", "grep foo"]
        #
        # Note: this is a naive regex split and does not respect quoting around
        # operators. A command like `echo "foo && bar"` would be split incorrectly.
        # This is a known limitation — see KNOWN_ISSUES.md.
        raw.split(/\s*(?:&&|\|\||;|\|)\s*/).map(&.strip).reject(&.empty?)
      end
    end
  end
end
