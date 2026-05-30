module Commandant
  module Parser
    # Parses PowerShell command strings.
    #
    # Handles:
    # - Flags: `-Flag`, `--Flag`, `-Flag:Value`
    # - Compound commands: `;`, `&&`, `||`, `|` (pipeline)
    # - Subshells: `$(...)` (same syntax as POSIX)
    # - Quoted arguments: single and double quoted strings
    # - Backtick escape: `` ` `` (PowerShell's escape character)
    #
    # PowerShell flags use `-` prefix (same as POSIX) so flag canonicals
    # are stored as-is. Rulesets targeting PowerShell commands should use
    # `-Flag` style values in `flags_any`.
    #
    # PowerShell is case-insensitive but case is preserved in `Flag#raw`.
    # Rulesets should use the canonical casing for the tool being assessed.
    class PowerShellParser < Base
      # Parses a PowerShell command string into a `ParsedCommand`.
      #
      # Example flow for `Get-ChildItem -Path . -Recurse | Where-Object {$_.Name -like "*.cr"}`:
      #
      #   1. extract_subshells → [] (no $() here; {$_.Name} is not extracted)
      #   2. split_compounds   → ["Get-ChildItem -Path . -Recurse",
      #                           "Where-Object {$_.Name -like \"*.cr\"}"]
      #                           (| treated as compound separator)
      #   3. primary_raw       = "Get-ChildItem -Path . -Recurse"
      #   4. tokenise          → ["Get-ChildItem", "-Path", ".", "-Recurse"]
      #   5. binary            = "Get-ChildItem"
      #   6. flags             = [Flag("-Path"), Flag("-Recurse")]
      #   7. arguments         = ["."]
      #   8. compounds         = [ParsedCommand(binary: "Where-Object", ...)]
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
          if token.starts_with?("--")
            # Long flag: `--version`, `--help`
            # Stored as-is; no colon-value splitting for double-dash flags.
            flags << Flag.new(raw: token, canonical: token)
          elsif token.starts_with?("-") && token.size > 1 && token[1].ascii_letter?
            # Named flag: `-Recurse`, `-Path`, `-Flag:Value`
            # PowerShell uses `-Flag:Value` (colon) or `-Flag Value` (space) for values.
            # `-Path:C:\Users` → Flag("-Path"), argument "C:\Users"
            # `-Path C:\Users` → Flag("-Path"), next token becomes an argument naturally
            if colon = token.index(':', 1)
              flag_part = token[0...colon]
              value_part = token[(colon + 1)..]
              flags << Flag.new(raw: flag_part, canonical: flag_part)
              arguments << value_part unless value_part.empty?
            else
              flags << Flag.new(raw: token, canonical: token)
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

      # ameba:disable Metrics/CyclomaticComplexity: State machine for tokenisation — clear as-is
      private def tokenise(raw : String) : Array(String)
        # Splits the command string into tokens by whitespace, respecting
        # PowerShell quoting and backtick escaping.
        #
        # Examples:
        #   "Get-ChildItem -Recurse"        → ["Get-ChildItem", "-Recurse"]
        #   "Write-Host 'hello world'"      → ["Write-Host", "hello world"]
        #   "Write-Host \"hello world\""    → ["Write-Host", "hello world"]
        #   "Write-Host hello`nworld"       → ["Write-Host", "hellonworld"]
        #                                      (backtick consumed, `n` kept literally —
        #                                       actual newline escape not handled here)
        #
        # PowerShell quoting rules:
        # - Single quotes: everything inside is literal; no escape processing.
        #   `'C:\Program Files'` → "C:\Program Files" as one token.
        # - Double quotes: backtick `` ` `` escapes the next character.
        #   `"hello`"world"` → `hello"world`.
        # - Backtick outside quotes: escapes the next character.
        #   `` Get-Date` `` → joins with next line (continuation); here treated
        #   as escaping next char.
        tokens = [] of String
        current = String::Builder.new
        in_single = false
        in_double = false
        i = 0

        while i < raw.size
          char = raw[i]
          case char
          when '`'
            # Backtick is PowerShell's escape character — consume it and include
            # the next character literally. Works both inside and outside double quotes.
            # Inside single quotes, backtick is literal.
            if !in_single && i + 1 < raw.size
              i += 1
              current << raw[i]
            else
              current << char
            end
          when '\''
            if !in_double
              # Toggle single-quote mode. Quote char itself is not added.
              in_single = !in_single
            else
              # Inside double quotes, single quote is literal.
              current << char
            end
          when '"'
            if !in_single
              # Toggle double-quote mode. Quote char itself is not added.
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
        # Extracts `$(...)` subshell expressions for constraint scanning.
        # PowerShell uses the same `$(...)` syntax as POSIX for subexpressions.
        #
        # `Write-Host $(Get-Date)` → subshells: ["Get-Date"]
        # `$((Get-Process).Count)` → subshells: ["(Get-Process"].Count"] (approximate)
        #
        # The content is passed to ConstraintChecker which attempts to parse it
        # as a command and check for blocked tools.
        subshells = [] of String
        raw.scan(/\$\(([^)]*)\)/) { |match| subshells << match[1] }
        subshells
      end

      # ameba:disable Metrics/CyclomaticComplexity: State machine for compound splitting — clear as-is
      private def split_compounds(raw : String) : Array(String)
        # Splits on PowerShell compound operators: `;`, `&&`, `||`, `|`.
        # Uses a state machine to avoid splitting inside quoted strings.
        #
        # `Get-Date; Get-Location`          → ["Get-Date", "Get-Location"]
        # `echo foo && echo bar`            → ["echo foo", "echo bar"]
        # `Get-Process | Where-Object {...}` → ["Get-Process", "Where-Object {...}"]
        # `Write-Host 'foo; bar'`           → ["Write-Host 'foo; bar'"]  (no split — quoted)
        #
        # Note: PowerShell pipelines (`|`) pass objects, not text strings, between
        # commands. For risk assessment purposes we treat `|` as a compound separator
        # and assess each stage independently.
        parts = [] of String
        current = String::Builder.new
        in_single = false
        in_double = false
        i = 0

        while i < raw.size
          char = raw[i]
          case char
          when '\''
            in_single = !in_single unless in_double
            current << char
          when '"'
            in_double = !in_double unless in_single
            current << char
          when ';', '|'
            if !in_single && !in_double
              next_char = i + 1 < raw.size ? raw[i + 1] : '\0'
              if char == '|' && next_char == '|'
                # `||` — run right side if left fails
                part = current.to_s.strip
                parts << part unless part.empty?
                current = String::Builder.new
                i += 2
                next
              else
                # `;` or single `|` — sequential or pipeline
                part = current.to_s.strip
                parts << part unless part.empty?
                current = String::Builder.new
                i += 1
                next
              end
            else
              current << char
            end
          when '&'
            if !in_single && !in_double
              next_char = i + 1 < raw.size ? raw[i + 1] : '\0'
              if next_char == '&'
                # `&&` — run right side if left succeeds
                part = current.to_s.strip
                parts << part unless part.empty?
                current = String::Builder.new
                i += 2
                next
              end
            end
            current << char
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
