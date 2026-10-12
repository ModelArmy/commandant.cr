require "json"

module Commandant
  # A constraint violation found at runtime.
  record ConstraintViolation,
    constraint : String,
    detail : String do
    include JSON::Serializable
  end

  # Evaluates runtime constraints against a parsed command.
  #
  # Constraints are context-specific policies — they cannot be computed
  # from the ruleset alone and must be evaluated against live configuration.
  class ConstraintChecker
    getter sandbox_root : Path
    getter allowed_tools : Array(String)

    def initialize(@sandbox_root : Path, @allowed_tools : Array(String))
      @parser = Parser::PosixParser.new
      @expanded_root = @sandbox_root.expand
    end

    # Returns all constraint violations for the given parsed command.
    # Recurses into compound commands and parses subshell contents.
    def check(cmd : ParsedCommand) : Array(ConstraintViolation)
      violations = [] of ConstraintViolation

      check_line_continuations(cmd, violations)
      check_allowed_tools(cmd, violations)
      check_sandbox(cmd, violations)

      # Recurse into compound commands (already parsed)
      cmd.compounds.each do |compound|
        violations.concat(check(compound))
      end

      # Parse and check subshell contents
      cmd.subshells.each do |subshell|
        check_subshell(subshell, violations)
      end

      violations
    end

    # ameba:disable Metrics/CyclomaticComplexity: State machine for detecting line continuation — clear as-is
    private def check_line_continuations(cmd : ParsedCommand, violations : Array(ConstraintViolation)) : Nil
      # Detects line-continuation sequences OUTSIDE quoted strings — R-INS-07.
      #
      # Two patterns are flagged:
      #
      # 1. Backslash-newline outside quotes (explicit line continuation):
      #    grep foo \
      #    file.txt
      #    The shell joins lines, potentially hiding what follows from a naive
      #    inspector. This is OpenClaw bypass technique #1 (arXiv 2603.27517).
      #
      # 2. Bare newline outside quotes:
      #    grep foo
      #    file.txt
      #    The shell treats this as two commands. A single-line inspector
      #    misses the second command entirely.
      #
      # Newlines INSIDE quoted strings are NOT flagged — they are legitimate
      # content (e.g. grep "foo\nbar" is a valid multi-line search pattern).
      raw = cmd.raw
      in_single = false
      in_double = false
      i = 0

      while i < raw.size
        char = raw[i]
        case char
        when '\''
          in_single = !in_single unless in_double
        when '"'
          in_double = !in_double unless in_single
        when '\\'
          if !in_single && !in_double && i + 1 < raw.size && raw[i + 1] == '\n'
            violations << ConstraintViolation.new(
              constraint: "line-continuation",
              detail: "Backslash-newline outside quotes — line continuation may obscure command intent"
            )
          end
          i += 1 # skip next char to avoid double-processing
        when '\n'
          unless in_single || in_double
            violations << ConstraintViolation.new(
              constraint: "line-continuation",
              detail: "Bare newline outside quotes — possible command separator injection"
            )
          end
        end
        i += 1
      end
    end

    private def check_subshell(content : String, violations : Array(ConstraintViolation)) : Nil
      return if content.strip.empty?

      parsed = @parser.parse(content.strip)

      if !parsed.binary.empty?
        violations.concat(check(parsed))
      else
        scan_for_blocked_tools(content, violations)
      end
    end

    # Scans opaque content for blocked tool names appearing as quoted string
    # literals. Catches capability tunneling patterns like:
    #   crystal eval 'Process.exec("shards", ["install"])'
    #   ruby -e 'system("npm install")'
    private def scan_for_blocked_tools(content : String, violations : Array(ConstraintViolation)) : Nil
      quoted = [] of String
      content.scan(/"([^"]+)"/) { |match| quoted << match[1] }
      content.scan(/'([^']+)'/) { |match| quoted << match[1] }

      quoted.each do |str|
        candidate = str.split(/\s+/).first?
        next unless candidate

        binary = File.basename(candidate)
        next if binary.empty?
        next if allowed_tools.includes?(binary)
        next unless binary.matches?(/\A[a-zA-Z][a-zA-Z0-9_-]*\z/)

        violations << ConstraintViolation.new(
          constraint: "escapes-allowed-tools",
          detail: "'#{binary}' found as string literal in subshell expression — possible capability tunneling"
        )
      end
    end

    private def check_allowed_tools(cmd : ParsedCommand, violations : Array(ConstraintViolation)) : Nil
      return if cmd.binary.empty?
      binary_to_check = cmd.binary_raw || cmd.binary
      unless allowed_tools.includes?(cmd.binary) || allowed_tools.includes?(binary_to_check)
        violations << ConstraintViolation.new(
          constraint: "escapes-allowed-tools",
          detail: "'#{cmd.binary}' is not in the allowed tools list"
        )
      end

      # Scan plain arguments for blocked tool names — catches find -exec shards
      # where the blocked tool appears as a plain token, not a quoted string.
      check_exec_arguments(cmd, violations)

      # Scan string-literal arguments for blocked tool names — catches eval patterns.
      cmd.arguments.each do |arg|
        scan_for_blocked_tools(arg, violations)
      end
    end

    # Checks arguments that follow an -exec style flag for blocked tool names.
    # In `find . -exec shards install \;`, "shards" is a plain argument token
    # that immediately follows -exec and represents the binary to invoke.
    private def check_exec_arguments(cmd : ParsedCommand, violations : Array(ConstraintViolation)) : Nil
      exec_flags = %w[-exec -execdir -ok -okdir]
      in_exec = false

      cmd.flags.each do |flag|
        in_exec = exec_flags.includes?(flag.canonical)
      end

      # If an exec-style flag is present, scan arguments for blocked binaries.
      # Arguments are scanned in order; the first non-option-looking token is
      # the binary being executed.
      return unless in_exec

      cmd.arguments.each do |arg|
        next if arg == "{}" || arg == "\\;" || arg == "+" || arg == ";"
        next if arg.starts_with?("-")

        binary = File.basename(arg)
        next if binary.empty?
        next if allowed_tools.includes?(binary)
        next unless binary.matches?(/\A[a-zA-Z][a-zA-Z0-9_-]*\z/)

        violations << ConstraintViolation.new(
          constraint: "escapes-allowed-tools",
          detail: "'#{binary}' passed to exec-style flag — possible capability tunneling via allowed tool"
        )
        break # Only flag the first — it's the binary
      end
    end

    private def check_sandbox(cmd : ParsedCommand, violations : Array(ConstraintViolation)) : Nil
      cmd.arguments.each do |arg|
        next unless looks_like_path?(arg)
        check_path_argument(arg, violations)
      end
    end

    private def check_path_argument(arg : String, violations : Array(ConstraintViolation)) : Nil
      resolved = resolve(arg)
      return if resolved && within_sandbox?(resolved)

      detail = if resolved
                 "'#{arg}' resolves to '#{resolved}' which is outside sandbox root '#{sandbox_root}'"
               else
                 "'#{arg}' could not be resolved relative to sandbox root '#{sandbox_root}'"
               end
      violations << ConstraintViolation.new(constraint: "escapes-sandbox", detail: detail)
    end

    # Expands *arg* as a command run in the sandbox root would see it: `~` is the
    # home directory and relative paths start at the sandbox root. Returns nil
    # when the path cannot be expanded.
    private def resolve(arg : String) : Path?
      Path[arg].expand(base: @expanded_root, home: true)
    rescue
      nil
    end

    # Compares path components rather than strings, with both paths expanded
    # the same way, so `/project-evil` is outside `/project` and a Windows
    # drive prefix applies to both sides.
    private def within_sandbox?(path : Path) : Bool
      relative = path.relative_to?(@expanded_root)
      !relative.nil? && relative.parts.first? != ".."
    end

    private def looks_like_path?(s : String) : Bool
      s.starts_with?("/") || s.starts_with?("~") || s.starts_with?("./") || s.starts_with?("../") || s == ".."
    end
  end
end
