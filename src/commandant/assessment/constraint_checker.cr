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
    end

    # Returns all constraint violations for the given parsed command.
    def check(cmd : ParsedCommand) : Array(ConstraintViolation)
      violations = [] of ConstraintViolation

      check_allowed_tools(cmd, violations)
      check_sandbox(cmd, violations)

      # Recurse into compound commands
      cmd.compounds.each do |compound|
        violations.concat(check(compound))
      end

      violations
    end

    private def check_allowed_tools(cmd : ParsedCommand, violations : Array(ConstraintViolation)) : Nil
      return if cmd.binary.empty?
      unless allowed_tools.includes?(cmd.binary) || allowed_tools.includes?(cmd.binary_raw.to_s)
        violations << ConstraintViolation.new(
          constraint: "escapes-allowed-tools",
          detail: "'#{cmd.binary}' is not in the allowed tools list"
        )
      end
    end

    private def check_sandbox(cmd : ParsedCommand, violations : Array(ConstraintViolation)) : Nil
      cmd.arguments.each do |arg|
        next unless looks_like_path?(arg)
        check_path_argument(arg, violations)
      end
    end

    private def check_path_argument(arg : String, violations : Array(ConstraintViolation)) : Nil
      return if arg.starts_with?(".") # relative — likely safe
      return unless arg.starts_with?("/") || arg.starts_with?("~")

      expanded = arg.starts_with?("~") ? Path.home / arg[2..] : Path[arg]

      begin
        resolved = expanded.expand
        unless resolved.to_s.starts_with?(sandbox_root.to_s)
          violations << ConstraintViolation.new(
            constraint: "escapes-sandbox",
            detail: "'#{arg}' resolves to '#{resolved}' which is outside sandbox root '#{sandbox_root}'"
          )
        end
      rescue
        # Path expansion failed — flag as potentially escaping
        violations << ConstraintViolation.new(
          constraint: "escapes-sandbox",
          detail: "'#{arg}' could not be resolved relative to sandbox root '#{sandbox_root}'"
        )
      end
    end

    private def looks_like_path?(s : String) : Bool
      s.starts_with?("/") || s.starts_with?("~") || s.starts_with?("./") || s.starts_with?("../")
    end
  end
end
