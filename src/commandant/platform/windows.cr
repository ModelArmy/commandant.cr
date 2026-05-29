module Commandant
  module Platform
    module Windows
      # cmd.exe platform — Windows Command Prompt.
      #
      # Flags use `/FLAG` syntax. Compound commands use `&`, `&&`, `||`.
      # Escape character is `^`. Environment variables use `%VAR%` syntax.
      class Cmd < Base
        def ruleset_folder : String
          "windows"
        end

        def default_parser : Parser::Base
          Parser::CmdParser.new
        end

        def flag_prefix : String
          "/"
        end
      end

      # PowerShell platform.
      #
      # Flags use `-Flag` or `--Flag` syntax (same prefix as POSIX).
      # Compound commands use `;`, `&&`, `||`. Subshells use `$(...)`.
      # Shares the `windows` ruleset folder with Cmd since rulesets
      # describe tool risk, not shell syntax.
      class PowerShell < Base
        def ruleset_folder : String
          "windows"
        end

        def default_parser : Parser::Base
          Parser::PowerShellParser.new
        end

        def flag_prefix : String
          "-"
        end
      end
    end

    # Compile-time default platform resolution.
    def self.default : Base
      {% if flag?(:win32) || flag?(:windows) %}
        Windows::Cmd.new
      {% elsif flag?(:darwin) %}
        MacOS.new
      {% else %}
        Linux.new
      {% end %}
    end
  end
end
