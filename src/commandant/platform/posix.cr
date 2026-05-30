module Commandant
  module Platform
    # Shared base for POSIX-compatible platforms.
    abstract class Posix < Base
      def flag_prefix : String
        "-"
      end

      def default_parser : Parser::Base
        Parser::PosixParser.new
      end
    end

    # Linux platform — GNU tool implementations.
    class Linux < Posix
      def ruleset_folder : String
        "linux"
      end
    end

    # macOS platform — BSD tool implementations.
    class MacOS < Posix
      def ruleset_folder : String
        "macos"
      end
    end
  end
end
