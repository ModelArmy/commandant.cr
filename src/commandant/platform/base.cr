module Commandant
  module Platform
    # Abstract base for all platform implementations.
    #
    # A platform provides three things:
    # - The ruleset folder name used to select committed rulesets
    # - The default parser for command strings on this platform
    # - The flag prefix convention used by tools on this platform
    #
    # Parser and ruleset must always be a matched pair — a CMD parser
    # produces `/FLAG` style canonicals; those must match the Windows
    # ruleset's `flags_any` values. `Assessor` enforces this by deriving
    # the parser from the platform unless explicitly overridden.
    abstract class Base
      # The folder name under `rulesets/` for this platform.
      # E.g. "linux", "macos", "windows", "posix".
      abstract def ruleset_folder : String

      # The default parser for command strings on this platform.
      abstract def default_parser : Parser::Base

      # The flag prefix convention for this platform ("-" or "/").
      abstract def flag_prefix : String
    end
  end
end
