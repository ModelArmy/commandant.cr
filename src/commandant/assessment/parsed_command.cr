require "json"

module Commandant
  # The result of parsing a raw shell command string.
  #
  # `binary` is the resolved tool name after multiplexer unwrapping.
  # `binary_raw` holds the original name before unwrapping (nil if no unwrapping).
  # `flags` are stored with their prefix intact; canonical form used for matching.
  # `compounds` holds commands chained via `;`, `&&`, `||`, or `&`.
  # `subshells` holds the raw content of `$(...)` or backtick expressions.
  record ParsedCommand,
    raw : String,
    binary : String,
    flags : Array(Flag),
    arguments : Array(String),
    binary_raw : String? = nil,
    compounds : Array(ParsedCommand) = [] of ParsedCommand,
    subshells : Array(String) = [] of String do
    include JSON::Serializable

    # Returns true if the binary was unwrapped from a multiplexer.
    def multiplexer_unwrapped? : Bool
      !binary_raw.nil?
    end

    # Returns all canonical flag strings — used for match evaluation.
    def flag_canonicals : Array(String)
      flags.map(&.canonical)
    end

    # Returns true if the raw command contains shell metacharacters
    # indicating subshell or pipe patterns not captured in `subshells`.
    def has_metacharacters? : Bool
      raw.matches?(/\$\(|`|;\s*\S|&&|\|\|/)
    end
  end
end
