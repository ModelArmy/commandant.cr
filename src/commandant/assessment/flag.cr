require "json"

module Commandant
  # A single parsed flag from a shell command.
  #
  # Flags are stored exactly as written — the prefix is preserved.
  # `canonical` holds the expanded form after abbreviation resolution;
  # it equals `raw` when no expansion occurred.
  #
  # Examples:
  # - `raw: "-r"`, `canonical: "-r"`, `abbreviated: false`
  # - `raw: "--compress-prog"`, `canonical: "--compress-program"`, `abbreviated: true`
  record Flag,
    raw : String,
    canonical : String,
    abbreviated : Bool = false do
    include JSON::Serializable

    # Returns the canonical form for matching against ruleset `match` fields.
    def to_s(io : IO) : Nil
      io << canonical
    end
  end
end
