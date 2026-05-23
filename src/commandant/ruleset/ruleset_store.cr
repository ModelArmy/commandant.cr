module Commandant
  # Loads and caches rulesets from a directory.
  #
  # Rulesets are looked up by tool name. The store searches platform-specific
  # and posix directories in priority order: platform first, posix as fallback.
  #
  # Usage:
  # ```
  # store = Commandant::RulesetStore.new(
  #   base_path: Path["./rulesets"],
  #   platform: "linux"
  # )
  # ruleset = store.load("grep") # loads rulesets/linux/grep.json or rulesets/posix/grep.json
  # ```
  class RulesetStore
    getter base_path : Path
    getter platform : String

    @cache : Hash(String, Ruleset)

    def initialize(@base_path : Path, @platform : String)
      @cache = {} of String => Ruleset
    end

    # Returns true if a committed ruleset exists for the given tool name.
    def known?(tool : String) : Bool
      !resolve_path(tool).nil?
    end

    # Loads and returns the ruleset for `tool`, or nil if not found.
    # Results are cached — subsequent calls for the same tool are free.
    def load(tool : String) : Ruleset?
      return @cache[tool] if @cache.has_key?(tool)

      path = resolve_path(tool)
      return nil unless path

      ruleset = Ruleset.from_file(path)
      @cache[tool] = ruleset
      ruleset
    end

    # Loads all rulesets in the store eagerly. Suitable for server mode
    # where startup cost is paid once.
    def load_all : Nil
      [platform, "posix"].uniq.each do |plat|
        dir = @base_path / plat
        next unless Dir.exists?(dir.to_s)
        Dir.glob("#{dir}/*.json") do |path|
          tool = File.basename(path, ".json")
          load(tool) unless @cache.has_key?(tool)
        end
      end
    end

    # Returns all tool names with a loaded or available ruleset.
    def known_tools : Array(String)
      discovered = [] of String
      [platform, "posix"].uniq.each do |plat|
        dir = @base_path / plat
        next unless Dir.exists?(dir.to_s)
        Dir.glob("#{dir}/*.json") do |path|
          discovered << File.basename(path, ".json")
        end
      end
      (discovered + @cache.keys).uniq
    end

    private def resolve_path(tool : String) : Path?
      # Platform-specific takes precedence over posix
      [platform, "posix"].each do |plat|
        path = @base_path / plat / "#{tool}.json"
        return path if File.exists?(path.to_s)
      end
      nil
    end
  end
end
