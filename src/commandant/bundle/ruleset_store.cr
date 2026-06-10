module Commandant
  # Loads and caches rulesets from a directory or a `RulesetBundle`.
  #
  # Rulesets are looked up by tool name. The store searches platform-specific
  # and posix directories in priority order: platform first, posix as fallback.
  #
  # Directory usage:
  # ```
  # store = Commandant::RulesetStore.new(
  #   base_path: Path["./rulesets"],
  #   platform: "linux"
  # )
  # ruleset = store.load("grep") # loads rulesets/linux/grep.json or rulesets/posix/grep.json
  # ```
  #
  # Bundle usage:
  # ```
  # bundle = Commandant::RulesetBundle.new(
  #   path: Path["commandant-rules-v0.4.0.zip"],
  #   checksum_path: Path["commandant-rules-v0.4.0.zip.sha256"]
  # )
  # store = Commandant::RulesetStore.from_bundle(bundle, platform: "linux")
  # ```
  class RulesetStore
    getter platform : String
    getter verification : RulesetVerification

    @base_path : Path?
    @bundle : RulesetBundle?
    @cache : Hash(String, Ruleset)

    def initialize(base_path : Path, @platform : String)
      @base_path = base_path
      @bundle = nil
      @cache = {} of String => Ruleset
      @verification = RulesetVerification::None
    end

    def self.from_bundle(bundle : RulesetBundle, platform : String) : self
      store = new(Path["."], platform)
      store.init_from_bundle(bundle)
      store
    end

    # Returns true if a committed ruleset exists for the given tool name.
    def known?(tool : String) : Bool
      if bundle = @bundle
        bundle_entry_path(tool, bundle).any? { |entry_path| !bundle.read_entry(entry_path).nil? }
      else
        !resolve_path(tool).nil?
      end
    end

    # Loads and returns the ruleset for `tool`, or nil if not found.
    # Results are cached — subsequent calls for the same tool are free.
    def load(tool : String) : Ruleset?
      return @cache[tool] if @cache.has_key?(tool)

      ruleset = if bundle = @bundle
                  load_from_bundle(tool, bundle)
                else
                  load_from_directory(tool)
                end

      if ruleset
        warn_missing_mitre_attack(ruleset, tool)
        @cache[tool] = ruleset
      end

      ruleset
    end

    # Loads all rulesets in the store eagerly. Suitable for server mode
    # where startup cost is paid once.
    def load_all : Nil
      if bundle = @bundle
        bundle.manifest.tools.each { |tool| load(tool) unless @cache.has_key?(tool) }
      elsif base_path = @base_path
        [platform, "posix"].uniq.each do |plat|
          dir = base_path / plat
          next unless Dir.exists?(dir.to_s)
          Dir.glob("#{dir}/*.json") do |path|
            tool = File.basename(path, ".json")
            load(tool) unless @cache.has_key?(tool)
          end
        end
      end
    end

    # Returns all tool names with a loaded or available ruleset.
    def known_tools : Array(String)
      if bundle = @bundle
        bundle.manifest.tools
      elsif base_path = @base_path
        discovered = [] of String
        [platform, "posix"].uniq.each do |plat|
          dir = base_path / plat
          next unless Dir.exists?(dir.to_s)
          Dir.glob("#{dir}/*.json") do |path|
            discovered << File.basename(path, ".json")
          end
        end
        (discovered + @cache.keys).uniq
      else
        @cache.keys
      end
    end

    # :nodoc:
    protected def init_from_bundle(bundle : RulesetBundle) : Nil
      @bundle = bundle
      @base_path = nil
      @verification = bundle.verification
    end

    private def load_from_bundle(tool : String, bundle : RulesetBundle) : Ruleset?
      bundle_entry_path(tool, bundle).each do |entry_path|
        json = bundle.read_entry(entry_path)
        next unless json
        return Ruleset.from_json(json)
      end
      nil
    end

    private def load_from_directory(tool : String) : Ruleset?
      path = resolve_path(tool)
      return nil unless path
      Ruleset.from_file(path)
    end

    # Returns candidate entry paths in priority order: platform-specific first, posix fallback.
    private def bundle_entry_path(tool : String, bundle : RulesetBundle) : Array(String)
      platforms = [platform, "posix"].uniq
      platforms.map { |plat| "rulesets/#{plat}/#{tool}.json" }
    end

    private def warn_missing_mitre_attack(ruleset : Ruleset, tool : String) : Nil
      missing = ruleset.rules.count { |rule| rule.mitre_attack.nil? }
      if missing > 0
        source = @bundle ? "bundle:#{tool}" : tool
        STDERR.puts "WARNING [commandant] #{source}: #{missing} of #{ruleset.rules.size} rule(s) " \
                    "are missing the mitre_attack field. MITRE ATT&CK mapping will be nil " \
                    "in assessment responses for these rules. Run a backfill pass to resolve."
      end
    end

    private def resolve_path(tool : String) : Path?
      return nil unless base_path = @base_path
      [platform, "posix"].each do |plat|
        path = base_path / plat / "#{tool}.json"
        return path if File.exists?(path.to_s)
      end
      nil
    end
  end
end
