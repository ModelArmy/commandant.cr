require "json"
require "semantic_version"

module Commandant
  # Parsed representation of `manifest.json` from a ruleset bundle.
  class BundleManifest
    include JSON::Serializable

    getter version : String
    getter commandant_min_version : String
    getter schema_version : String
    getter attack_version : String
    getter created_at : String
    getter tool_count : Int32
    getter rule_count : Int32
    getter platforms : Array(String)
    getter tools : Array(String)
    getter checksums : Hash(String, String)

    # Returns true if the running engine meets the bundle's minimum version requirement.
    def engine_compatible?(engine_version : String) : Bool
      return true if commandant_min_version.empty?
      SemanticVersion.parse(engine_version) >= SemanticVersion.parse(commandant_min_version)
    rescue
      # If version parsing fails, fail open with a warning — don't block loading.
      STDERR.puts "WARNING [commandant] Could not compare engine version '#{engine_version}' " \
                  "against bundle minimum '#{commandant_min_version}'. Proceeding."
      true
    end
  end
end
