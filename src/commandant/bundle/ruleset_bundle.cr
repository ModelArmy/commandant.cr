require "compress/zip"
require "digest/sha256"

module Commandant
  # A versioned, optionally verified commandant ruleset bundle.
  #
  # A bundle is a ZIP file produced by `scripts/package.rb`, containing a
  # `manifest.json` at the root and a `rulesets/` subtree. It may optionally
  # be verified against a SHA256 checksum.
  #
  # Construction accepts an optional checksum for ZIP-level verification:
  # ```
  # # No verification
  # bundle = RulesetBundle.new(path: Path["commandant-rules-v0.4.0.zip"])
  #
  # # ZIP-level verification from a checksum file
  # bundle = RulesetBundle.new(
  #   path: Path["commandant-rules-v0.4.0.zip"],
  #   checksum_path: Path["commandant-rules-v0.4.0.zip.sha256"]
  # )
  #
  # # ZIP-level verification from a checksum string
  # bundle = RulesetBundle.new(
  #   path: Path["commandant-rules-v0.4.0.zip"],
  #   checksum: ENV["RULESET_CHECKSUM"]
  # )
  #
  # # Full verification — ZIP-level + per-entry
  # bundle.verify!
  # ```
  class RulesetBundle
    class Error < Exception; end

    class ChecksumMismatchError < Error; end

    class ManifestError < Error; end

    class IncompatibleEngineError < Error; end

    getter path : Path
    getter manifest : BundleManifest
    getter verification : RulesetVerification
    getter mitre_names : MitreNames

    def initialize(
      @path : Path,
      checksum_path : Path? = nil,
      checksum : String? = nil,
    )
      if checksum_path && checksum
        raise Error.new("Provide checksum_path or checksum, not both.")
      end

      @manifest = load_manifest
      @mitre_names = load_mitre_names
      check_engine_compatibility

      expected = if checksum_path
                   read_checksum_file(checksum_path)
                 elsif checksum
                   normalise_checksum(checksum)
                 end

      if expected
        verify_zip_checksum(expected)
        @verification = RulesetVerification::Bundle
      else
        @verification = RulesetVerification::None
      end
    end

    # Performs per-entry checksum verification against the manifest.
    #
    # Upgrades `verification` to `Entries` (if previously `None`) or
    # `Full` (if previously `Bundle`). Raises `ChecksumMismatchError`
    # on any mismatch.
    def verify! : self
      Compress::Zip::File.open(path.to_s) do |zip|
        manifest.checksums.each do |entry_path, expected_hex|
          entry = zip[entry_path]?
          raise ManifestError.new("Bundle is missing manifest entry: #{entry_path}") unless entry

          actual_hex = entry.open { |io| Digest::SHA256.hexdigest(io.gets_to_end) }

          unless actual_hex == expected_hex
            raise ChecksumMismatchError.new(
              "Entry checksum mismatch: #{entry_path}\n" \
              "  expected: #{expected_hex}\n" \
              "  actual:   #{actual_hex}"
            )
          end
        end
      end

      @verification = case @verification
                      in .none?   then RulesetVerification::Entries
                      in .bundle? then RulesetVerification::Full
                      in .entries?, .full?
                        @verification
                      end
      self
    end

    # Looks up the human-readable name for a MITRE ATT&CK technique ID.
    # Returns nil when the ID is not present in the bundle's mitre_names.json,
    # which can occur for pre-backfill rulesets or unknown technique IDs.
    def mitre_name(id : String) : String?
      @mitre_names.name_for(id)
    end

    # Reads a ruleset entry from the bundle by relative path (e.g. "rulesets/posix/grep.json").
    # Returns nil if the entry is not present.
    def read_entry(entry_path : String) : String?
      Compress::Zip::File.open(path.to_s) do |zip|
        entry = zip[entry_path]?
        entry.try(&.open(&.gets_to_end))
      end
    end

    private def load_mitre_names : MitreNames
      Compress::Zip::File.open(path.to_s) do |zip|
        entry = zip["mitre_names.json"]?
        if entry
          json = entry.open(&.gets_to_end)
          MitreNames.from_json(json)
        else
          MitreNames.new
        end
      end
    rescue ex : JSON::ParseException
      raise ManifestError.new("Failed to parse mitre_names.json in #{path}: #{ex.message}")
    end

    private def load_manifest : BundleManifest
      Compress::Zip::File.open(path.to_s) do |zip|
        entry = zip["manifest.json"]?
        raise ManifestError.new("Bundle is missing manifest.json: #{path}") unless entry
        json = entry.open(&.gets_to_end)
        BundleManifest.from_json(json)
      end
    rescue ex : JSON::ParseException
      raise ManifestError.new("Failed to parse manifest.json in #{path}: #{ex.message}")
    end

    private def check_engine_compatibility : Nil
      engine_version = Commandant::Version::VERSION
      unless manifest.engine_compatible?(engine_version)
        raise IncompatibleEngineError.new(
          "Bundle requires commandant >= #{manifest.commandant_min_version}, " \
          "but running #{engine_version}."
        )
      end
    end

    private def verify_zip_checksum(expected_hex : String) : Nil
      actual_hex = Digest::SHA256.hexdigest(File.read(path.to_s))
      unless actual_hex == expected_hex
        raise ChecksumMismatchError.new(
          "Bundle checksum mismatch: #{path}\n" \
          "  expected: #{expected_hex}\n" \
          "  actual:   #{actual_hex}"
        )
      end
    end

    private def read_checksum_file(checksum_path : Path) : String
      content = File.read(checksum_path.to_s)
      normalise_checksum(content)
    rescue ex : File::NotFoundError
      raise Error.new("Checksum file not found: #{checksum_path}")
    end

    # Accepts either a raw 64-char hex digest or a full sha256sum line
    # ("<hex>  <filename>"). Strips whitespace and takes the first token.
    private def normalise_checksum(raw : String) : String
      raw.strip.split(/\s+/).first.downcase
    end
  end
end
