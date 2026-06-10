require "../spec_helper"

BUNDLE_PATH          = FIXTURES_PATH / "bundles/test-bundle-v0.4.0.zip"
BUNDLE_CHECKSUM_PATH = FIXTURES_PATH / "bundles/test-bundle-v0.4.0.zip.sha256"
BUNDLE_CHECKSUM_HEX  = File.read(BUNDLE_CHECKSUM_PATH).strip.split(/\s+/).first

Spectator.describe Commandant::RulesetBundle do
  describe ".new" do
    context "without checksum" do
      it "loads and parses the manifest" do
        bundle = described_class.new(path: BUNDLE_PATH)
        expect(bundle.manifest.version).to eq("v0.4.0")
        expect(bundle.manifest.commandant_min_version).to eq("0.4.0")
      end

      it "sets verification to None" do
        bundle = described_class.new(path: BUNDLE_PATH)
        expect(bundle.verification).to eq(Commandant::RulesetVerification::None)
      end

      it "exposes platform list from manifest" do
        bundle = described_class.new(path: BUNDLE_PATH)
        expect(bundle.manifest.platforms).to contain("posix")
      end

      it "exposes tool list from manifest" do
        bundle = described_class.new(path: BUNDLE_PATH)
        expect(bundle.manifest.tools).to contain("grep")
        expect(bundle.manifest.tools).to contain("echo")
      end
    end

    context "with checksum_path" do
      it "sets verification to Bundle on match" do
        bundle = described_class.new(path: BUNDLE_PATH, checksum_path: BUNDLE_CHECKSUM_PATH)
        expect(bundle.verification).to eq(Commandant::RulesetVerification::Bundle)
      end

      it "raises ChecksumMismatchError when checksum file does not match" do
        bad_checksum = FIXTURES_PATH / "bundles/bad.sha256"
        File.write(bad_checksum.to_s, "0000000000000000000000000000000000000000000000000000000000000000  test-bundle-v0.4.0.zip\n")
        expect do
          described_class.new(path: BUNDLE_PATH, checksum_path: bad_checksum)
        end.to raise_error(Commandant::RulesetBundle::ChecksumMismatchError)
        File.delete(bad_checksum.to_s)
      end

      it "raises Error when checksum file is missing" do
        expect do
          described_class.new(path: BUNDLE_PATH, checksum_path: Path["nonexistent.sha256"])
        end.to raise_error(Commandant::RulesetBundle::Error)
      end
    end

    context "with checksum string" do
      it "sets verification to Bundle when hex digest matches" do
        bundle = described_class.new(path: BUNDLE_PATH, checksum: BUNDLE_CHECKSUM_HEX)
        expect(bundle.verification).to eq(Commandant::RulesetVerification::Bundle)
      end

      it "accepts full sha256sum line format" do
        full_line = "#{BUNDLE_CHECKSUM_HEX}  test-bundle-v0.4.0.zip"
        bundle = described_class.new(path: BUNDLE_PATH, checksum: full_line)
        expect(bundle.verification).to eq(Commandant::RulesetVerification::Bundle)
      end

      it "raises ChecksumMismatchError when string does not match" do
        expect do
          described_class.new(path: BUNDLE_PATH, checksum: "0" * 64)
        end.to raise_error(Commandant::RulesetBundle::ChecksumMismatchError)
      end
    end

    it "raises Error when both checksum_path and checksum are provided" do
      expect do
        described_class.new(
          path: BUNDLE_PATH,
          checksum_path: BUNDLE_CHECKSUM_PATH,
          checksum: BUNDLE_CHECKSUM_HEX,
        )
      end.to raise_error(Commandant::RulesetBundle::Error)
    end
  end

  describe "#verify!" do
    context "starting from None" do
      it "upgrades verification to Entries on success" do
        bundle = described_class.new(path: BUNDLE_PATH)
        bundle.verify!
        expect(bundle.verification).to eq(Commandant::RulesetVerification::Entries)
      end

      it "returns self for chaining" do
        bundle = described_class.new(path: BUNDLE_PATH)
        expect(bundle.verify!).to be(bundle)
      end
    end

    context "starting from Bundle" do
      it "upgrades verification to Full on success" do
        bundle = described_class.new(path: BUNDLE_PATH, checksum: BUNDLE_CHECKSUM_HEX)
        bundle.verify!
        expect(bundle.verification).to eq(Commandant::RulesetVerification::Full)
      end
    end

    context "starting from Full" do
      it "remains Full when called again" do
        bundle = described_class.new(path: BUNDLE_PATH, checksum: BUNDLE_CHECKSUM_HEX)
        bundle.verify!
        bundle.verify!
        expect(bundle.verification).to eq(Commandant::RulesetVerification::Full)
      end
    end
  end

  describe "#read_entry" do
    it "returns JSON content for a present entry" do
      bundle = described_class.new(path: BUNDLE_PATH)
      content = bundle.read_entry("rulesets/posix/grep.json")
      expect(content).not_to be_nil
      expect(content.not_nil!).to contain("\"tool\": \"grep\"")
    end

    it "returns nil for an absent entry" do
      bundle = described_class.new(path: BUNDLE_PATH)
      expect(bundle.read_entry("rulesets/posix/nonexistent.json")).to be_nil
    end
  end
end

Spectator.describe Commandant::RulesetStore do
  describe ".from_bundle" do
    let(bundle) { Commandant::RulesetBundle.new(path: BUNDLE_PATH) }
    let(store) { described_class.from_bundle(bundle, platform: "linux") }

    it "loads a ruleset from the bundle" do
      ruleset = store.load("grep")
      expect(ruleset).not_to be_nil
      expect(ruleset.not_nil!.tool).to eq("grep")
    end

    it "falls back to posix when platform-specific entry is absent" do
      # grep is posix-only in fixtures; linux store should find it
      ruleset = store.load("grep")
      expect(ruleset).not_to be_nil
      expect(ruleset.not_nil!.platform).to eq("posix")
    end

    it "prefers platform-specific entry when present" do
      # sed has a linux entry in fixtures
      ruleset = store.load("sed")
      expect(ruleset).not_to be_nil
      expect(ruleset.not_nil!.platform).to eq("linux")
    end

    it "returns nil for a tool not in the bundle" do
      expect(store.load("curl")).to be_nil
    end

    it "caches ruleset after first load" do
      first = store.load("grep")
      second = store.load("grep")
      expect(first).to be(second)
    end

    it "reflects bundle verification level" do
      verified_bundle = Commandant::RulesetBundle.new(
        path: BUNDLE_PATH,
        checksum: BUNDLE_CHECKSUM_HEX
      )
      verified_store = described_class.from_bundle(verified_bundle, platform: "posix")
      expect(verified_store.verification).to eq(Commandant::RulesetVerification::Bundle)
    end
  end
end
