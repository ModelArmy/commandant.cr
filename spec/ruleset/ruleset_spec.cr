require "../spec_helper"

Spectator.describe Commandant::Ruleset do
  describe ".from_file" do
    it "loads grep posix ruleset" do
      ruleset = described_class.from_file(RULESETS_PATH / "posix/grep.json")
      expect(ruleset.tool).to eq("grep")
      expect(ruleset.platform).to eq("posix")
      expect(ruleset.rules).not_to be_empty
    end

    it "loads find posix ruleset" do
      ruleset = described_class.from_file(RULESETS_PATH / "posix/find.json")
      expect(ruleset.tool).to eq("find")
      expect(ruleset.default_rule).not_to be_nil
    end

    it "loads sed linux ruleset" do
      ruleset = described_class.from_file(RULESETS_PATH / "linux/sed.json")
      expect(ruleset.tool).to eq("sed")
      expect(ruleset.platform).to eq("linux")
    end

    it "populates option_abbreviations when present" do
      ruleset = described_class.from_file(RULESETS_PATH / "posix/cat.json")
      expect(ruleset.option_abbreviations).not_to be_nil
    end

    it "sets is_multiplexer correctly" do
      ruleset = described_class.from_file(RULESETS_PATH / "posix/grep.json")
      expect(ruleset.is_multiplexer?).to be_false
    end

    it "deserialises mitre_attack as nil when field is absent" do
      # Uses a controlled fixture that will never have mitre_attack backfilled —
      # stable regardless of live ruleset changes.
      ruleset = described_class.from_file(FIXTURES_PATH / "rulesets/posix/echo.json")
      expect(ruleset.rules.all? { |r| r.mitre_attack.nil? }).to be_true
    end
  end
end

Spectator.describe Commandant::RulesetStore do
  let(store) do
    described_class.new(
      base_path: RULESETS_PATH,
      platform: "linux"
    )
  end

  describe "#known?" do
    it "returns true for a tool with a committed ruleset" do
      expect(store.known?("grep")).to be_true
    end

    it "returns true for posix fallback" do
      expect(store.known?("ls")).to be_true
    end

    it "returns false for unknown tool" do
      expect(store.known?("curl")).to be_false
    end
  end

  describe "#load" do
    it "loads a ruleset by tool name" do
      ruleset = store.load("grep")
      expect(ruleset).not_to be_nil
      expect(ruleset.not_nil!.tool).to eq("grep")
    end

    it "returns nil for unknown tool" do
      expect(store.load("notarealtool")).to be_nil
    end

    it "caches on second load" do
      first = store.load("grep")
      second = store.load("grep")
      expect(first.object_id).to eq(second.object_id)
    end

    context "platform priority" do
      let(linux_store) do
        Commandant::RulesetStore.new(
          base_path: RULESETS_PATH,
          platform: "linux"
        )
      end

      it "prefers linux over posix for sed" do
        ruleset = linux_store.load("sed")
        expect(ruleset.not_nil!.platform).to eq("linux")
      end

      it "falls back to posix for grep" do
        ruleset = linux_store.load("grep")
        expect(ruleset.not_nil!.platform).to eq("posix")
      end
    end

    context "mitre_attack warnings" do
      let(fixture_store) do
        described_class.new(
          base_path: FIXTURES_PATH / "rulesets",
          platform: "posix"
        )
      end

      it "loads rulesets with missing mitre_attack without raising" do
        # Uses the echo fixture which has no mitre_attack field —
        # stable regardless of live ruleset backfill progress.
        ruleset = fixture_store.load("echo")
        expect(ruleset).not_to be_nil
        expect(ruleset.not_nil!.rules.all? { |r| r.mitre_attack.nil? }).to be_true
      end
    end
  end
end
