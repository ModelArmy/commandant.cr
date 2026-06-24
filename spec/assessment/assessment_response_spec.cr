require "../spec_helper"

# Specs for AssessmentResponse#readonly?
#
# readonly? requires all three conditions to hold:
#   1. decision is Allow
#   2. mitre_attack is [] (not nil — nil means pre-backfill/unknown)
#   3. no write-side risk tag in the unioned risk_tags
#
# Fixture notes:
#   - true.json  — mitre_attack: [] on all rules and default; risk_tags: []
#   - grep.json  — default_rule has no mitre_attack field (pre-backfill → nil)
#   - cat.json   — write-side rules (cat > file, cat >> file) have mitre_attack: [...]
#   - sed.json   — write-side rules but mitre_attack absent (nil); covers nil guard

Spectator.describe Commandant::AssessmentResponse do
  let(sandbox_root) { Path["/home/user/project"] }

  # Assessor scoped to tools present in fixtures.
  let(assessor) do
    Commandant::Assessor.new(
      ruleset_path: RULESETS_PATH,
      sandbox_root: sandbox_root,
      allowed_tools: %w[true grep cat sed find ls],
      platform: Commandant::Platform::Linux.new
    )
  end

  describe "#readonly?" do
    context "when decision is Allow, mitre_attack is [], and only read-side tags" do
      it "returns true for `true` (no flags)" do
        response = assessor.assess("true")
        expect(response.readonly?).to be_true
      end

      it "returns true for `true --help`" do
        response = assessor.assess("true --help")
        expect(response.readonly?).to be_true
      end
    end

    context "when decision is Allow but mitre_attack is nil (pre-backfill ruleset)" do
      it "returns false for plain grep (default rule has no mitre_attack field)" do
        response = assessor.assess("grep foo file.txt")
        expect(response.decision).to eq(Commandant::Decision::Allow)
        expect(response.mitre_attack).to be_nil
        expect(response.readonly?).to be_false
      end
    end

    context "when a write-side risk tag is present" do
      it "returns false for cat redirecting to a file (writes-files)" do
        response = assessor.assess("cat README.md > output.txt")
        expect(response.risk_tags).to contain(Commandant::RiskTag::WritesFiles)
        expect(response.readonly?).to be_false
      end

      it "returns false for cat appending to a file (writes-files)" do
        response = assessor.assess("cat README.md >> output.txt")
        expect(response.risk_tags).to contain(Commandant::RiskTag::WritesFiles)
        expect(response.readonly?).to be_false
      end
    end

    context "when decision is not Allow" do
      it "returns false when Escalate" do
        response = assessor.assess("find . -exec cat {} \\;")
        expect(response.decision).to eq(Commandant::Decision::Escalate)
        expect(response.readonly?).to be_false
      end

      it "returns false when Deny" do
        response = assessor.assess("find /etc -name '*.conf'")
        expect(response.decision).to eq(Commandant::Decision::Deny)
        expect(response.readonly?).to be_false
      end
    end
  end
end
