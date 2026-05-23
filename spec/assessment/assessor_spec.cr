require "../spec_helper"

Spectator.describe Commandant::Assessor do
  let(ruleset_path) { RULESETS_PATH }
  let(sandbox_root) { Path["/home/user/project"] }
  let(allowed_tools) { %w[find grep sed cat ls] }

  subject(assessor) do
    described_class.new(
      ruleset_path: ruleset_path,
      sandbox_root: sandbox_root,
      allowed_tools: allowed_tools,
      platform: Commandant::Platform::Linux.new
    )
  end

  describe "#assess" do
    context "unknown tool" do
      it "escalates with tool_known false" do
        response = assessor.assess("curl https://example.com")
        expect(response.tool_known?).to be_false
        expect(response.decision).to eq(Commandant::Decision::Escalate)
      end
    end

    context "safe commands" do
      it "allows plain ls" do
        response = assessor.assess("ls /home/user/project")
        expect(response.decision).to eq(Commandant::Decision::Allow)
        expect(response.risk_tags).to contain(Commandant::RiskTag::ReadsFiles)
      end

      it "allows plain grep" do
        response = assessor.assess("grep foo file.txt")
        expect(response.decision).to eq(Commandant::Decision::Allow)
      end

      it "allows cat on a file" do
        response = assessor.assess("cat README.md")
        expect(response.decision).to eq(Commandant::Decision::Allow)
      end
    end

    context "find -exec (executes-code)" do
      it "escalates find with -exec" do
        response = assessor.assess("find . -name '*.log' -exec cat {} \\;")
        expect(response.decision).to eq(Commandant::Decision::Escalate)
        expect(response.risk_tags).to contain(Commandant::RiskTag::ExecutesCode)
      end

      it "sets non_bypassable_tags for executes-code" do
        response = assessor.assess("find . -exec rm {} \\;")
        expect(response.non_bypassable_tags).to contain(Commandant::RiskTag::ExecutesCode)
      end
    end

    context "sandbox escape" do
      it "denies absolute path outside sandbox" do
        response = assessor.assess("find /etc -name '*.conf'")
        expect(response.decision).to eq(Commandant::Decision::Deny)
        expect(response.constraint_violations.map(&.constraint)).to contain("escapes-sandbox")
      end
    end

    context "sed in-place" do
      it "escalates sed -i (irreversible)" do
        response = assessor.assess("sed -i 's/foo/bar/' file.txt")
        expect(response.decision).to eq(Commandant::Decision::Escalate)
        expect(response.risk_tags).to contain(Commandant::RiskTag::Irreversible)
      end

      it "allows sed -i.bak (with backup)" do
        response = assessor.assess("sed -i.bak 's/foo/bar/' file.txt")
        expect(response.risk_tags).to contain(Commandant::RiskTag::WritesFiles)
        expect(response.risk_tags).not_to contain(Commandant::RiskTag::Irreversible)
      end
    end

    context "disallowed tool" do
      it "escalates with escapes-allowed-tools violation" do
        response = assessor.assess("shards install")
        expect(response.decision).to eq(Commandant::Decision::Escalate)
      end
    end

    context "response structure" do
      it "includes assessment_latency_ms" do
        response = assessor.assess("grep foo file.txt")
        expect(response.assessment_latency_ms).to be > 0.0
      end

      it "serialises to valid JSON" do
        response = assessor.assess("grep foo file.txt")
        json = response.to_json
        parsed = JSON.parse(json)
        expect(parsed["decision"]).not_to be_nil
        expect(parsed["risk_tags"]).not_to be_nil
      end
    end
  end
end
