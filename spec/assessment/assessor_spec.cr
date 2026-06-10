require "../spec_helper"

Spectator.describe Commandant::Assessor do
  let(ruleset_path) { RULESETS_PATH }
  let(sandbox_root) { Path["/home/user/project"] }
  let(allowed_tools) { %w[find grep sed cat ls true] }

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

    context "compound commands" do
      it "surfaces risk tags from the dangerous half of a compound" do
        response = assessor.assess("ls . && find . -exec rm {} \\;")
        expect(response.risk_tags).to contain(Commandant::RiskTag::ExecutesCode)
      end

      it "escalates when a compound contains a non-bypassable tag" do
        response = assessor.assess("cat README.md; sed -i 's/foo/bar/' file.txt")
        expect(response.decision).to eq(Commandant::Decision::Escalate)
      end
    end

    context "subshell constraint checking" do
      it "detects blocked tool in argument string literals" do
        # crystal eval with single-quoted arg containing a blocked tool name
        response = assessor.assess("cat file.txt | grep $(shards --version)")
        expect(response.constraint_violations.map(&.constraint)).to contain("escapes-allowed-tools")
      end

      it "escalates when subshell command is a disallowed tool" do
        # $() subshell containing a blocked tool — use grep as outer (allowed)
        response = assessor.assess("grep $(shards install) file.txt")
        expect(response.decision).to eq(Commandant::Decision::Escalate)
        expect(response.constraint_violations.map(&.constraint)).to contain("escapes-allowed-tools")
      end

      it "allows safe subshell content" do
        response = assessor.assess("grep $(cat file.txt) other.txt")
        expect(response.constraint_violations.map(&.constraint)).not_to contain("escapes-allowed-tools")
      end
    end

    context "mitre_attack in response" do
      it "returns nil mitre_attack when no rules match (default rule only)" do
        # Plain grep matches no rules — falls through to default_rule which has
        # no mitre_attack. union_mitre_attack returns nil (unknown), not [] (none found).
        response = assessor.assess("grep foo file.txt")
        expect(response.mitre_attack).to be_nil
      end

      it "returns nil mitre_attack for unknown tools" do
        response = assessor.assess("curl https://example.com")
        expect(response.mitre_attack).to be_nil
      end

      it "returns populated mitre_attack when matched rules carry techniques" do
        # grep -r fires grep-recursive which has mitre_attack: ["T1083", "T1005"]
        response = assessor.assess("grep -r foo .")
        expect(response.mitre_attack).not_to be_nil
        expect(response.mitre_attack).to contain("T1083")
        expect(response.mitre_attack).to contain("T1005")
      end

      it "returns empty array when matched rules have mitre_attack present but empty" do
        # true --help fires true-help which has mitre_attack: [] — evaluated, none found
        response = assessor.assess("true --help")
        expect(response.mitre_attack).not_to be_nil
        expect(response.mitre_attack.not_nil!).to be_empty
      end
    end

    context "ruleset_verification in response" do
      it "returns None when using directory-based loader" do
        response = assessor.assess("grep foo file.txt")
        expect(response.ruleset_verification).to eq(Commandant::RulesetVerification::None)
      end

      it "returns None for unknown tools" do
        response = assessor.assess("curl https://example.com")
        expect(response.ruleset_verification).to eq(Commandant::RulesetVerification::None)
      end

      it "returns Bundle when assessor is backed by a verified bundle" do
        bundle = Commandant::RulesetBundle.new(
          path: FIXTURES_PATH / "bundles/test-bundle-v0.4.0.zip",
          checksum_path: FIXTURES_PATH / "bundles/test-bundle-v0.4.0.zip.sha256"
        )
        bundle_assessor = Commandant::Assessor.from_bundle(
          bundle: bundle,
          sandbox_root: Path["/tmp"],
          allowed_tools: %w[grep find cat ls sed],
        )
        response = bundle_assessor.assess("grep foo file.txt")
        expect(response.ruleset_verification).to eq(Commandant::RulesetVerification::Bundle)
      end

      it "returns Full when bundle has passed verify!" do
        bundle = Commandant::RulesetBundle.new(
          path: FIXTURES_PATH / "bundles/test-bundle-v0.4.0.zip",
          checksum_path: FIXTURES_PATH / "bundles/test-bundle-v0.4.0.zip.sha256"
        )
        bundle.verify!
        bundle_assessor = Commandant::Assessor.from_bundle(
          bundle: bundle,
          sandbox_root: Path["/tmp"],
          allowed_tools: %w[grep find cat ls sed],
        )
        response = bundle_assessor.assess("grep foo file.txt")
        expect(response.ruleset_verification).to eq(Commandant::RulesetVerification::Full)
      end
    end
  end
end
