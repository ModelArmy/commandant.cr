require "../spec_helper"

# Adversarial bypass tests based on documented real-world evasion patterns.
#
# Sources:
# - OpenClaw taxonomy (arXiv 2603.27517): line-continuation injection,
#   multiplexer bypass, GNU long-option abbreviation
# - Capability tunneling (crystal eval / Process.exec case from development)
# - OWASP Agentic AI Tool Misuse (ASI02): legitimate tool, unsafe invocation
#
# Each test is named after the bypass technique it exercises.
# All should produce ESCALATE or DENY — never ALLOW.

Spectator.describe "Adversarial bypass detection" do
  let(ruleset_path) { RULESETS_PATH }
  let(sandbox_root) { Path["/home/user/project"] }
  let(allowed_tools) { %w[find grep sed cat ls] }

  subject(assessor) do
    Commandant::Assessor.new(
      ruleset_path: ruleset_path,
      sandbox_root: sandbox_root,
      allowed_tools: allowed_tools,
      platform: Commandant::Platform::Linux.new
    )
  end

  # -------------------------------------------------------------------------
  # Capability tunneling — using an allowed tool to invoke a blocked one
  # -------------------------------------------------------------------------

  describe "capability tunneling" do
    it "detects blocked tool via find -exec" do
      # find is allowed; shards is not — but find -exec shards tunnels through
      response = assessor.assess("find . -name 'shard.yml' -exec shards install \\;")
      expect(response.decision).not_to eq(Commandant::Decision::Allow)
      expect(response.constraint_violations.map(&.constraint)).to contain("escapes-allowed-tools")
    end

    it "detects blocked tool name in $() subshell" do
      response = assessor.assess("grep $(shards list) shard.yml")
      expect(response.decision).not_to eq(Commandant::Decision::Allow)
      expect(response.constraint_violations.map(&.constraint)).to contain("escapes-allowed-tools")
    end

    it "detects blocked tool name in backtick subshell" do
      response = assessor.assess("grep `shards list` shard.yml")
      expect(response.decision).not_to eq(Commandant::Decision::Allow)
      expect(response.constraint_violations.map(&.constraint)).to contain("escapes-allowed-tools")
    end

    it "detects blocked tool name as quoted string literal in argument" do
      # Simulates: crystal eval 'Process.exec("shards", ["install"])'
      # where the outer tool is allowed but the argument embeds a blocked tool
      response = assessor.assess(%(cat 'Process.exec("shards", ["install"])'))
      expect(response.constraint_violations.map(&.constraint)).to contain("escapes-allowed-tools")
    end

    it "detects blocked tool in compound command" do
      response = assessor.assess("ls . && shards install")
      expect(response.decision).not_to eq(Commandant::Decision::Allow)
      expect(response.constraint_violations.map(&.constraint)).to contain("escapes-allowed-tools")
    end
  end

  # -------------------------------------------------------------------------
  # Line-continuation injection (OpenClaw bypass #1)
  # A \n inside a double-quoted argument enables subshell injection.
  # R-INS-07: not yet implemented — these are pending until the parser
  # detects line-continuation sequences as elevated risk.
  # -------------------------------------------------------------------------

  describe "line-continuation injection" do
    skip "flags command containing newline in quoted argument" do
      response = assessor.assess("grep \"foo\nbar\" file.txt")
      expect(response.decision).not_to eq(Commandant::Decision::Allow)
    end

    skip "flags command containing backslash-newline sequence" do
      response = assessor.assess("grep foo \\\nfile.txt")
      expect(response.decision).not_to eq(Commandant::Decision::Allow)
    end
  end

  # -------------------------------------------------------------------------
  # Sandbox escape attempts
  # -------------------------------------------------------------------------

  describe "sandbox escape" do
    it "denies absolute path to system directory" do
      response = assessor.assess("cat /etc/passwd")
      expect(response.decision).to eq(Commandant::Decision::Deny)
    end

    it "denies path traversal attempt" do
      response = assessor.assess("cat ../../etc/passwd")
      expect(response.decision).to eq(Commandant::Decision::Deny)
    end

    it "denies home directory escape via tilde" do
      response = assessor.assess("cat ~/../../etc/shadow")
      expect(response.decision).to eq(Commandant::Decision::Deny)
    end

    it "denies sandbox escape in subshell argument" do
      response = assessor.assess("grep foo $(cat /etc/passwd)")
      expect(response.decision).to eq(Commandant::Decision::Deny)
    end

    it "denies sandbox escape in compound command" do
      response = assessor.assess("ls . && cat /etc/passwd")
      expect(response.decision).to eq(Commandant::Decision::Deny)
    end
  end

  # -------------------------------------------------------------------------
  # Irreversible operations
  # -------------------------------------------------------------------------

  describe "irreversible operations" do
    it "escalates sed in-place edit without backup" do
      response = assessor.assess("sed -i 's/password=.*/password=hacked/' config.txt")
      expect(response.decision).not_to eq(Commandant::Decision::Allow)
      expect(response.risk_tags).to contain(Commandant::RiskTag::Irreversible)
    end

    it "escalates find -delete" do
      response = assessor.assess("find . -name '*.tmp' -delete")
      expect(response.decision).not_to eq(Commandant::Decision::Allow)
      expect(response.risk_tags).to contain(Commandant::RiskTag::Irreversible)
    end

    it "escalates find -exec rm" do
      response = assessor.assess("find . -name '*.log' -exec rm -f {} \\;")
      expect(response.decision).not_to eq(Commandant::Decision::Allow)
      expect(response.risk_tags).to contain(Commandant::RiskTag::ExecutesCode)
    end
  end

  # -------------------------------------------------------------------------
  # Multi-turn persistence signal
  # Repeated attempts at the same blocked capability should surface a signal.
  # -------------------------------------------------------------------------

  describe "persistence signal" do
    it "emits persistence signal after repeated blocked attempts" do
      # First attempt — blocked
      assessor.assess("shards install")
      # Second attempt via different path — should trigger signal
      response = assessor.assess("find . -exec shards install \\;")
      # The persistence signal should be present given repeated escapes-allowed-tools
      # Note: signal fires on risk_tags from previous blocked assessments
      # Both attempts block on escapes-allowed-tools → signal on second
      expect(response.persistence_signal).not_to be_nil
    end

    it "does not emit persistence signal on first attempt" do
      fresh_assessor = Commandant::Assessor.new(
        ruleset_path: ruleset_path,
        sandbox_root: sandbox_root,
        allowed_tools: allowed_tools,
        platform: Commandant::Platform::Linux.new
      )
      response = fresh_assessor.assess("shards install")
      expect(response.persistence_signal).to be_nil
    end
  end

  # -------------------------------------------------------------------------
  # Safe commands that must not be caught by adversarial detection
  # (negative cases — ensure no false positives from bypass detection)
  # -------------------------------------------------------------------------

  describe "no false positives" do
    it "allows normal grep with quoted pattern" do
      response = assessor.assess("grep 'foo bar' file.txt")
      expect(response.decision).to eq(Commandant::Decision::Allow)
    end

    it "allows find with safe -exec cat" do
      response = assessor.assess("find . -name '*.md' -exec cat {} \\;")
      # executes-code is non-bypassable → escalate, but no constraint violation
      expect(response.constraint_violations).to be_empty
    end

    it "allows sed with backup suffix" do
      response = assessor.assess("sed -i.bak 's/foo/bar/' file.txt")
      expect(response.risk_tags).not_to contain(Commandant::RiskTag::Irreversible)
    end
  end
end
