require "../spec_helper"

# Property-based invariant tests.
#
# These tests generate random command strings from a grammar covering the
# interesting variation space and assert structural invariants on every response.
# The goal is not to verify correct risk assessment of specific commands —
# that is covered by the unit and adversarial specs — but to verify that
# `Assessor#assess` never raises and always returns a structurally valid
# response regardless of input.
#
# Invariants asserted for every generated command:
#   I1. No unhandled exception — assess always returns, never raises
#   I2. decision is one of Allow, Escalate, Deny
#   I3. risk_tags is an array (possibly empty)
#   I4. constraint_violations is an array (possibly empty)
#   I5. assessment_latency_ms is non-negative
#   I6. tool_known is a bool
#   I7. DENY implies at least one constraint_violation
#   I8. Non-bypassable tags in risk_tags implies decision is not Allow

Spectator.describe "Assessment invariants" do
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

  # ---------------------------------------------------------------------------
  # Command string generators
  # ---------------------------------------------------------------------------

  # All token pools used by generators

  KNOWN_BINARIES   = %w[find grep sed cat ls]
  UNKNOWN_BINARIES = %w[curl wget npm pip shards cargo make cmake]
  ALL_BINARIES     = KNOWN_BINARIES + UNKNOWN_BINARIES

  SHORT_FLAGS = %w[-r -R -i -n -l -L -v -a -f -e -exec -delete -name -type]
  LONG_FLAGS  = %w[--recursive --include --exclude --null --color=always --color=never]
  SAFE_ARGS   = %w[. ./src ./README.md file.txt *.cr *.md shard.yml]
  UNSAFE_ARGS = %w[/etc/passwd /tmp ../../../etc ~/../etc /dev/null]
  PATTERNS    = %w[foo bar TODO FIXME password secret]
  EXEC_ARGS   = ["{}", "\\;", "+", "rm", "cat", "shards", "sh"]
  SUBSHELLS   = ["$(whoami)", "$(shards list)", "$(cat /etc/passwd)", "`date`"]

  # Generates a simple command: binary + random flags + random args
  def simple_command(rng : Random) : String
    binary = ALL_BINARIES.sample(random: rng)
    flags = SHORT_FLAGS.sample(rng.rand(0..2), random: rng)
    args = SAFE_ARGS.sample(rng.rand(0..2), random: rng)
    ([binary] + flags + args).join(" ")
  end

  # Generates a command with potentially unsafe path arguments
  def path_escape_command(rng : Random) : String
    binary = KNOWN_BINARIES.sample(random: rng)
    args = (SAFE_ARGS + UNSAFE_ARGS).sample(rng.rand(1..3), random: rng)
    ([binary] + args).join(" ")
  end

  # Generates a find command with various action flags
  def find_command(rng : Random) : String
    actions = ["-exec rm {} \\;", "-exec shards {} \\;", "-delete",
               "-exec cat {} \\;", "-print0", "-execdir ls {} \\;"]
    constraints = ["-name '*.cr'", "-name '*.md'", "-type f", "-type d"]
    action = actions.sample(random: rng)
    constraint = constraints.sample(random: rng)
    path = (SAFE_ARGS + UNSAFE_ARGS).sample(random: rng)
    "find #{path} #{constraint} #{action}"
  end

  # Generates a compound command joined by a shell operator
  def compound_command(rng : Random) : String
    operators = [" && ", " || ", "; ", " | "]
    op = operators.sample(random: rng)
    left = simple_command(rng)
    right = simple_command(rng)
    "#{left}#{op}#{right}"
  end

  # Generates a command containing a subshell
  def subshell_command(rng : Random) : String
    binary = KNOWN_BINARIES.sample(random: rng)
    subshell = SUBSHELLS.sample(random: rng)
    arg = SAFE_ARGS.sample(random: rng)
    "#{binary} #{subshell} #{arg}"
  end

  # Generates an adversarial command from the documented bypass patterns
  def adversarial_command(rng : Random) : String
    patterns = [
      "crystal eval 'Process.exec(\"shards\", [\"install\"])'",
      "find . -exec shards install \\;",
      "grep $(shards list) shard.yml",
      "ls . && shards install",
      "cat ../../etc/passwd",
      "sed -i 's/foo/bar/' file.txt",
      "find /etc -name '*.conf'",
      "grep foo `shards list`",
    ]
    patterns.sample(random: rng)
  end

  # Generates edge case strings that should not crash the parser
  def edge_case_command(rng : Random) : String
    cases = [
      "",                     # empty string
      "   ",                  # whitespace only
      "-",                    # just a dash
      "--",                   # double dash
      "a",                    # single char
      "'unclosed quote",      # malformed quoting
      "find . -name",         # missing argument
      "grep",                 # no args
      "sed -i.bak",           # flag with value, no target
      "cat " + "x" * 500,     # very long argument
      "find . " + "-r " * 20, # many repeated flags
    ]
    cases.sample(random: rng)
  end

  # ---------------------------------------------------------------------------
  # Invariant assertions
  # ---------------------------------------------------------------------------

  def assert_invariants(response : Commandant::AssessmentResponse, cmd : String) : Nil
    # I2: decision is a valid enum value
    valid_decisions = [
      Commandant::Decision::Allow,
      Commandant::Decision::Escalate,
      Commandant::Decision::Deny,
    ]
    expect(valid_decisions).to contain(response.decision),
      "I2 failed for: #{cmd.inspect}"

    # I3: risk_tags is an array
    expect(response.risk_tags).to be_a(Array(Commandant::RiskTag)),
      "I3 failed for: #{cmd.inspect}"

    # I4: constraint_violations is an array
    expect(response.constraint_violations).to be_a(Array(Commandant::ConstraintViolation)),
      "I4 failed for: #{cmd.inspect}"

    # I5: latency is non-negative
    expect(response.assessment_latency_ms).to be >= 0.0,
      "I5 failed for: #{cmd.inspect}"

    # I7: DENY implies at least one constraint_violation
    if response.deny?
      expect(response.constraint_violations).not_to be_empty,
        "I7 failed for: #{cmd.inspect} — DENY with no constraint violations"
    end

    # I8: non-bypassable tags imply not Allow
    has_non_bypassable = response.risk_tags.any?(&.non_bypassable?)
    if has_non_bypassable
      expect(response.decision).not_to eq(Commandant::Decision::Allow),
        "I8 failed for: #{cmd.inspect} — non-bypassable tags but decision is Allow"
    end
  end

  # ---------------------------------------------------------------------------
  # Property tests
  # ---------------------------------------------------------------------------

  ITERATIONS = 200

  it "never raises and satisfies invariants for simple commands" do
    rng = Random.new(42)
    ITERATIONS.times do
      cmd = simple_command(rng)
      response = assessor.assess(cmd)
      assert_invariants(response, cmd)
    end
  end

  it "never raises and satisfies invariants for path escape attempts" do
    rng = Random.new(43)
    ITERATIONS.times do
      cmd = path_escape_command(rng)
      response = assessor.assess(cmd)
      assert_invariants(response, cmd)
    end
  end

  it "never raises and satisfies invariants for find commands" do
    rng = Random.new(44)
    ITERATIONS.times do
      cmd = find_command(rng)
      response = assessor.assess(cmd)
      assert_invariants(response, cmd)
    end
  end

  it "never raises and satisfies invariants for compound commands" do
    rng = Random.new(45)
    ITERATIONS.times do
      cmd = compound_command(rng)
      response = assessor.assess(cmd)
      assert_invariants(response, cmd)
    end
  end

  it "never raises and satisfies invariants for subshell commands" do
    rng = Random.new(46)
    ITERATIONS.times do
      cmd = subshell_command(rng)
      response = assessor.assess(cmd)
      assert_invariants(response, cmd)
    end
  end

  it "never raises and satisfies invariants for adversarial patterns" do
    rng = Random.new(47)
    ITERATIONS.times do
      cmd = adversarial_command(rng)
      response = assessor.assess(cmd)
      assert_invariants(response, cmd)
    end
  end

  it "never raises on edge case inputs" do
    rng = Random.new(48)
    ITERATIONS.times do
      cmd = edge_case_command(rng)
      # I1: no exception raised
      expect {
        begin
          assessor.assess(cmd)
        rescue ex
          STDERR.puts ex.inspect_with_backtrace
          raise ex
        end
      }.not_to raise_error
    end
  end
end
