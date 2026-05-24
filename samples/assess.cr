require "../src/commandant"

USAGE = "Usage: assess CMDSEQ"

cmd = ARGV.join(' ')
abort(USAGE) unless !(cmd.strip.blank?)

rulesets_path = Path[ENV["RULESETS_PATH"]? || "./rulesets"]
allowed = ENV["ALLOWED_TOOLS"]?.try(&.split(/\s+/)) || %w[find grep sed cat ls]

assessor = Commandant::Assessor.new(
  ruleset_path: rulesets_path,
  sandbox_root: Path["./"],
  allowed_tools: allowed
)

puts assessor.assess(cmd).to_pretty_json
