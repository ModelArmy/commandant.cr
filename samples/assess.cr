require "../src/commandant"
require "colorize"

USAGE = "Usage: assess CMDSEQ"

cmd = ARGV.join(' ')
abort(USAGE) unless !(cmd.strip.blank?)

rulesets_path = Path[ENV["RULESETS_PATH"]? || "./rulesets"]
allowed = ENV["ALLOWED_TOOLS"]?.try(&.split(/\s+/)) || %w[find grep sed cat ls]

abort "FATAL: Cannot find rulesets path: #{rulesets_path}" unless Dir.exists?(rulesets_path)

puts "#{"FOUND".colorize(:green)} rulesets folder: #{rulesets_path}"

assessor = Commandant::Assessor.new(
  ruleset_path: rulesets_path,
  sandbox_root: Path["./"],
  allowed_tools: allowed
)

assessment = assessor.assess(cmd)

puts "#{"WARNING".colorize(:red).bold}: Unknown tool: #{assessment.command.binary}" unless assessment.tool_known?

puts assessment.to_pretty_json
