require "../src/commandant"
require "colorize"

def show_confirmation(response : Commandant::AssessmentResponse)
  puts "Command: #{response.command.raw}"
  puts "Risk:    #{response.overall_risk}"
  puts
  response.risk_tags.each do |tag|
    puts "  ⚠️ #{tag}"
  end
  unless response.constraint_violations.empty?
    response.constraint_violations.each do |v|
      puts "  🚫 #{v.constraint}: #{v.detail}"
    end
  end
  if sig = response.persistence_signal
    puts
    puts "  ⚡ Repeated attempt: #{sig.risk_tag} tried #{sig.attempt_count} times"
  end
  puts
end

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
puts

show_confirmation(assessment)

puts "---"
puts assessment.to_pretty_json
