require "../src/commandant"
require "colorize"

def show_confirmation(response : Commandant::AssessmentResponse, bundle : Commandant::RulesetBundle? = nil)
  puts "Command:   #{response.command.raw}"
  puts "Risk:      #{response.overall_risk}"
  puts "Readonly?  #{response.readonly?}"
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
  if techniques = response.mitre_attack
    unless techniques.empty?
      puts
      puts "  ATT&CK techniques:"
      techniques.each do |id|
        name = bundle.try(&.mitre_name(id)) || id
        puts "    #{id}  #{name}"
      end
    end
  end
  puts
end

USAGE = "Usage: assess CMDSEQ\n\nSet RULESETS_PATH environment variable to rulesets folder or bundle ZIP."

cmd = ARGV.join(' ')
abort(USAGE) unless !(cmd.strip.blank?)

rulesets = Path[ENV["RULESETS_PATH"]? || "./rulesets"]
allowed = ENV["ALLOWED_TOOLS"]?.try(&.split(/\s+/)) || %w[find grep sed cat ls]

bundle = if rulesets.to_s.downcase.ends_with?(".zip") && File.exists?(rulesets)
           checksum_path = "#{rulesets}.sha256"
           Commandant::RulesetBundle.new(
             rulesets,
             checksum_path: File.exists?(checksum_path) ? Path.new(checksum_path) : nil)
         else
           abort "FATAL: Cannot find rulesets path: #{rulesets}" unless Dir.exists?(rulesets)
         end
puts "#{"FOUND".colorize(:green)} rulesets: #{rulesets}"

assessor = if bundle
             Commandant::Assessor.from_bundle(bundle,
               sandbox_root: Path["./"],
               allowed_tools: allowed
             )
           else
             Commandant::Assessor.new(
               ruleset_path: rulesets,
               sandbox_root: Path["./"],
               allowed_tools: allowed
             )
           end

assessment = assessor.assess(cmd)

puts "#{"WARNING".colorize(:red).bold}: Unknown tool: #{assessment.command.binary}" unless assessment.tool_known?
puts

show_confirmation(assessment, bundle)

puts "---"
puts assessment.to_pretty_json
