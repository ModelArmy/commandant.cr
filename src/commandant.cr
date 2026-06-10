require "./commandant/assessment/flag"
require "./commandant/assessment/parsed_command"
require "./commandant/ruleset/match_spec"
require "./commandant/ruleset/rule"
require "./commandant/ruleset/ruleset"
require "./commandant/bundle/ruleset_verification"
require "./commandant/bundle/bundle_manifest"
require "./commandant/bundle/ruleset_bundle"
require "./commandant/ruleset/ruleset_store"
require "./commandant/parser/base"
require "./commandant/parser/posix_parser"
require "./commandant/parser/cmd_parser"
require "./commandant/parser/powershell_parser"
require "./commandant/platform/base"
require "./commandant/platform/posix"
require "./commandant/platform/linux"
require "./commandant/platform/macos"
require "./commandant/platform/windows"
require "./commandant/assessment/evaluator"
require "./commandant/assessment/constraint_checker"
require "./commandant/assessment/persistence_tracker"
require "./commandant/assessment/assessment_response"
require "./commandant/assessment/assessor"

# **Commandant** is a shell command risk assessment library for AI agent tool calling.
#
# It intercepts proposed shell commands, evaluates them against committed rulesets,
# and returns a structured verdict before execution.
#
# Basic usage:
# ```
# assessor = Commandant::Assessor.new(
#   ruleset_path: Path["./rulesets"],
#   sandbox_root: Path["/home/user/project"],
#   allowed_tools: %w[find grep sed cat ls]
# )
#
# response = assessor.assess("find . -exec rm {} \\;")
#
# case response.decision
# in .allow?    then proceed
# in .escalate? then show_confirmation(response)
# in .deny?     then hard_block(response)
# end
# ```
module Commandant
  # :nodoc:
  module Version
    VERSION    = {{ `shards version #{__DIR__}`.chomp.stringify }}
    PRERELEASE = VERSION.match(/^\d+\.\d+\.\d+$/).nil?
  end
end
