require "spectator"
require "../src/commandant"

FIXTURES_PATH = Path[__DIR__] / "fixtures"
RULESETS_PATH = FIXTURES_PATH / "rulesets"

Spectator.configure do |config|
  config.fail_blank
  config.randomize
end
