# commandant.cr

Crystal shard for semantic shell command risk assessment. Parses commands, evaluates them against structured rulesets, and returns a structured verdict.

> **WARNING**: This shard is a work in progress and in development until this warning is removed.

> See [DISCLOSURE](./DISCLOSURE.md) for information how AI is used by this project.


## Installation

1. Add the dependency to your `shard.yml`:

```yml
dependencies:
  commandant:
    github: modelarmy/commandant.cr
```

2. Run `shards install`

## Usage

`commandant` intercepts a proposed shell command, assesses its risk against committed rulesets, and returns a structured verdict. Your agent calls `assess` before executing any shell command and acts on the response.

### Setup

Create an `Assessor` with your sandbox boundary, allowed tools, and the path to your rulesets. The rulesets from [`commandant-rules-core`](https://github.com/ModelArmy/commandant-rules-core) cover the common POSIX coding assistant tools and Windows `forfiles`.

```crystal
require "commandant"

assessor = Commandant::Assessor.new(
  ruleset_path:  Path["./rulesets"],          # path to your commandant-rules-core checkout
  sandbox_root:  Path[Dir.current],           # commands must stay within this directory
  allowed_tools: %w[find grep sed cat ls]     # tools your agent is permitted to use
)
```

The platform is resolved automatically at compile time (Linux, macOS, or Windows). You can override it explicitly:

```crystal
assessor = Commandant::Assessor.new(
  ruleset_path:  Path["./rulesets"],
  sandbox_root:  Path[Dir.current],
  allowed_tools: %w[find grep sed cat ls],
  platform:      Commandant::Platform::MacOS.new   # explicit override
)
```

### Assessing a command

Call `assess` with the raw command string your agent wants to run:

```crystal
response = assessor.assess("find . -name '*.cr' -exec grep TODO {} \;")

case response.decision
in .allow?    then run_command(command)
in .escalate? then ask_user(response)
in .deny?     then reject(response)
end
```

The three decisions map to:

|Decision  |Meaning                         |When                                                                          |
|----------|--------------------------------|------------------------------------------------------------------------------|
|`Allow`   |Safe to run without interruption|No risky flags, no constraint violations                                      |
|`Escalate`|Present to user for confirmation|Non-bypassable tags (`executes-code`, `irreversible`) or constraint violations|
|`Deny`    |Hard block — do not run         |Command escapes the sandbox boundary                                          |

### The response

`AssessmentResponse` carries everything you need to build a confirmation prompt:

```crystal
response = assessor.assess("sed -i 's/foo/bar/' config.cr")

response.decision          # => Escalate
response.overall_risk      # => High
response.risk_tags         # => [WritesFiles, Irreversible]
response.reversible        # => No
response.constraint_violations  # => []
response.tool_known        # => true

# Serialise to JSON for logging or protocol use
puts response.to_pretty_json
```

A minimal confirmation table from the response:

```crystal
def show_confirmation(response : Commandant::AssessmentResponse)
  puts "Command: #{response.command.raw}"
  puts "Risk:    #{response.overall_risk}"
  puts
  response.risk_tags.each do |tag|
    puts "  ⚠️  #{tag}"
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
  print "Proceed? [y/N] "
  gets.try(&.strip.downcase) == "y"
end
```

### Non-bypassable tags

Two tags always force `Escalate` regardless of your policy configuration:

- **`executes-code`** — the command invokes another binary or shell. `find -exec`, `sed -f script.sed`, subshells.
- **`irreversible`** — the effect cannot be undone without a backup. `sed -i` without a suffix, `find -delete`.

A sandbox escape (`escapes-sandbox`) always forces `Deny`.

### Persistence signal

When an agent repeatedly attempts a blocked capability via different command paths — the capability tunneling pattern — the response includes a `persistence_signal`:

```crystal
# First attempt — blocked
assessor.assess("shards install")

# Second attempt via a different path
response = assessor.assess("find . -exec shards install \;")
if sig = response.persistence_signal
  # sig.risk_tag      => ExecutesCode
  # sig.attempt_count => 2
  warn "Agent is repeatedly attempting a blocked capability"
end
```

## Development

See [DEVELOPMENT.md](./DEVELOPMENT.md) for how to build, run the samples, and understand the internals.

## Contributions, by invitation!

*With apologies*, at this time contributions are *by invitation only* and limited to people I know and see often.

These are early days for _Commandant_ and I am busy with family and work.

At this time I want to work on this at a manageable pace.
