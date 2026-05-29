require "../spec_helper"

Spectator.describe Commandant::Parser::CmdParser do
  subject(parser) { described_class.new }

  describe "#parse" do
    context "basic command" do
      it "extracts binary" do
        cmd = parser.parse("forfiles /P . /S")
        expect(cmd.binary).to eq("forfiles")
      end

      it "returns empty ParsedCommand for empty string" do
        cmd = parser.parse("")
        expect(cmd.binary).to eq("")
      end

      it "returns empty ParsedCommand for whitespace" do
        cmd = parser.parse("   ")
        expect(cmd.binary).to eq("")
      end
    end

    context "Windows /FLAG syntax" do
      it "parses single flag" do
        cmd = parser.parse("forfiles /S")
        expect(cmd.flag_canonicals).to contain("/S")
      end

      it "uppercases flag canonicals" do
        cmd = parser.parse("forfiles /s /p .")
        expect(cmd.flag_canonicals).to contain("/S")
        expect(cmd.flag_canonicals).to contain("/P")
      end

      it "parses flag with colon-separated value" do
        cmd = parser.parse("forfiles /M *.log /C \"cmd /c echo @file\"")
        expect(cmd.flag_canonicals).to contain("/M")
        expect(cmd.arguments).to contain("*.log")
      end

      it "preserves arguments" do
        cmd = parser.parse("forfiles /P . /S /M *.txt")
        expect(cmd.arguments).to contain(".")
        expect(cmd.arguments).to contain("*.txt")
      end
    end

    context "caret escape" do
      it "handles caret-escaped characters" do
        cmd = parser.parse("echo hello^&world")
        expect(cmd.arguments.first).to eq("hello&world")
      end
    end

    context "double-quoted arguments" do
      it "handles quoted argument with spaces" do
        cmd = parser.parse("forfiles /C \"cmd /c del @file\"")
        expect(cmd.arguments).to contain("cmd /c del @file")
      end
    end

    context "compound commands" do
      it "splits on & operator" do
        cmd = parser.parse("echo foo & echo bar")
        expect(cmd.binary).to eq("echo")
        expect(cmd.compounds.size).to eq(1)
        expect(cmd.compounds.first.binary).to eq("echo")
      end

      it "splits on && operator" do
        cmd = parser.parse("echo foo && echo bar")
        expect(cmd.binary).to eq("echo")
        expect(cmd.compounds.first.binary).to eq("echo")
      end

      it "splits on || operator" do
        cmd = parser.parse("echo foo || echo bar")
        expect(cmd.compounds.size).to eq(1)
      end
    end

    context "environment variables" do
      it "extracts %VAR% as subshell content" do
        cmd = parser.parse("echo %PATH%")
        expect(cmd.subshells).to contain("PATH")
      end
    end
  end
end

Spectator.describe Commandant::Parser::PowerShellParser do
  subject(parser) { described_class.new }

  describe "#parse" do
    context "basic command" do
      it "extracts binary" do
        cmd = parser.parse("Get-ChildItem -Path .")
        expect(cmd.binary).to eq("Get-ChildItem")
      end

      it "returns empty ParsedCommand for empty string" do
        cmd = parser.parse("")
        expect(cmd.binary).to eq("")
      end
    end

    context "PowerShell flag syntax" do
      it "parses single-dash flag" do
        cmd = parser.parse("Get-ChildItem -Recurse")
        expect(cmd.flag_canonicals).to contain("-Recurse")
      end

      it "parses double-dash flag" do
        cmd = parser.parse("git --version")
        expect(cmd.flag_canonicals).to contain("--version")
      end

      it "parses flag with colon-separated value" do
        cmd = parser.parse("Get-ChildItem -Path:C:\\Users")
        expect(cmd.flag_canonicals).to contain("-Path")
        expect(cmd.arguments).to contain("C:\\Users")
      end

      it "parses multiple flags" do
        cmd = parser.parse("Get-ChildItem -Recurse -Force -Path .")
        expect(cmd.flag_canonicals).to contain("-Recurse")
        expect(cmd.flag_canonicals).to contain("-Force")
        expect(cmd.flag_canonicals).to contain("-Path")
      end
    end

    context "quoting" do
      it "handles single-quoted strings" do
        cmd = parser.parse("Write-Host 'hello world'")
        expect(cmd.arguments).to contain("hello world")
      end

      it "handles double-quoted strings" do
        cmd = parser.parse("Write-Host \"hello world\"")
        expect(cmd.arguments).to contain("hello world")
      end
    end

    context "backtick escape" do
      it "handles backtick-escaped characters" do
        cmd = parser.parse("Write-Host hello`nworld")
        expect(cmd.arguments.first).to eq("hellonworld")
      end
    end

    context "compound commands" do
      it "splits on semicolon" do
        cmd = parser.parse("Get-Date; Get-Location")
        expect(cmd.binary).to eq("Get-Date")
        expect(cmd.compounds.first.binary).to eq("Get-Location")
      end

      it "splits on && operator" do
        cmd = parser.parse("echo foo && echo bar")
        expect(cmd.compounds.size).to eq(1)
      end

      it "splits on || operator" do
        cmd = parser.parse("echo foo || echo bar")
        expect(cmd.compounds.size).to eq(1)
      end

      it "splits on pipe" do
        cmd = parser.parse("Get-Process | Where-Object {$_.CPU -gt 10}")
        expect(cmd.binary).to eq("Get-Process")
        expect(cmd.compounds.size).to eq(1)
      end
    end

    context "subshells" do
      it "extracts $() subshell content" do
        cmd = parser.parse("Write-Host $(Get-Date)")
        expect(cmd.subshells).to contain("Get-Date")
      end
    end
  end
end

Spectator.describe "Windows platform integration" do
  describe Commandant::Platform::Windows::Cmd do
    subject(platform) { described_class.new }

    it "returns windows ruleset folder" do
      expect(platform.ruleset_folder).to eq("windows")
    end

    it "returns / flag prefix" do
      expect(platform.flag_prefix).to eq("/")
    end

    it "returns CmdParser as default parser" do
      expect(platform.default_parser).to be_a(Commandant::Parser::CmdParser)
    end
  end

  describe Commandant::Platform::Windows::PowerShell do
    subject(platform) { described_class.new }

    it "returns windows ruleset folder" do
      expect(platform.ruleset_folder).to eq("windows")
    end

    it "returns - flag prefix" do
      expect(platform.flag_prefix).to eq("-")
    end

    it "returns PowerShellParser as default parser" do
      expect(platform.default_parser).to be_a(Commandant::Parser::PowerShellParser)
    end
  end
end
