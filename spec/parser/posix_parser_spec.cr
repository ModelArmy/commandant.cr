require "../spec_helper"

Spectator.describe Commandant::Parser::PosixParser do
  subject(parser) { described_class.new }

  describe "#parse" do
    context "basic command" do
      it "extracts binary" do
        cmd = parser.parse("grep foo bar.txt")
        expect(cmd.binary).to eq("grep")
      end

      it "extracts arguments" do
        cmd = parser.parse("grep foo bar.txt")
        expect(cmd.arguments).to contain("bar.txt")
      end
    end

    context "short flags" do
      it "parses single short flag" do
        cmd = parser.parse("grep -r foo .")
        expect(cmd.flag_canonicals).to contain("-r")
      end

      it "parses combined short flags" do
        cmd = parser.parse("ls -la /home")
        expect(cmd.flag_canonicals).to contain("-l")
        expect(cmd.flag_canonicals).to contain("-a")
      end

      it "parses flag with attached value" do
        cmd = parser.parse("sed -i.bak 's/foo/bar/' file.txt")
        expect(cmd.flag_canonicals).to contain("-i")
        expect(cmd.arguments).to contain(".bak")
      end
    end

    context "long flags" do
      it "parses long flag" do
        cmd = parser.parse("grep --recursive foo .")
        expect(cmd.flag_canonicals).to contain("--recursive")
      end
    end

    context "subshells" do
      it "extracts dollar-paren subshell" do
        cmd = parser.parse("echo $(whoami)")
        expect(cmd.subshells).to contain("whoami")
      end

      it "extracts backtick subshell" do
        cmd = parser.parse("echo `date`")
        expect(cmd.subshells).to contain("date")
      end
    end

    context "compound commands" do
      it "parses primary command from semicolon compound" do
        cmd = parser.parse("ls /tmp; rm -rf /tmp/foo")
        expect(cmd.binary).to eq("ls")
        expect(cmd.compounds.size).to eq(1)
        expect(cmd.compounds.first.binary).to eq("rm")
      end

      it "parses primary command from && compound" do
        cmd = parser.parse("mkdir /tmp/x && cd /tmp/x")
        expect(cmd.binary).to eq("mkdir")
        expect(cmd.compounds.first.binary).to eq("cd")
      end
    end

    context "quoted arguments" do
      it "handles single-quoted arguments with spaces" do
        cmd = parser.parse("grep 'hello world' file.txt")
        expect(cmd.arguments).to contain("hello world")
      end

      it "handles double-quoted arguments" do
        cmd = parser.parse("grep \"foo bar\" file.txt")
        expect(cmd.arguments).to contain("foo bar")
      end
    end
  end
end
