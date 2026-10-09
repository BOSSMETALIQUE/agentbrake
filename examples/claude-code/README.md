# AgentBrake for Claude Code: example files

| File | What it is |
|---|---|
| `settings.example.json` | The `hooks` block for a Claude Code `settings.json`. Replace the interpreter path, or let `agentbrake claude-code install` write it with the right path (it also checks that the hook starts). `agentbrake claude-code print-settings` prints it for your interpreter |
| `policy.example.json` | Overrides for `~/.agentbrake/claude-code/policy.json`. Every key is optional; unknown keys are refused so a typo cannot silently weaken the policy. A list-valued key (`egress_allowed_domains`, `private_file_globs`, ...) **replaces** its default, so copy the entries you want to keep |
| `agentbrake-guard/` + `.claude-plugin/marketplace.json` | The same hooks as a plugin, in a local marketplace (`claude plugin marketplace add <this folder>`, then `claude plugin install agentbrake-guard@agentbrake`). The plugin runs `python` from `PATH`, which must be the interpreter py-agentbrake is installed in; if it isn't, the hook fails closed and blocks every tool call. Prefer `install` unless you know your `PATH` |

The hook runs Python in isolated mode (`-I`): Claude Code starts it in the
project directory, and without `-I` a repository shipping its own `agentbrake/`
folder could replace the hook with one that allows everything.

## About `recipients` (MCP send tools)

Each entry is compiled into `FlowPolicy.allow_args`: after an untrusted read, a
send passes without asking only if every recipient in `fields` is allow-listed
and every other argument is named in `other_fields`. Any argument you don't
list makes the call ask, on purpose.

The Gmail example leaves out two real parameters of `send_message` on purpose:

- `draftId` sends an existing draft *as is* and ignores `to`/`cc`/`bcc`, so
  allowing it would skip the recipient check entirely;
- `htmlBody` can carry remote images that leak data when the mail is opened.
  Keep sends plain text.

Check your own MCP tool's parameters before copying an entry.
