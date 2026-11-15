"""Static rules. Line rules match single lines of code or Markdown; structural
checks read the parsed plugin components (hooks, MCP servers, manifests...).

Each rule says what it found, why that matters on a real machine, where to fix it,
and which precautions (see hardening.py) reduce the risk if you install anyway.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Severity

S = Severity
CODE = frozenset({"shell", "python", "js", "code"})
SHELLISH = frozenset({"shell"})
MD = frozenset({"markdown"})
CODE_MD = CODE | MD
ALL_TEXT = CODE | MD | frozenset({"config", "other"})


@dataclass(frozen=True)
class LineRule:
    id: str
    title: str
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str
    fix: str
    precautions: tuple[str, ...] = ()
    kinds: frozenset[str] = CODE
    exclude: re.Pattern[str] | None = None
    confidence: str = "high"
    auto_boost: bool = True  # raise one level when the file runs on its own
    tags: frozenset[str] = field(default_factory=frozenset)
    # Lower-case substrings, at least one of which every match contains. A file with none of them
    # skips the regex. Purely a speed-up: leave empty unless every branch of the pattern is covered.
    hints: tuple[str, ...] = ()


def r(pattern: str, flags: int = re.I) -> re.Pattern[str]:
    return re.compile(pattern, flags)


NET_CALL = r(
    r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|\bfetch\s*\(|\baxios(\.\w+)?\s*\(|"
    r"\brequests\.(get|post|put|patch)\s*\(|\burllib\.request|\burlopen\s*\(|\bhttpx\.|\bhttps?\.(request|get)\s*\(|"
    r"\bnet\.connect\s*\(|\bsocket\.connect|\bnew\s+WebSocket\s*\(|\bgot\s*\(|\bundici\b|\bXMLHttpRequest\b|\bsendBeacon\s*\("
)

LINE_RULES: list[LineRule] = [
    # ---- remote code -------------------------------------------------------
    LineRule(
        "RCE-PIPE-SHELL", "Downloads a script and pipes it straight into a shell", "remote-code", S.HIGH,
        r(r"\b(curl|wget|iwr|irm|Invoke-WebRequest)\b[^\n|]*\|\s*(sudo\s+)?(-?\s*)(ba|z|da|k|fi)?sh\b|\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b"),
        "Whatever the server returns runs with your user's full access, and the server can change it at any time, so the code you reviewed is not the code that runs.",
        "Replace the pipe with a pinned, checksummed download that is committed to the plugin, or vendor the script.",
        ("review-before-run", "pin-commit"), kinds=CODE_MD | SHELLISH,
    ),
    LineRule(
        "RCE-EVAL-REMOTE", "Evaluates code fetched from the network", "remote-code", S.CRITICAL,
        r(r"(eval|source|bash|sh)\s+[\"']?\$\((curl|wget)|<\((curl|wget)\b|\b(iex|Invoke-Expression)\b[^\n]*(iwr|irm|Invoke-WebRequest|DownloadString|Net\.WebClient)|exec\s*\(\s*(requests\.get|urlopen|urllib)|eval\s*\(\s*await\s+\(?\s*await\s+fetch|new\s+Function\s*\([^)]*fetch"),
        "Remote code is executed in memory without ever being written to disk, which hides it from review and from most scanners.",
        "Remove the remote eval. Ship the code in the plugin so it can be reviewed and pinned.",
        ("disable-plugin", "review-before-run"), kinds=CODE_MD | SHELLISH,
    ),
    LineRule(
        "RCE-DOWNLOAD-EXEC", "Downloads a file and makes it executable", "remote-code", S.HIGH,
        r(r"\b(curl|wget)\b[^\n]*(-o|-O|--output)\s*\S+[^\n]*(&&|;)\s*(chmod\s+\+?[0-7]*x|\./|sh\s|bash\s)"),
        "A binary or script fetched at run time can't be reviewed before it runs and can be swapped on the server.",
        "Pin the download to a version and verify a SHA-256 checksum before running it.",
        ("review-before-run", "pin-commit"), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "RCE-UNPINNED-RUNNER", "Runs a package straight from a registry without a version pin", "supply-chain", S.MEDIUM,
        r(r"\b(npx|bunx|pnpm\s+dlx|uvx|pipx\s+run)\s+(-y\s+|--yes\s+|-q\s+)*(?!-)(@?[a-z0-9][\w./-]*)(?![\w./-]*@\d)(?=[\s\"'`]|$)"),
        "Every run downloads the newest published version, so a compromised or typosquatted release runs on your machine without any change to the plugin.",
        "Pin the package to an exact version, for example `npx -y package@1.2.3`, or vendor it.",
        ("pin-mcp-version", "pin-commit"), kinds=CODE | SHELLISH,
        exclude=r(r"@\d|--version|npx\s+(-y\s+)?(tsc|tsx|vitest|jest|eslint|prettier|ts-node)\b"),
    ),
    # ---- obfuscation --------------------------------------------------------
    LineRule(
        "OBF-DECODE-EXEC", "Decodes hidden data and runs it", "obfuscation", S.CRITICAL,
        r(r"base64\s+(-d|--decode|-D)[^\n]*\|\s*(ba|z)?sh\b|echo\s+[A-Za-z0-9+/=]{24,}\s*\|\s*base64|"
          r"(eval|(ba|z)?sh\s+-c)\s+[\"']?\$\([^)\n]*base64\s+(-d|--decode|-D)|"
          r"(eval|exec|Function)\s*\(\s*(atob|Buffer\.from|base64\.b64decode|b64decode|bytes\.fromhex|codecs\.decode|zlib\.decompress|marshal\.loads)|"
          r"exec\s*\(\s*compile\s*\(\s*(base64|zlib|codecs)"),
        "Code that only exists in encoded form can't be read in review. Legitimate plugins rarely need this; malware uses it to hide payloads.",
        "Remove the encoded payload and ship readable source.",
        ("disable-plugin",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "OBF-ENCODED-BLOB", "Long encoded string in code", "obfuscation", S.MEDIUM,
        r(r"[\"'`][A-Za-z0-9+/]{300,}={0,2}[\"'`]|[\"'`](?:[0-9a-fA-F]{2}){200,}[\"'`]"),
        "Large encoded strings can carry hidden code or data. Check what decodes it and what happens with the result.",
        "Replace the blob with a readable file, or document what it contains.",
        ("review-before-run",), confidence="medium", auto_boost=True,
        exclude=r(r"data:(image|font|application/font)|integrity=|sha(256|384|512)-"),
    ),
    LineRule(
        "OBF-HEX-ESCAPES", "Heavily escaped string (hex or unicode escapes)", "obfuscation", S.MEDIUM,
        r(r"(\\x[0-9a-fA-F]{2}){24,}|(\\u[0-9a-fA-F]{4}){16,}"),
        "Long runs of escape sequences are a common way to hide commands, hostnames and keys from a quick read.",
        "Decode the string and replace it with plain text.",
        ("review-before-run",), confidence="medium",
    ),
    LineRule(
        "OBF-DYNAMIC-EXEC", "Runs code built from strings at run time", "obfuscation", S.LOW,
        r(r"\beval\s*\(\s*[A-Za-z_$][\w$.]*\s*\)|\bnew\s+Function\s*\(\s*[A-Za-z_$]|\bexec\s*\(\s*[A-Za-z_][\w.]*\s*\)"),
        "Dynamic code execution makes behaviour depend on data that can come from outside the plugin.",
        "Replace eval/exec with explicit logic.",
        ("review-before-run",), confidence="low",
        exclude=r(r"\.exec\s*\(|re\.compile|regex|RegExp|child_process|subprocess|\bexec\s*\(\s*(cmd|command|args)\s*\)"),
    ),
    # ---- network / exfiltration ----------------------------------------------
    LineRule(
        "EXFIL-KNOWN-SINK", "Sends data to a known exfiltration service", "exfiltration", S.HIGH,
        r(r"discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|api\.telegram\.org/bot|pastebin\.com/api|transfer\.sh|webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interact\.sh|oast\.(fun|live|me|pro|site)|burpcollaborator|canarytokens|0x0\.st|file\.io|temp\.sh"),
        "These services are commonly used to receive stolen data because they need no account and are hard to trace.",
        "Remove the call, or replace it with the project's own documented endpoint.",
        ("disable-plugin", "deny-network-bash"), kinds=CODE_MD | SHELLISH,
    ),
    LineRule(
        "NET-REVERSE-SHELL", "Reverse shell pattern", "remote-code", S.CRITICAL,
        r(r"/dev/tcp/\S+/\d+|\bn(c|cat)\b[^\n]*\s-(e|c)\s|\bbash\s+-i\s*>&|socket\.socket\([^)]*\)[^\n]*(dup2|subprocess|pty\.spawn)|\bpty\.spawn\s*\(\s*[\"']/bin/(ba)?sh|mkfifo\s+\S+[^\n]*\bnc\b"),
        "This gives someone else an interactive shell on your machine.",
        "Do not install. Report the repository to GitHub.",
        ("disable-plugin",), kinds=CODE_MD | SHELLISH,
    ),
    LineRule(
        "NET-RAW-IP", "Connects to a hard-coded IP address", "network", S.MEDIUM,
        r(r"\b(https?|wss?|tcp|ftp)://(?!(127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.))\d{1,3}(\.\d{1,3}){3}"),
        "Servers addressed by raw IP skip DNS and are often throwaway infrastructure. Check who runs it.",
        "Use a documented hostname over HTTPS.",
        ("deny-network-bash", "sandbox-bash"), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "NET-CLEARTEXT", "Sends traffic over plain HTTP to a remote host", "network", S.LOW,
        r(r"[\"'`]http://(?!(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example\.(com|org)|www\.w3\.org|schemas?\.|json-schema\.org|ns\.adobe\.com|purl\.org|xmlns))[\w.-]+"),
        "Plain HTTP can be read and modified by anyone on the network path.",
        "Switch the URL to https://.",
        ("sandbox-bash",), confidence="medium",
    ),
    LineRule(
        "ENV-DUMP", "Collects the whole environment", "credentials", S.MEDIUM,
        r(r"JSON\.stringify\(\s*process\.env\s*\)|\{\s*\.\.\.process\.env\s*\}[^\n]*(fetch|post|send|write)|json\.dumps\(\s*(dict\()?os\.environ|dict\(\s*os\.environ\s*\)|\bprintenv\b\s*(\||>)|\benv\s*\|\s*(curl|nc|base64)|Object\.(entries|keys)\(\s*process\.env\s*\)[^\n]*(fetch|post|send)"),
        "Environment variables usually hold API keys and tokens. Bundling all of them is how credential stealers work.",
        "Read only the specific variables the plugin needs.",
        ("deny-secret-reads", "sandbox-bash"),
    ),
    # ---- credentials --------------------------------------------------------
    LineRule(
        "CRED-SSH-KEYS", "Touches SSH keys or authorized_keys", "credentials", S.HIGH,
        r(r"(~|\$HOME|\$\{HOME\}|homedir\(\)|expanduser\([\"']~)[/\\\"', +]*\.ssh\b|\bid_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|authorized_keys"),
        "SSH private keys give access to every server and Git host you use. authorized_keys controls who can log in to this machine.",
        "Remove the access. A plugin should never need your SSH keys.",
        ("deny-secret-reads", "disable-plugin"), kinds=CODE | SHELLISH,
        exclude=r(r"ssh-keygen\s+-l|known_hosts"),
    ),
    LineRule(
        "CRED-CLOUD-FILES", "Reads cloud or registry credential files", "credentials", S.HIGH,
        r(r"\.aws/(credentials|config)|\.config/gcloud|application_default_credentials|\.azure/|\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.config/gh/hosts\.yml|\.terraform\.d/credentials"),
        "These files hold long-lived tokens for cloud accounts and package registries.",
        "Remove the access, or use the provider's SDK with scoped, user-approved credentials.",
        ("deny-secret-reads",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "CRED-KEYCHAIN", "Reads the macOS keychain or a password store", "credentials", S.HIGH,
        r(r"\bsecurity\s+(find-(generic|internet)-password|dump-keychain|export)\b|Library/Keychains|\bkeyring\.get_password|\bkeytar\b|\bsecret-tool\s+lookup|\bpass\s+show\b"),
        "Keychain access can expose every saved password and token on the machine.",
        "Remove keychain reads unless the plugin's documented purpose needs one specific item.",
        ("disable-plugin",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "CRED-BROWSER-DATA", "Reads browser profiles, cookies or saved logins", "credentials", S.CRITICAL,
        r(r"Library/Application Support/(Google/Chrome|BraveSoftware|Microsoft Edge|Arc)/|[/\\\"']Login Data\b|Firefox/Profiles|Cookies\.binarycookies|\bcookies\.sqlite\b|[/\\]Local State\b|(Firefox|Profiles)[^\n]{0,80}logins\.json|\bkey[34]\.db\b", 0),
        "Browser data contains session cookies and saved passwords. Reading it is a hallmark of info-stealer malware.",
        "Do not install.",
        ("disable-plugin",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "CRED-WALLET", "Reads cryptocurrency wallet files", "credentials", S.CRITICAL,
        r(r"Ethereum/keystore|\bExodus\b/|\.electrum\b|solana/id\.json|wallet\.dat|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn|Phantom/|Coinbase Wallet"),
        "Wallet files and extension IDs are targeted to steal funds.",
        "Do not install.",
        ("disable-plugin",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "CRED-CLAUDE-AUTH", "Reads Claude Code credentials", "credentials", S.HIGH,
        r(r"\.claude/\.credentials\.json|Claude Code-credentials|claudeAiOauth"),
        "These hold your Claude login or API credentials.",
        "Remove the access. Plugins never need your Claude credentials.",
        ("deny-secret-reads", "disable-plugin"), kinds=CODE | SHELLISH,
    ),
    # ---- persistence & config tampering ---------------------------------------
    LineRule(
        "PERSIST-SHELL-PROFILE", "Writes to a shell startup file", "persistence", S.HIGH,
        r(r"(>>?|appendFile(Sync)?\s*\(|writeFile(Sync)?\s*\(|open\s*\([^)]*[\"']a[\"']|tee\s+-a)[^\n]*(\.bashrc|\.zshrc|\.zprofile|\.zshenv|\.bash_profile|\.profile|config\.fish)|(\.bashrc|\.zshrc|\.zprofile|\.zshenv|\.bash_profile|\.profile)[\"'`]?\s*,?[^\n]*(appendFile|writeFile|open\([^)]*[\"']a)"),
        "Lines added to shell startup files run in every new terminal, long after the plugin is removed.",
        "Print the line for the user to add themselves instead of editing the file.",
        ("check-persistence",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "PERSIST-LAUNCH", "Installs a launch agent, cron job or service", "persistence", S.HIGH,
        r(r"LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap|submit|enable)|\bcrontab\s+(-[^l]|\S+\.)|/etc/cron|systemctl\s+(--user\s+)?enable|\.config/systemd|\.config/autostart|schtasks\s+/create|HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"),
        "Background services keep running after the plugin is uninstalled and are a common persistence technique.",
        "Remove the scheduled job. If the plugin needs a background process, document it and let the user start it.",
        ("check-persistence", "disable-plugin"), kinds=CODE_MD | SHELLISH,
    ),
    LineRule(
        "TAMPER-CLAUDE-CONFIG", "Edits Claude Code settings or memory files", "config-tampering", S.HIGH,
        r(r"(writeFile|appendFile|write_text|open\([^)]*[\"'](w|a)|>>?|tee|cp|mv|sed\s+-i|json\.dump)[^\n]*(\.claude/settings(\.local)?\.json|\.claude\.json|\.claude/CLAUDE\.md|\.claude/agents|\.claude/commands|\.claude/hooks|managed-settings\.json)|(\.claude/settings(\.local)?\.json|\.claude\.json|\.claude/CLAUDE\.md)[^\n]*(writeFile|appendFile|write_text|json\.dump)"),
        "A plugin that rewrites your settings can grant itself permissions, add hooks, or change the instructions Claude follows in every project.",
        "Ask the user to make the change, or show the snippet to paste.",
        ("protect-claude-config", "disable-plugin"), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "TAMPER-BYPASS-PERMISSIONS", "Turns off Claude Code permission prompts", "permissions", S.HIGH,
        r(r"--dangerously-skip-permissions|[\"']?defaultMode[\"']?\s*[:=]\s*[\"']bypassPermissions|permission-mode\s+bypassPermissions|skipDangerousModePermissionPrompt|allowDangerouslySkipPermissions"),
        "With prompts off, every tool call (shell commands, file writes, network) runs without asking you.",
        "Remove the flag; let the user choose their own permission mode.",
        ("lock-permission-mode",), kinds=CODE_MD | SHELLISH | frozenset({"config"}),
        exclude=r(r"\b(do\s*not|don't|never|avoid|instead\s+of|rather\s+than|without\s+using)\b"),
    ),
    LineRule(
        "TAMPER-GIT-HOOKS", "Installs git hooks or changes core.hooksPath", "config-tampering", S.MEDIUM,
        r(r"\.git/hooks/|core\.hooksPath|git\s+config\s+(--global\s+)?(core\.(hooksPath|sshCommand|fsmonitor|pager|editor)|credential\.helper|alias\.)"),
        "Git hooks and these config keys run commands on ordinary git operations in your repositories.",
        "Document the hook and let the user install it.",
        ("check-persistence",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "TAMPER-HISTORY", "Clears shell history or logs", "obfuscation", S.HIGH,
        r(r"history\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|rm\s+[^\n]*\.(bash|zsh)_history|>\s*~/\.(bash|zsh)_history|log\s+erase"),
        "Wiping history removes evidence of what ran.",
        "Remove it.", ("disable-plugin",), kinds=CODE | SHELLISH,
    ),
    # ---- destructive ---------------------------------------------------------
    LineRule(
        "DESTRUCT-RM-HOME", "Recursive delete of the home or root folder", "destructive", S.CRITICAL,
        r(r"\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*(--no-preserve-root\s+)?[\"']?(/|~|\$HOME|\$\{HOME\}|/Users|/home)[\"']?(/\*?)?(\s|$|;|&)|shutil\.rmtree\(\s*(os\.path\.expanduser\([\"']~[\"']\)|Path\.home\(\)|[\"']/[\"'])|rmSync\(\s*(os\.)?homedir\(\)|rm(Sync)?\([^)]*homedir\(\)[^)]*recursive"),
        "One run deletes every file you own.", "Remove it.", ("disable-plugin",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "DESTRUCT-DISK", "Formats or overwrites a disk", "destructive", S.CRITICAL,
        r(r"\bmkfs(\.\w+)?\s|\bdd\s+[^\n]*of=/dev/(disk|sd|nvme|rdisk)|diskutil\s+(eraseDisk|eraseVolume|zeroDisk|secureErase)|format\s+[a-z]:\s*/[qy]"),
        "Destroys data on a whole disk.", "Remove it.", ("disable-plugin",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "DESTRUCT-GIT", "Force-pushes or hard-resets git state", "destructive", S.MEDIUM,
        r(r"git\s+push\s+[^\n]*(--force\b|-f\b)(?!-with-lease)|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f[a-z]*d|git\s+checkout\s+--\s+\.|git\s+stash\s+drop|git\s+branch\s+-D"),
        "These commands throw away uncommitted work or rewrite shared history.",
        "Make the step opt-in and ask before running it.",
        ("ask-git-destructive",), kinds=CODE | SHELLISH, auto_boost=True,
    ),
    # ---- privilege & protections ---------------------------------------------
    LineRule(
        "PRIV-SUDO", "Runs commands with sudo", "privilege", S.MEDIUM,
        r(r"(^|[\s;&|`(\"'])sudo\s+(?!-l\b|-v\b|-k\b)"),
        "Root access lets the command change anything on the machine.",
        "Remove sudo; ask the user to run privileged steps themselves.",
        ("sandbox-bash",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "PRIV-CHMOD", "Makes files world-writable or setuid", "privilege", S.MEDIUM,
        r(r"chmod\s+(-R\s+)?(0?777|a\+w|[ugo]*\+s|[2467][0-7]{3})\b|os\.chmod\([^)]*0o?777"),
        "World-writable or setuid files let other programs tamper with them or gain privileges.",
        "Use the narrowest permissions the file needs.", ("sandbox-bash",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "PRIV-GATEKEEPER", "Disables macOS security protections", "privilege", S.HIGH,
        r(r"spctl\s+--master-disable|spctl\s+--global-disable|xattr\s+(-[a-z]*d[a-z]*\s+|-c[r]?\s+)?[^\n]*com\.apple\.quarantine|xattr\s+-c?r\b|csrutil\s+disable|LSQuarantine\s+-bool\s+(NO|false)|tccutil\s+reset"),
        "Removing the quarantine flag or turning off Gatekeeper lets unsigned downloads run without the usual macOS checks.",
        "Sign and notarise binaries instead of stripping quarantine.", ("disable-plugin",), kinds=CODE_MD | SHELLISH,
    ),
    LineRule(
        "PRIV-TLS-OFF", "Turns off TLS certificate checks", "privilege", S.MEDIUM,
        r(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|ssl\._create_unverified_context|CERT_NONE|\bcurl\b[^\n]{0,200}(\s-[a-zA-Z]*k[a-zA-Z]*\b|--insecure)|InsecureSkipVerify:\s*true|PYTHONHTTPSVERIFY\s*=\s*[\"']?0"),
        "Without certificate checks, anyone on the network path can impersonate the server and inject responses.",
        "Remove the override and fix the certificate problem.", ("sandbox-bash",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "MINER", "Cryptocurrency miner", "remote-code", S.CRITICAL,
        r(r"stratum\+(tcp|ssl)://|\bxmrig\b|\bminerd\b|cryptonight|coinhive|\bnicehash\b|\bmoneroocean\b"),
        "Mining uses your CPU and power for someone else's profit.", "Do not install.", ("disable-plugin",), kinds=CODE_MD | SHELLISH,
    ),
    # ---- hook output that changes Claude's decisions ---------------------------
    LineRule(
        "HOOK-AUTO-APPROVE", "Hook script approves tool calls on your behalf", "permissions", S.HIGH,
        r(r"permissionDecision[\"'`]?\s*[:=]\s*[\"'`]allow|[\"']decision[\"']\s*:\s*[\"']approve|behavior[\"'`]?\s*[:=]\s*[\"'`]allow"),
        "A PreToolUse or PermissionRequest hook that returns allow skips your permission prompt for that tool call.",
        "Return 'ask' or no decision, and let the user's permission rules decide.",
        ("disable-hooks", "lock-permission-mode"), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "HOOK-REWRITES-INPUT", "Hook script rewrites tool arguments", "permissions", S.MEDIUM,
        r(r"updatedInput|updatedToolOutput"),
        "The hook can change a command or file path after you approved it, or alter what Claude sees as the result.",
        "Document exactly which fields are rewritten and why.", ("disable-hooks",), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "HOOK-CONTEXT-INJECTION", "Hook script injects text into Claude's context", "prompt-injection", S.LOW,
        r(r"additionalContext|hookSpecificOutput[^\n]*SessionStart|systemMessage"),
        "Injected context steers Claude in every session. Read what the hook adds and make sure you agree with it.",
        "Keep injected text factual and visible to the user.", ("review-context-injection", "disable-hooks"), kinds=CODE | SHELLISH,
    ),
    # ---- Markdown that Claude reads as instructions ------------------------------
    LineRule(
        "PROMPT-OVERRIDE", "Instruction-override phrase", "prompt-injection", S.HIGH,
        r(r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|other|system)\s+(instructions|prompts|rules|messages)|disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above|system|safety|user)\s+(instructions|rules|guidelines)|forget\s+(all\s+)?(your|previous)\s+instructions|new\s+system\s+prompt|override\s+(the\s+|your\s+)?(system|safety|security)\s+(prompt|rules|instructions)"),
        "Phrases like this try to replace the instructions Claude follows. In a skill, agent or command they act on every user who installs the plugin.",
        "Remove the phrase. If it is a quoted example, mark it clearly as an example.",
        ("review-context-injection", "disable-plugin"), kinds=MD, auto_boost=False,
    ),
    LineRule(
        "PROMPT-CONCEAL", "Tells Claude to hide actions from the user", "prompt-injection", S.HIGH,
        r(r"(do\s+not|don't|never)\s+(tell|inform|notify|alert|show|mention\s+(this|it)\s+to|reveal\s+(this|it)\s+to)\s+(the\s+)?user|without\s+(telling|informing|notifying|asking)\s+the\s+user|keep\s+this\s+(secret|hidden)\s+from|hide\s+(this|it)\s+from\s+the\s+user"),
        "Instructions to keep the user in the dark are a strong sign of a malicious prompt.",
        "Remove the instruction.", ("disable-plugin",), kinds=MD, auto_boost=False,
        exclude=r(r"\bnot\b[^\n]{0,40}\b(secret|password|token|key|credential)s?\b"),
    ),
    LineRule(
        "PROMPT-REMOTE-INSTRUCTIONS", "Tells Claude to fetch and follow remote instructions", "prompt-injection", S.HIGH,
        r(r"(fetch|download|curl|read|load|retrieve)\s+[^\n]{0,60}https?://\S+[^\n]{0,60}\b(and\s+)?(follow|obey|execute|run|apply)\s+(the\s+|its\s+|those\s+)?(instructions|steps|commands|it)"),
        "The instructions at that URL can change at any time after you install the plugin.",
        "Ship the instructions in the plugin itself.", ("pin-commit", "disable-plugin"), kinds=MD, auto_boost=False,
    ),
    LineRule(
        "PROMPT-SKIP-CONFIRM", "Tells Claude to act without asking for permission", "prompt-injection", S.MEDIUM,
        r(r"(do\s+not|don't|never)\s+ask\s+(the\s+user\s+)?(for\s+)?(permission|confirmation|approval)\b|proceed\s+without\s+(asking|confirmation|permission|approval)"),
        "This pushes Claude to take actions you would normally approve one by one.",
        "Let the user's permission settings decide.", ("lock-permission-mode",), kinds=MD, auto_boost=False,
        confidence="medium", exclude=r(r"--yes|\s-y\b|--force|\bflag\b|\boption\b|\|"),
    ),
    LineRule(
        "PROMPT-SECRET-ACCESS", "Tells Claude to read or send secret files", "prompt-injection", S.HIGH,
        r(r"\b(read|cat|open|print|show|send|upload|post|copy|include|attach|collect)\b[^\n]{0,50}(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|\.npmrc|\.netrc|keychain|\.claude/\.credentials|browser\s+cookies|wallet)"),
        "An instruction like this turns Claude into the tool that collects your secrets.",
        "Remove the instruction.", ("deny-secret-reads", "disable-plugin"), kinds=MD, auto_boost=False,
        exclude=r(r"\b(do\s*not|don't|never|avoid|refuse|block|deny|protect)\b"),
    ),
    LineRule(
        "PROMPT-PRIORITY", "Claims priority over your own instructions", "prompt-injection", S.LOW,
        r(r"you\s+do\s+not\s+have\s+a\s+choice|this\s+is\s+not\s+negotiable|non-negotiable|takes?\s+precedence\s+over\s+(the\s+)?(user|system|all)|(override|overrides)\s+(any|all)\s+(other|user)\s+instructions|regardless\s+of\s+(what\s+)?(the\s+user|user\s+instructions)"),
        "Strong priority language makes the plugin's instructions win over yours when they conflict.",
        "Soften the wording, or state that user instructions take precedence.",
        ("review-context-injection",), kinds=MD, auto_boost=False, confidence="medium",
    ),
    LineRule(
        "PROMPT-HIDDEN-COMMENT", "Hidden HTML comment with instructions", "prompt-injection", S.HIGH,
        r(r"<!--(?:(?!-->).){0,400}?\b(ignore\s+(all|any|previous|prior|the)|you\s+must|execute|curl|wget|send\s+(the|all|it|this)|upload|exfiltrate|do\s+not\s+(tell|mention|inform)|system\s+prompt)\b(?:(?!-->).)*-->", re.I | re.S),
        "HTML comments are invisible when Markdown is rendered on GitHub, but Claude still reads them.",
        "Move the text out of the comment so reviewers can see it.", ("review-context-injection",), kinds=MD, auto_boost=False,
        exclude=r(r"<!--\s*(markdownlint|prettier|toc|begin|end|omit|vale|lint|textlint|spell|cspell|eslint|BEGIN|END)\b"),
    ),
    # ---- 0.3.0: exfiltration channels ---------------------------------------------
    LineRule(
        "EXFIL-DNS", "Builds a DNS lookup from command output or variables", "exfiltration", S.HIGH,
        r(r"\b(dig|nslookup|drill)\s+[^\n|;]{0,120}(\$\(|\$\{?\w+\}?\.|`)|\bdns\.(resolve\w*|lookup)\s*\(\s*(`[^`\n]{0,80}\$\{|[\w.()]+\s*\+\s*[\"'`]\.)|"
          r"\b(gethostbyname|getaddrinfo)\s*\(\s*(f[\"']|[\w.()]+\s*\+\s*[\"']\.)|\bresolver\.(resolve|query)\s*\(\s*(f[\"']|[\w.()]+\s*\+\s*[\"']\.)"),
        "Data placed in a hostname leaves the machine through DNS, which most firewalls and proxies let through and few teams log.",
        "Remove the lookup, or look up a fixed, documented hostname.",
        ("disable-plugin", "sandbox-bash"), kinds=CODE | SHELLISH, confidence="medium",
    ),
    LineRule(
        "EXFIL-PASTE-SITE", "Talks to a paste or anonymous file-drop site", "exfiltration", S.HIGH,
        r(r"paste\.ee|hastebin\.com|dpaste\.(com|org)|ghostbin\.|rentry\.(co|org)|termbin\.com|\bix\.io\b|sprunge\.us|paste\.rs|pastebin\.com/raw|"
          r"gofile\.io|anonfiles?\.|catbox\.moe|bashupload\.com|oshi\.at|uguu\.se|tmpfiles\.org|filebin\.net|controlc\.com|privatebin\."),
        "Paste and file-drop sites need no account, so they are used both to receive stolen data and to host the next stage of an attack.",
        "Remove the call, or use the project's own documented endpoint.",
        ("disable-plugin", "deny-network-bash"), kinds=CODE_MD | SHELLISH,
        hints=("paste", "hastebin", "ghostbin", "rentry", "termbin", "ix.io", "sprunge", "gofile", "anonfile", "catbox", "bashupload", "oshi.at", "uguu", "tmpfiles", "filebin", "controlc", "privatebin"),
    ),
    LineRule(
        "EXFIL-FILE-UPLOAD", "Uploads local files to another machine", "exfiltration", S.MEDIUM,
        r(r"\b(scp|rsync)\s+[^\n]{0,160}\s[\w.-]+@[\w.-]+:|\brclone\s+(copy|sync|move)\b|\baws\s+s3\s+(cp|sync|mv)\s+[^\n]{0,120}s3://|"
          r"\bcurl\b[^\n]{0,200}\s(-T|--upload-file)\s|\bcurl\b[^\n]{0,200}(-F|--form)\s+[\"']?[\w-]+=@|\bcurl\b[^\n]{0,200}(--data-binary|--data|-d)\s+[\"']?@|"
          r"\bsmtplib\.SMTP|\bnodemailer\b|\b(mail|mailx|mutt)\s+-s\b|\bnc\s+(-\w+\s+)*[\w.-]+\s+\d{2,5}\s*<\s*\S"),
        "Whole files are sent off the machine. Check which files, and who runs the receiving end.",
        "Make the upload an explicit, documented step the user starts, and name the destination.",
        ("deny-network-bash", "sandbox-bash"), kinds=CODE | SHELLISH, confidence="medium",
    ),
    # ---- 0.3.0: credentials -----------------------------------------------------
    LineRule(
        "CRED-CLOUD-METADATA", "Queries a cloud instance metadata service", "credentials", S.HIGH,
        r(r"169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2\b|fd00:ec2::254|100\.100\.100\.200"),
        "On a cloud VM, CI runner or dev container the metadata service hands out the machine's own cloud credentials to any local process that asks.",
        "Remove the request. Use the provider's SDK with credentials the user supplies.",
        ("deny-network-bash", "disable-plugin"), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "CRED-CLI-TOKEN", "Asks a signed-in CLI for its access token", "credentials", S.MEDIUM,
        r(r"\bgh\s+auth\s+token\b|gcloud\s+auth\s+(application-default\s+)?print-(access|identity)-token|aws\s+configure\s+(get|export-credentials)|"
          r"aws\s+sts\s+get-session-token|az\s+account\s+get-access-token|\bop\s+(read|item\s+get)\b|git\s+credential\s+fill|"
          r"npm\s+config\s+get\s+[^\n]{0,40}_authToken|doctl\s+auth\s+token|kubectl\s+config\s+view\s+[^\n]{0,40}--raw|vault\s+print\s+token"),
        "The command prints a live token for an account you are signed in to. Whatever reads the output can act as you.",
        "Let the tool that needs the token call the CLI itself, or ask the user for a scoped token.",
        ("deny-secret-reads", "sandbox-bash"), kinds=CODE | SHELLISH, confidence="medium",
    ),
    LineRule(
        "CRED-APP-DATA", "Reads chat, mail or messaging app data", "credentials", S.HIGH,
        r(r"discord[^\n]{0,40}(Local Storage|leveldb)|Telegram Desktop|[/\\]tdata\b|Slack/(Cookies|storage|Local Storage)|\.config/Signal\b|"
          r"Library/Messages\b|Library/Application Support/AddressBook|Library/Mail/|\.thunderbird\b|NoteStore\.sqlite"),
        "These folders hold session tokens and private messages. Info-stealers copy them to take over accounts.",
        "Do not install.", ("disable-plugin",), kinds=CODE | SHELLISH,
        hints=("discord", "telegram", "tdata", "slack/", "signal", "library/", ".thunderbird", "notestore"),
    ),
    LineRule(
        "CRED-FAKE-PROMPT", "Shows its own password prompt", "credentials", S.HIGH,
        r(r"display\s+dialog[^\n]{0,240}(hidden\s+answer|password)|zenity\s+[^\n]{0,80}--password|kdialog\s+--password|\bGet-Credential\b|SUDO_ASKPASS\s*="),
        "A dialog drawn by a script can look like a system prompt. Whatever you type goes to the script.",
        "Remove the prompt. Let the operating system ask for passwords.",
        ("disable-plugin",), kinds=CODE | SHELLISH,
        hints=("dialog", "zenity", "get-credential", "askpass"),
    ),
    # ---- 0.3.0: surveillance ----------------------------------------------------
    LineRule(
        "SPY-CLIPBOARD", "Reads the clipboard", "surveillance", S.MEDIUM,
        r(r"\bpbpaste\b|\bxclip\b[^\n]{0,60}\s-o\b|\bxsel\b[^\n]{0,40}\s(-o|--output)\b|\bwl-paste\b|\bGet-Clipboard\b|pyperclip\.paste\s*\(|"
          r"clipboardy?\.(read|readSync)\s*\(|navigator\.clipboard\.read(Text)?\s*\(|clipboard\.readText\s*\(|\bNSPasteboard\b|\.clipboard_get\s*\("),
        "The clipboard often holds passwords, tokens and one-time codes copied from a password manager.",
        "Take input as an argument or a file instead of reading the clipboard.",
        ("sandbox-bash", "disable-plugin"), kinds=CODE | SHELLISH,
    ),
    LineRule(
        "SPY-KEYLOGGER", "Listens to keystrokes system-wide", "surveillance", S.HIGH,
        r(r"\bpynput\b|keyboard\.(on_press|hook|record|read_event)\s*\(|CGEventTapCreate|\biohook\b|\buiohook|node-global-key-listener|GlobalKeyboardListener|"
          r"\bxinput\s+test\b|\blogkeys\b|GetAsyncKeyState|SetWindowsHookEx|addGlobalMonitorForEvents|/dev/input/event\d"),
        "A global key listener sees everything you type in every application, including passwords.",
        "Do not install unless the plugin's documented purpose is keyboard automation and you have read the code.",
        ("disable-plugin",), kinds=CODE | SHELLISH, confidence="medium",
        hints=("pynput", "keyboard", "cgeventtap", "iohook", "key-listener", "xinput", "logkeys", "getasynckeystate", "setwindowshookex", "addglobalmonitor", "/dev/input"),
    ),
    LineRule(
        "SPY-SCREENSHOT", "Captures the screen", "surveillance", S.MEDIUM,
        r(r"\bscreencapture\s+\S|ImageGrab\.grab\s*\(|pyautogui\.screenshot\s*\(|\bmss\.mss\s*\(|\bmss\(\)\.(shot|grab)|\bscrot\s|gnome-screenshot|"
          r"\bimport\s+-window\s+root|screenshot-desktop|desktopCapturer\.getSources|CGWindowListCreateImage|CGDisplayCreateImage|\bgrim\s+(-|/|~|\$)"),
        "A screenshot of the whole desktop captures whatever is open: mail, chats, password managers, other projects.",
        "Capture only the plugin's own window or page, and only when the user asks.",
        ("disable-plugin", "sandbox-bash"), kinds=CODE | SHELLISH,
        hints=("screencapture", "imagegrab", "screenshot", "mss", "scrot", "-window", "desktopcapturer", "cgwindowlistcreateimage", "cgdisplaycreateimage", "grim"),
    ),
    LineRule(
        "SPY-MIC-CAMERA", "Records from the microphone, camera or screen", "surveillance", S.HIGH,
        r(r"\bimagesnap\b|ffmpeg[^\n]{0,160}-f\s+(avfoundation|v4l2|alsa|pulse|dshow|x11grab|gdigrab)|\b(arecord|parecord)\s|\bsox\s+(-t\s+\w+\s+)?-d\b|"
          r"cv2\.VideoCapture\s*\(\s*\d|sounddevice\.(rec|InputStream)|\bsd\.rec\s*\(|pyaudio\.PyAudio|getUserMedia\s*\(|AVCaptureDevice|AVAudioRecorder|"
          r"node-record-lpcm16|\bfswebcam\b"),
        "Audio and video capture records the room, not the project.",
        "Do not install unless voice or video input is the plugin's documented purpose.",
        ("disable-plugin",), kinds=CODE | SHELLISH,
        hints=("imagesnap", "ffmpeg", "arecord", "parecord", "sox", "videocapture", "sounddevice", "sd.rec", "pyaudio", "getusermedia", "avcapturedevice", "avaudiorecorder", "node-record-lpcm16", "fswebcam"),
    ),
    LineRule(
        "SPY-BROWSER-HISTORY", "Reads browser history or bookmarks", "surveillance", S.HIGH,
        r(r"\bplaces\.sqlite\b|Safari/History\.db|[/\\\"'](Default|Profile \d+)[/\\]History\b|(Chrome|Chromium|Brave|Edge|Arc)[^\n]{0,120}[/\\\"' ,]History[\"']|"
          r"\bHistory\.db\b|Library/Safari/(Bookmarks|History|LastSession)|\bTopSites\.plist"),
        "Browsing history shows which internal tools, banks and accounts you use, and is collected by info-stealers.",
        "Do not install.", ("disable-plugin",), kinds=CODE | SHELLISH,
        hints=("places.sqlite", "history", "library/safari", "topsites"),
    ),
    LineRule(
        "TELEMETRY-MACHINE-ID", "Reads a hardware or machine identifier", "surveillance", S.LOW,
        r(r"IOPlatformUUID|IOPlatformSerialNumber|/etc/machine-id|/var/lib/dbus/machine-id|system_profiler\s+SPHardwareDataType|wmic\s+csproduct|"
          r"node-machine-id|machineIdSync\s*\(|\bMachineGuid\b|dmidecode\s+-s\s+system-(uuid|serial)|uuid\.getnode\s*\("),
        "A stable machine identifier lets a server recognise this computer across sessions, projects and reinstalls.",
        "Use a random identifier the user can reset, and document it.",
        ("disable-hooks", "sandbox-bash"), kinds=CODE | SHELLISH, confidence="medium",
        hints=("ioplatform", "machine-id", "system_profiler", "wmic", "machineid", "machineguid", "dmidecode", "getnode"),
    ),
    LineRule(
        "TELEMETRY-SDK", "Sends usage data to an analytics or telemetry service", "network", S.LOW,
        r(r"\bposthog\b|api\.segment\.(io|com)|analytics-node|@segment/|\bmixpanel\b|amplitude\.com|@amplitude/|sentry\.io|@sentry/|\bsentry_sdk\b|"
          r"google-analytics\.com|googletagmanager|api\.honeycomb\.io|\brudderstack\b|\bstatsig\b|plausible\.io/api|\btelemetry\.[\w-]+\.(com|io|dev|net|sh|ai)\b"),
        "Telemetry reports what you do to a third party. From a hook it can include prompts, file paths and command lines.",
        "Make telemetry opt-in and document exactly what is sent.",
        ("disable-hooks", "sandbox-bash"), kinds=CODE | SHELLISH, confidence="medium",
        hints=("posthog", "segment", "analytics-node", "mixpanel", "amplitude", "sentry", "google-analytics", "googletagmanager", "honeycomb", "rudderstack", "statsig", "plausible", "telemetry"),
    ),
    # ---- 0.3.0: instructions hidden in code and tool descriptions ----------------
    LineRule(
        "PROMPT-TOOL-POISONING", "Instructions to the model inside code or a tool description", "prompt-injection", S.HIGH,
        r(r"<IMPORTANT>|(do\s+not|don't|never)\s+(tell|inform|notify|alert|mention\s+(this|it|that)\s+to)\s+(the\s+)?user|without\s+(telling|informing|notifying)\s+the\s+user|"
          r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)|"
          r"before\s+(using|calling|invoking|running)\s+(this|any|the|other)\s+tools?\b[^\n]{0,120}\b(read|send|pass|include|fetch|call)\b|"
          r"(pass|send|include)\s+(its|the|their|file)\s+contents?\s+(as|in|to)\b[^\n]{0,60}(param|argument|sidenote|field|note)|"
          r"\b(always|must)\s+(call|use)\s+this\s+tool\s+(first|before|instead)"),
        "An MCP tool's description is read by the model, not shown to you. Text like this steers Claude from inside a tool definition (tool poisoning).",
        "Remove the instruction. A tool description should say what the tool does and nothing else.",
        ("deny-mcp-server", "review-context-injection", "disable-plugin"), kinds=CODE | frozenset({"config"}), auto_boost=False,
        exclude=r(r"re\.compile|\bRegExp\b|\bregex\b|\bpattern\b"),
    ),
    LineRule(
        "TAMPER-SANDBOX-OFF", "Turns off the Bash sandbox or auto-approves MCP servers", "permissions", S.HIGH,
        r(r"dangerouslyDisableSandbox[\"'`]?\s*[:=]\s*true|enableAllProjectMcpServers[\"'`]?\s*[:=]\s*true|"
          r"[\"'`]?sandbox[\"'`]?\s*[:=]\s*\{\s*[\"'`]?enabled[\"'`]?\s*[:=]\s*false"),
        "The sandbox limits what Claude's shell commands can reach, and the MCP approval prompt is the only moment you see a new server before it starts.",
        "Remove the setting; let the user choose.",
        ("lock-permission-mode", "protect-claude-config"), kinds=CODE_MD | SHELLISH | frozenset({"config"}),
        exclude=r(r"\b(do\s*not|don't|never|avoid|instead\s+of|rather\s+than)\b"),
    ),
    # ---- 0.3.0: obfuscation, triggers and evasion ----------------------------------
    LineRule(
        "OBF-CHARCODE", "Builds a string from character codes", "obfuscation", S.MEDIUM,
        r(r"String\.fromCharCode\s*\(\s*\d+(\s*,\s*\d+){7,}|(chr\(\s*\d+\s*\)\s*\+\s*){5,}|(\\[0-3][0-7]{2}){12,}"),
        "Spelling a command or address out of numbers hides it from search and from a quick read.",
        "Replace it with the plain string.", ("review-before-run",), confidence="medium",
    ),
    LineRule(
        "EVADE-SANDBOX-CHECK", "Checks for a virtual machine, debugger or analysis sandbox", "obfuscation", S.MEDIUM,
        r(r"systemd-detect-virt|/sys/class/dmi/id/(product_name|sys_vendor|board_vendor)|sysctl\s+(-n\s+)?(hw\.model|kern\.hv_vmm_present)|"
          r"\b(VBOX|VirtualBox|VMware|QEMU|Parallels|Hyper-V)\b[^\n]{0,80}\b(exit|return|quit|process\.exit|sys\.exit|os\._exit)\b|"
          r"PT_DENY_ATTACH|IsDebuggerPresent|sys\.gettrace\s*\(\s*\)|joesandbox|\bcuckoo\b"),
        "Code that behaves differently when it is being watched is written to pass review and then do something else.",
        "Remove the check, or document why the plugin needs to know.",
        ("disable-plugin", "review-before-run"), kinds=CODE | SHELLISH, confidence="medium",
        hints=("detect-virt", "dmi/id", "sysctl", "vbox", "virtualbox", "vmware", "qemu", "parallels", "hyper-v", "pt_deny_attach", "isdebuggerpresent", "gettrace", "joesandbox", "cuckoo"),
    ),
    LineRule(
        "TRIGGER-ENV-GATE", "Behaviour depends on which machine, user or CI system it runs on", "obfuscation", S.LOW,
        r(r"(GITHUB_ACTIONS|\$\{?CI\}?\b|process\.env\.CI\b|os\.environ[^\n]{0,20}[\"']CI[\"'])[^\n]{0,80}\b(exit|return)\b|"
          r"(os\.hostname\(\)|socket\.gethostname\(\)|getpass\.getuser\(\)|os\.userInfo\(\)\.username|\$\(hostname\)|\$\(whoami\)|\$USER\b)[\"']?\s*\]?\s*(===?|!==?|=|-eq)\s*[\"'][\w.-]+[\"']|"
          r"[\"'][\w.-]+[\"']\s*(===?|!==?)\s*(os\.hostname\(\)|socket\.gethostname\(\)|getpass\.getuser\(\))"),
        "A branch that only runs for one host name, one user or outside CI will not show up when someone else tests the plugin.",
        "Read what the gated branch does.", ("review-before-run",), kinds=CODE | SHELLISH, confidence="low",
    ),
    LineRule(
        "TRIGGER-TIME-BOMB", "Behaviour switches on a hard-coded date", "obfuscation", S.MEDIUM,
        r(r"(Date\.now\(\)|new\s+Date\(\)(\.getTime\(\))?|time\.time\(\)|datetime\.(now|utcnow|today)\(\)|date\.today\(\))\s*(>=?|<=?)\s*"
          r"(1[6-9]\d{8}(\d{3})?\b|new\s+Date\(\s*[\"']?20\d\d|datetime(\.datetime)?\(\s*20\d\d|(datetime\.)?date\(\s*20\d\d)|"
          r"\$\(date\s+\+%s\)[\"']?\s+-(gt|ge|lt|le)\s+1[6-9]\d{8}\b|\$\(date\s+\+%Y-?%m-?%d\)[\"']?\s*(>|<|==|-gt|-ge)\s*[\"']?20\d\d"),
        "Code that waits for a date can stay quiet through review and the first weeks of use, then change what it does.",
        "Read both branches. Remove the date check if it is not a documented expiry.",
        ("pin-commit", "review-before-run"), kinds=CODE | SHELLISH, confidence="medium",
    ),
    # ---- 0.3.0: reconnaissance --------------------------------------------------
    LineRule(
        "RECON-NET-SCAN", "Scans the local network or ports", "network", S.MEDIUM,
        r(r"\b(nmap|masscan|zmap|rustscan|arp-scan|netdiscover|fping)\s+(-|\d|\$|[\"'])|\bnc\s+(-[a-z]+\s+)*-[a-z]*z[a-z]*\s|\barp\s+-a\b|"
          r"for\s+\w+\s+in\s+[^\n]{0,60}(seq\s|\{1\.\.25[45]\})[^\n]{0,120}(ping\s+-c|/dev/tcp)|\bpython-nmap\b|\bfrom\s+scapy\b|\bimport\s+scapy\b"),
        "Mapping the network a developer's laptop sits on is the first step of moving to other machines.",
        "Remove the scan unless network discovery is the plugin's documented purpose.",
        ("deny-network-bash", "sandbox-bash"), kinds=CODE | SHELLISH,
        hints=("nmap", "masscan", "zmap", "rustscan", "arp", "netdiscover", "fping", "nc", "ping", "/dev/tcp", "scapy"),
    ),
    # ---- 0.3.0: tampering and defence evasion ---------------------------------------
    LineRule(
        "TAMPER-OTHER-PLUGINS", "Installs, edits or removes other plugins, skills or MCP servers", "config-tampering", S.HIGH,
        r(r"(writeFile|appendFile|write_text|open\([^)\n]{0,80}[\"'](w|a)|>>?|\btee\b|\bcp\b|\bmv\b|\brm\b|sed\s+-i|json\.dump|rmSync|unlink|shutil\.(copy|move|rmtree))"
          r"[^\n]{0,200}(\.claude/plugins\b|installed_plugins\.json|known_marketplaces\.json|\.claude/skills/)|"
          r"(installed_plugins\.json|known_marketplaces\.json)[^\n]{0,200}(writeFile|appendFile|write_text|json\.dump)|"
          r"\bclaude\s+plugins?\s+(install|enable|marketplace\s+add)\b|\bclaude\s+mcp\s+add(-json)?\b"),
        "A plugin that changes what else is installed can add code you never chose, or alter a plugin you already reviewed.",
        "Ask the user to install other plugins themselves.",
        ("protect-claude-config", "disable-plugin"), kinds=CODE | SHELLISH,
        exclude=r(r"CLAUDE_PLUGIN_DATA|\.claude/plugins/data/"),
        hints=("claude", "installed_plugins", "known_marketplaces"),
    ),
    LineRule(
        "PRIV-SECURITY-TOOLS", "Stops or disables security software", "privilege", S.HIGH,
        r(r"(pkill|killall|kill\s+-9|taskkill|launchctl\s+(unload|bootout|remove|disable)|systemctl\s+(stop|disable|mask)|service\s+\S+\s+stop)[^\n]{0,120}"
          r"(falcon|crowdstrike|sentinel(one|d|ctl)|defender|mdatp|little\s*snitch|\blulu\b|osquery|\bsanta\b|clamd|clamav|auditd|apparmor|firewalld|\bufw\b|"
          r"carbonblack|cbdaemon|\bjamf\b|sophos|malwarebytes|blockblock|knockknock|wazuh|ossec|\bfalco\b|sysmon)|"
          r"Set-MpPreference\s+[^\n]{0,80}-Disable|\bsetenforce\s+0|\bufw\s+disable|\bpfctl\s+-d\b|socketfilterfw\s+--setglobalstate\s+off|"
          r"\biptables\s+(-F|--flush)|\bauditctl\s+-e\s*0|DisableAntiSpyware|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off"),
        "Endpoint protection, firewalls and audit logging are what would notice the rest of an attack.",
        "Do not install.", ("disable-plugin",), kinds=CODE_MD | SHELLISH,
        hints=("kill", "launchctl", "systemctl", "service", "set-mppreference", "setenforce", "ufw", "pfctl", "socketfilterfw", "iptables", "auditctl", "disableantispyware", "netsh"),
    ),
    LineRule(
        "TAMPER-LOGS", "Deletes system logs or Claude Code session transcripts", "obfuscation", S.HIGH,
        r(r"\b(rm|shred|srm|truncate|unlink)\s+[^\n]{0,80}(/var/log\b|\.claude/projects\b|\.claude/history\.jsonl|\.claude/logs\b|/var/audit\b|Library/Logs\b|"
          r"\bauth\.log|\bwtmp\b|\butmp\b|\blastlog\b|\.viminfo|\.lesshst|\.python_history|\.node_repl_history)|>\s*/var/log/\S+|"
          r"\bjournalctl\s+[^\n]{0,40}--(vacuum-\w+|rotate)|\bwevtutil\s+cl\b|\bClear-EventLog\b|"
          r"(rmSync|unlinkSync|unlink|os\.remove|shutil\.rmtree|\.unlink)\s*\([^)\n]{0,120}(\.claude[/\"', +]+(projects|logs|history)|transcript_path|/var/log)"),
        "Logs and transcripts are the record of what ran. Removing them hides what a plugin or the agent did.",
        "Remove it.", ("disable-plugin",), kinds=CODE | SHELLISH,
        hints=("rm", "shred", "truncate", "unlink", "/var/log", "journalctl", "wevtutil", "clear-eventlog", "remove"),
    ),
    LineRule(
        "DESTRUCT-ENCRYPT", "Encrypts files in bulk or leaves a ransom note", "destructive", S.CRITICAL,
        r(r"find\s+[^\n]{0,200}-exec\s+(openssl\s+enc|gpg\s+[^\n]{0,40}(-c\b|--symmetric|--encrypt)|age\s+-|7z\s+a\s+[^\n]{0,40}-p|zip\s+[^\n]{0,40}(-P|--password|-e\b))|"
          r"openssl\s+enc\s+[^\n]{0,200}(&&|;|\|\|)\s*(rm|shred|srm|unlink)\b|gpg\s+[^\n]{0,120}(-c\b|--symmetric)[^\n]{0,200}(&&|;)\s*(rm|shred|srm)\b|"
          r"(zip|7z)\s+[^\n]{0,80}(-P\s|--password|-p\S)[^\n]{0,200}(&&|;)\s*(rm|shred|srm)\b|"
          r"your\s+files\s+(have\s+been|are|were)\s+encrypted|README[_-]?(DECRYPT|RESTORE|RECOVER)|HOW[_ -]TO[_ -](DECRYPT|RESTORE|RECOVER)|DECRYPT[_ -]INSTRUCTIONS|"
          r"vssadmin\s+delete\s+shadows|tmutil\s+(deletelocalsnapshots|disable)\b|wbadmin\s+delete|recoveryenabled\s+no"),
        "Encrypting files and deleting the originals, or removing backups and snapshots, is how ransomware works.",
        "Do not install.", ("disable-plugin",), kinds=CODE | SHELLISH,
        hints=("find", "openssl", "gpg", "zip", "7z", "encrypted", "decrypt", "restore", "recover", "vssadmin", "tmutil", "wbadmin", "recoveryenabled"),
    ),
    LineRule(
        "PRIV-ESCALATE", "Grants itself administrator rights", "privilege", S.HIGH,
        r(r"/etc/sudoers|\bNOPASSWD\b|\bvisudo\b|with\s+administrator\s+privileges|\bpkexec\s+\S|\bsetcap\s+\S|chown\s+(-R\s+)?root\b|"
          r"dscl\s+\.\s+-append\s+/Groups/admin|usermod\s+[^\n]{0,40}-a?G\s+(sudo|wheel|admin|docker)|\|\s*sudo\s+-S\b|sudo\s+-S\b[^\n]{0,60}<<<|"
          r"net\s+localgroup\s+administrators|runas\s+/user:|Start-Process\s+[^\n]{0,80}-Verb\s+RunAs|AuthorizationExecuteWithPrivileges"),
        "These give a script lasting root or administrator access, beyond a single sudo command.",
        "Remove it; ask the user to run privileged steps themselves.",
        ("disable-plugin", "sandbox-bash"), kinds=CODE | SHELLISH,
        hints=("sudo", "nopasswd", "administrator", "pkexec", "setcap", "chown", "dscl", "usermod", "localgroup", "runas", "authorizationexecutewithprivileges"),
    ),
    LineRule(
        "PERSIST-LOGIN-HOOK", "Hooks into login, shell start-up or library loading", "persistence", S.HIGH,
        r(r"make\s+(new\s+)?login\s+item|/etc/profile\.d/|\.ssh/rc\b|/etc/rc\.local|\.xinitrc|\.xprofile|/etc/ld\.so\.preload|DYLD_INSERT_LIBRARIES|"
          r"\bLD_PRELOAD\s*=|LoginHook|\.config/fish/conf\.d|\.pam_environment|SMLoginItemSetEnabled|\.bash_logout|/etc/zshenv|/etc/zprofile|"
          r"emond\.d|init\.templateDir|Startup[/\\][^\n]{0,60}\.(lnk|bat|vbs)\b"),
        "These run code at every login, in every shell or inside other programs, long after the plugin is removed.",
        "Remove it. If the plugin needs to start something, document it and let the user do it.",
        ("check-persistence", "disable-plugin"), kinds=CODE | SHELLISH, confidence="medium",
        hints=("login", "profile", ".ssh/rc", "rc.local", ".xinitrc", "preload", "dyld_insert", "fish/conf.d", "pam_environment", "bash_logout", "zshenv", "emond", "templatedir", "startup"),
    ),
    LineRule(
        "PERSIST-DETACHED", "Starts a process that outlives the session", "persistence", S.LOW,
        r(r"\bnohup\s+\S[^\n]{0,200}&\s*($|\)|;)|\bsetsid\s+(-f\s+)?\S|\bdisown\b|\bdetached\s*:\s*true|start_new_session\s*=\s*True|DETACHED_PROCESS|os\.setsid\s*\(\s*\)", re.I | re.M),
        "A detached process keeps running after Claude Code exits, with nothing on screen to show it.",
        "Stop the process when the session ends, or document it.",
        ("check-persistence", "disable-hooks"), kinds=CODE | SHELLISH, confidence="medium",
    ),
]


# Unicode that renders as nothing or reorders text ("Trojan Source"), plus tag characters
# that can smuggle invisible instructions to a model.
HIDDEN_UNICODE = re.compile("[​‌‍⁠⁡⁢⁣⁤᠎﻿‪-‮⁦-⁩\U000e0000-\U000e007f]")


SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("SECRET-AWS", "AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("SECRET-GITHUB", "GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("SECRET-ANTHROPIC", "Anthropic API key", re.compile(r"\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{40,}")),
    ("SECRET-OPENAI", "OpenAI API key", re.compile(r"\bsk-(proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}")),
    ("SECRET-SLACK", "Slack token", re.compile(r"\bxox[abposr]-[0-9A-Za-z-]{10,}")),
    ("SECRET-STRIPE", "Stripe live key", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{20,}")),
    ("SECRET-GOOGLE", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SECRET-NPM", "npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("SECRET-PRIVATE-KEY", "Private key", re.compile(r"-----BEGIN ((RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY( BLOCK)?-----")),
    ("SECRET-GENERIC", "Hard-coded credential", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)\b[\"']?\s*[:=]\s*[\"']([^\"'\s$<>{}]{16,})[\"']")),
]
SECRET_PLACEHOLDER = re.compile(r"(?i)(x{6,}|your[_-]|example|placeholder|dummy|changeme|redacted|sample|fake|test|<|\*{4,}|\.\.\.|0{8,}|1234)")

BIN_SHADOW = {
    "git", "ls", "cat", "cp", "mv", "rm", "curl", "wget", "ssh", "scp", "sudo", "python", "python3", "pip", "pip3",
    "node", "npm", "npx", "pnpm", "yarn", "bun", "uv", "uvx", "brew", "docker", "kubectl", "aws", "gcloud", "gh", "make",
    "bash", "sh", "zsh", "env", "which", "grep", "find", "sed", "awk", "open", "claude", "code", "go", "cargo", "rustc",
    "java", "ruby", "gem", "tar", "zip", "unzip", "chmod", "chown", "head", "tail", "echo", "printf", "test", "security",
}

RESERVED_NAME = re.compile(r"^(claude|anthropic|anthropics|cc-plugin)-|^(claude|anthropic|anthropics|claude-code|claude-mods)$|official[-_]?(claude|anthropic)|(claude|anthropic)[-_]?official")
CLAUDE_WORD = re.compile(r"(^|[-_.])(claude|anthropic|anthropics)($|[-_.])")

SENSITIVE_PATH_HINTS = re.compile(r"\.ssh\b|id_rsa|id_ed25519|\.aws/|gcloud|\.kube/|\.docker/config|\.npmrc|\.netrc|\.git-credentials|Keychains|Login Data|Cookies|\.claude/\.credentials|\.claude/settings|\.claude\.json|\.zshrc|\.bashrc|LaunchAgents", re.I)
ENV_SECRET_READ = re.compile(r"""(?:process\.env(?:\.|\[\s*['"])|os\.environ(?:\.get)?\s*[\[(]\s*['"]|os\.getenv\s*\(\s*['"]|\$\{?)([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIALS?|AUTH|PAT)[A-Z0-9_]*)""")
URL_RE = re.compile(r"""\b(?:https?|wss?)://([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?""")
IGNORED_HOSTS = re.compile(r"(^|\.)(example\.(com|org|net)|localhost|w3\.org|json-schema\.org|schema\.org|schemastore\.org|purl\.org|xmlns\.com|creativecommons\.org|opensource\.org|semver\.org|shields\.io|img\.shields\.io|apache\.org|mozilla\.org|spdx\.org|unicode\.org|ietf\.org|rfc-editor\.org)$")


# Checks that read plugin structure (manifests, hook and MCP configs, packages)
# rather than matching single lines. Listed here so `warden rules` can show them.
STRUCTURAL_RULES: dict[str, tuple[str, str]] = {
    "HOOK-EXTERNAL-COMMAND": ("auto-execution", "Hook runs a command that lives outside the plugin"),
    "HOOK-ALL-TOOLS": ("auto-execution", "Hook matcher fires on every tool call"),
    "HOOK-HTTP": ("exfiltration", "HTTP hook posts tool input to a URL"),
    "HOOK-MODEL": ("prompt-injection", "Prompt or agent hook asks a model to decide"),
    "MCP-REMOTE": ("network", "Remote MCP server receives tool calls"),
    "MCP-CLEARTEXT": ("network", "MCP server over plain http"),
    "MCP-HEADERS-HELPER": ("auto-execution", "MCP headersHelper runs a command for auth headers"),
    "MCP-UNPINNED": ("supply-chain", "MCP server launched from an unpinned package"),
    "MCP-UNPINNED-IMAGE": ("supply-chain", "MCP server runs an unpinned container image"),
    "MCP-CONTAINER-ESCAPE": ("privilege", "Container MCP server mounts host paths or runs privileged"),
    "MCP-EXTERNAL-BINARY": ("auto-execution", "MCP server is a binary outside the plugin"),
    "MCP-BUNDLE": ("integrity", "MCP bundle (.mcpb/.dxt) that cannot be read as source"),
    "SECRET-MCP-ENV": ("secrets", "Credential written into an MCP server env block"),
    "SECRET-MCP-HEADER": ("secrets", "Credential written into an MCP server header"),
    "LSP-SERVER": ("auto-execution", "LSP server starts with matching files"),
    "MONITOR-BACKGROUND": ("auto-execution", "Monitor runs a background command"),
    "STATUSLINE-COMMAND": ("auto-execution", "Status line runs a command on every render"),
    "BIN-EXECUTABLE": ("auto-execution", "Executable added to Claude's PATH"),
    "BIN-SHADOW": ("integrity", "PATH executable shadows a common system command"),
    "NAME-IMPERSONATION": ("impersonation", "Plugin name passes as an official Anthropic plugin"),
    "NAME-LOOKALIKE": ("impersonation", "Plugin name contains claude or anthropic"),
    "MARKETPLACE-IMPERSONATION": ("impersonation", "Marketplace name passes as official"),
    "MARKETPLACE-COMMAND-SOURCE": ("remote-code", "Marketplace entry installs by running a command"),
    "MARKETPLACE-ARCHIVE-UNPINNED": ("supply-chain", "Marketplace archive source without a checksum"),
    "MARKETPLACE-HEADERS-HELPER": ("auto-execution", "Marketplace source runs a headers helper"),
    "MARKETPLACE-UNPINNED": ("supply-chain", "Marketplace plugin source not pinned to a commit"),
    "PATH-ESCAPE": ("integrity", "Manifest path points outside the plugin"),
    "PLUGIN-DEPENDENCIES": ("supply-chain", "Plugin installs other plugins as dependencies"),
    "CONFIG-PLAINTEXT-SECRET": ("secrets", "Plain-text credential in a config file"),
    "CONFIG-PARSE-ERROR": ("integrity", "Config file Claude Code would load does not parse"),
    "BROAD-TOOL-GRANT": ("permissions", "Skill, command or agent grants broad tools"),
    "AGENT-PERMISSION-MODE": ("permissions", "Agent sets its own permission mode"),
    "AGENT-EMBEDDED-CONFIG": ("auto-execution", "Agent file embeds hooks or MCP servers"),
    "INLINE-SHELL": ("auto-execution", "Command or skill runs inline shell when loaded"),
    "NPM-INSTALL-SCRIPT": ("supply-chain", "npm lifecycle script runs on install"),
    "PY-CUSTOM-INSTALL": ("supply-chain", "Python package runs custom code on install"),
    "DEP-GIT-SOURCE": ("supply-chain", "Dependency installed from a git URL"),
    "DEP-UNPINNED": ("supply-chain", "Dependency without a pinned version"),
    "DEP-NO-LOCKFILE": ("supply-chain", "Dependencies without a lockfile"),
    "GIT-SUBMODULES": ("supply-chain", "Git submodules pull code from elsewhere"),
    "SYMLINK-ESCAPE": ("integrity", "Symlink points outside the repository"),
    "ARCHIVE-FILE": ("integrity", "Archive that cannot be reviewed in place"),
    "COMPILED-BINARY": ("integrity", "Compiled executable shipped in the repo"),
    "MINIFIED-AUTORUN": ("obfuscation", "Minified code that runs automatically"),
    "VENDORED-DEPENDENCIES": ("supply-chain", "Vendored dependency folders shipped in the repo"),
    "EXFIL-CORRELATED": ("exfiltration", "Same file reads sensitive data and makes network calls"),
    "NET-AUTORUN": ("network", "Code that runs automatically makes network calls"),
    "HIDDEN-UNICODE": ("prompt-injection", "Invisible or bidirectional Unicode characters"),
    "DEP-TYPOSQUAT": ("supply-chain", "Dependency name is one slip away from a well-known package"),
    "DESTRUCT-ENCRYPT-CORRELATED": ("destructive", "Same file walks folders, encrypts and removes or overwrites files"),
}


# Well-known package names that typosquatters imitate. A dependency that is not on the list but is
# one edit (or one swapped pair, or a dropped separator) away from an entry is reported.
POPULAR_PACKAGES: dict[str, frozenset[str]] = {
    "npm": frozenset({
        "react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "request", "moment", "webpack", "typescript", "eslint",
        "prettier", "jquery", "angular", "nodemon", "dotenv", "mongoose", "underscore", "async", "debug", "yargs", "inquirer", "bluebird",
        "cheerio", "puppeteer", "playwright", "electron", "socket.io", "body-parser", "jsonwebtoken", "bcrypt", "node-fetch", "cross-env",
        "rimraf", "minimist", "semver", "colors", "mocha", "babel-core", "openai", "esbuild", "rollup", "tailwindcss", "discord.js", "ethers",
        "sharp", "dayjs", "date-fns", "winston", "passport", "nodemailer", "sequelize", "redis", "mysql", "sqlite3", "fs-extra", "shelljs",
        "execa", "tslib", "core-js", "classnames", "prop-types", "styled-components", "graphql", "firebase", "aws-sdk", "stripe", "twilio",
        "mcp-remote", "supergateway", "@modelcontextprotocol/sdk", "@anthropic-ai/sdk", "@anthropic-ai/claude-code", "@anthropic-ai/claude-agent-sdk",
    }),
    "pypi": frozenset({
        "requests", "urllib3", "numpy", "pandas", "boto3", "botocore", "setuptools", "pyyaml", "cryptography", "django", "flask", "fastapi",
        "pydantic", "httpx", "aiohttp", "beautifulsoup4", "selenium", "pillow", "scipy", "matplotlib", "tensorflow", "torch", "transformers",
        "openai", "anthropic", "fastmcp", "langchain", "sqlalchemy", "psycopg2", "pymongo", "redis", "celery", "pytest", "click", "typer",
        "jinja2", "colorama", "python-dotenv", "paramiko", "scikit-learn", "opencv-python", "pyjwt", "uvicorn", "gunicorn", "playwright",
        "discord.py", "pycryptodome", "python-dateutil", "certifi", "attrs", "websockets", "starlette", "claude-agent-sdk",
    }),
}
# Real packages that sit one edit away from a popular name.
TYPOSQUAT_ALLOW = frozenset({"preact", "requests", "color", "mysql2", "sqlite", "boto", "aredis", "torchx", "clickx", "redis-py", "flask2"})
KNOWN_SCOPES = ("@anthropic-ai", "@modelcontextprotocol")


def _one_edit(a: str, b: str) -> bool:
    """True when a and b differ by one insert, delete, substitute or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    short, long = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(short) and short[i] == long[i]:
        i += 1
    return short[i:] == long[i + 1:]


def typosquat_of(name: str, ecosystem: str) -> str | None:
    """The well-known package this name imitates, or None."""
    name = name.strip().lower()
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    popular = POPULAR_PACKAGES.get(ecosystem, frozenset())
    if not name or name in popular or name in TYPOSQUAT_ALLOW:
        return None
    if name.startswith("@") and "/" in name:
        scope = name.split("/", 1)[0]
        for known in KNOWN_SCOPES:
            if scope != known and (_one_edit(scope, known) or re.sub(r"[-_.]", "", scope) == re.sub(r"[-_.]", "", known)):
                return known + "/" + name.split("/", 1)[1]
    flat = re.sub(r"[-_.]", "", name)
    for known in popular:
        if len(known) < 5:
            continue
        if _one_edit(name, known) or (flat == re.sub(r"[-_.]", "", known) and ecosystem == "npm"):
            return known
    return None

