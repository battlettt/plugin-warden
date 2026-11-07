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
        r(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|ssl\._create_unverified_context|CERT_NONE|\bcurl\s+[^\n]*(\s-k\b|--insecure)|InsecureSkipVerify:\s*true|PYTHONHTTPSVERIFY\s*=\s*[\"']?0"),
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
}
