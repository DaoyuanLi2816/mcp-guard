"""Rule catalog and shared constants.

Each rule has a stable identifier (``MCPGNNN``). Rule definitions are loaded
at import time and exposed via :data:`RULE_CATALOG` and the helper
:func:`rule`.
"""

from __future__ import annotations

from typing import TypedDict

from .models import Severity


class RuleSpec(TypedDict):
    id: str
    title: str
    severity: Severity
    category: str
    rationale: str
    recommendation: str


# Categories (kept short so reports group cleanly).
CAT_STARTUP = "startup-command"
CAT_TRANSPORT = "transport-binding"
CAT_SECRETS = "secrets"
CAT_METADATA = "tool-metadata"
CAT_SCHEMA = "schema"
CAT_DYNAMIC = "dynamic-behavior"
CAT_SANDBOX = "sandbox"
CAT_PROTOCOL = "protocol"


_RULES: list[RuleSpec] = [
    # A. Config / startup
    {
        "id": "MCPG001",
        "title": "Server start command uses a shell",
        "severity": Severity.MEDIUM,
        "category": CAT_STARTUP,
        "rationale": (
            "Launching the MCP server through a shell (`sh -c`, `bash -c`, "
            "`shell: true`) expands metacharacters and broadens the attack "
            "surface."
        ),
        "recommendation": "Invoke the interpreter directly with an argv list.",
    },
    {
        "id": "MCPG002",
        "title": "Start command downloads and executes code",
        "severity": Severity.CRITICAL,
        "category": CAT_STARTUP,
        "rationale": (
            "`curl | sh`, `wget | sh`, `base64 -d | sh`, or piping a network "
            "fetch into a shell is a supply-chain compromise."
        ),
        "recommendation": (
            "Vendor and review the script, then run it from a local path."
        ),
    },
    {
        "id": "MCPG003",
        "title": "Start command uses sudo",
        "severity": Severity.HIGH,
        "category": CAT_STARTUP,
        "rationale": "Root privileges should not be required to run a local MCP server.",
        "recommendation": "Run as a non-privileged user; use Docker for isolation.",
    },
    {
        "id": "MCPG004",
        "title": "Start command contains destructive operations",
        "severity": Severity.HIGH,
        "category": CAT_STARTUP,
        "rationale": "`rm -rf`, `mkfs`, `dd`, or `chmod 777` should never appear in a start command.",
        "recommendation": "Remove the destructive call or move it to a documented setup step.",
    },
    {
        "id": "MCPG005",
        "title": "Start command references sensitive host paths",
        "severity": Severity.HIGH,
        "category": CAT_STARTUP,
        "rationale": (
            "Touching ~/.ssh, ~/.aws, /etc, or /var/run/docker.sock from the "
            "start command implies elevated access to host secrets."
        ),
        "recommendation": "Avoid touching credential directories; use Docker named volumes.",
    },
    {
        "id": "MCPG006",
        "title": "Plaintext secret in env",
        "severity": Severity.HIGH,
        "category": CAT_SECRETS,
        "rationale": "Secrets in `env` end up in process listings and config commits.",
        "recommendation": "Read secrets from a vault or environment at runtime.",
    },
    {
        "id": "MCPG007",
        "title": "HTTP transport bound to 0.0.0.0",
        "severity": Severity.HIGH,
        "category": CAT_TRANSPORT,
        "rationale": (
            "Binding to `0.0.0.0` exposes the MCP server to the local "
            "network and to other users on the host."
        ),
        "recommendation": "Bind to 127.0.0.1 or a Unix socket.",
    },
    {
        "id": "MCPG008",
        "title": "HTTP/SSE transport without authentication",
        "severity": Severity.HIGH,
        "category": CAT_TRANSPORT,
        "rationale": "Any local process or webpage can call an unauthenticated transport.",
        "recommendation": "Require a bearer token or OAuth; bind to localhost.",
    },
    {
        "id": "MCPG009",
        "title": "Server allows broad filesystem access",
        "severity": Severity.MEDIUM,
        "category": CAT_STARTUP,
        "rationale": (
            "Mounting `$HOME` or allow-all directory lists removes the "
            "principle of least privilege."
        ),
        "recommendation": "Specify an explicit allowlist of subdirectories.",
    },
    # B. Metadata / tool poisoning
    {
        "id": "MCPG010",
        "title": "Prompt-injection phrase in tool description",
        "severity": Severity.HIGH,
        "category": CAT_METADATA,
        "rationale": (
            "Phrases like 'ignore previous instructions' in tool metadata "
            "indicate tool poisoning."
        ),
        "recommendation": "Remove the phrase and treat tool descriptions as untrusted input downstream.",
    },
    {
        "id": "MCPG011",
        "title": "Hidden instruction in tool description",
        "severity": Severity.HIGH,
        "category": CAT_METADATA,
        "rationale": (
            "HTML comments, zero-width characters, or invisible markdown in a "
            "description hide instructions from human reviewers."
        ),
        "recommendation": "Strip hidden content; render descriptions as plain text.",
    },
    {
        "id": "MCPG012",
        "title": "Confusable tool name",
        "severity": Severity.MEDIUM,
        "category": CAT_METADATA,
        "rationale": (
            "Unicode confusables or near-misses of common tool names enable "
            "spoofing in tool registries."
        ),
        "recommendation": "Use ASCII names that do not collide with well-known tools.",
    },
    {
        "id": "MCPG013",
        "title": "Overly broad tool name",
        "severity": Severity.LOW,
        "category": CAT_METADATA,
        "rationale": (
            "Generic names like `execute`, `run`, `admin`, `shell`, `eval` "
            "make least-privilege impossible."
        ),
        "recommendation": "Use action-scoped names like `read_repo_file`.",
    },
    {
        "id": "MCPG014",
        "title": "Description claims read-only but exposes destructive surface",
        "severity": Severity.MEDIUM,
        "category": CAT_METADATA,
        "rationale": (
            "A read-only claim contradicted by `command`, `exec`, or write-like "
            "parameters misleads clients and human reviewers."
        ),
        "recommendation": "Match the description, schema, and annotations.",
    },
    {
        "id": "MCPG015",
        "title": "Destructive annotation without schema guard",
        "severity": Severity.MEDIUM,
        "category": CAT_METADATA,
        "rationale": (
            "If `annotations.destructiveHint` is true the schema should "
            "constrain inputs (enum/pattern) and require explicit confirmation."
        ),
        "recommendation": "Add input constraints; gate destructive calls on a confirmation flag.",
    },
    {
        "id": "MCPG016",
        "title": "Read-only assertion contradicted by parameters",
        "severity": Severity.MEDIUM,
        "category": CAT_METADATA,
        "rationale": "`readOnlyHint: true` but parameters include `url`, `command`, `code`, etc.",
        "recommendation": "Set `readOnlyHint: false` or remove the contradictory parameter.",
    },
    {
        "id": "MCPG017",
        "title": "Tool inputSchema missing type=object",
        "severity": Severity.LOW,
        "category": CAT_SCHEMA,
        "rationale": "MCP tool schemas should declare `type: object` so clients can validate.",
        "recommendation": "Set `type: object` and list `properties`.",
    },
    {
        "id": "MCPG018",
        "title": "Dangerous tool with no required parameters",
        "severity": Severity.LOW,
        "category": CAT_SCHEMA,
        "rationale": "A high-risk tool that accepts an empty object hides the cost of a call.",
        "recommendation": "Mark the operational parameter(s) as `required`.",
    },
    {
        "id": "MCPG019",
        "title": "additionalProperties not restricted",
        "severity": Severity.LOW,
        "category": CAT_SCHEMA,
        "rationale": (
            "Allowing arbitrary additional properties on a high-risk tool "
            "smuggles unvetted fields through validators."
        ),
        "recommendation": "Set `additionalProperties: false`.",
    },
    {
        "id": "MCPG020",
        "title": "Unbounded string parameter",
        "severity": Severity.LOW,
        "category": CAT_SCHEMA,
        "rationale": "Large string inputs can hang servers and stress LLM clients.",
        "recommendation": "Set a reasonable `maxLength`.",
    },
    {
        "id": "MCPG021",
        "title": "High-risk parameter lacks pattern/enum",
        "severity": Severity.MEDIUM,
        "category": CAT_SCHEMA,
        "rationale": (
            "Parameters that look like paths, URLs, or commands need a "
            "pattern, enum, or explicit allowlist."
        ),
        "recommendation": "Add a `pattern` or `enum` that reflects the allowed surface.",
    },
    {
        "id": "MCPG022",
        "title": "High-risk parameter name",
        "severity": Severity.MEDIUM,
        "category": CAT_SCHEMA,
        "rationale": (
            "Parameter names like `command`, `eval`, `token`, `webhook` "
            "demand careful schema and runtime handling."
        ),
        "recommendation": "Constrain the parameter or rename to a narrower verb.",
    },
    {
        "id": "MCPG023",
        "title": "Tool name implies arbitrary code execution",
        "severity": Severity.HIGH,
        "category": CAT_METADATA,
        "rationale": "Tools named `eval`, `exec`, `run_command`, `shell` are essentially RCE primitives.",
        "recommendation": (
            "Replace with a narrowly scoped tool; if RCE is truly required, "
            "require sandboxing and explicit per-call confirmation."
        ),
    },
    {
        "id": "MCPG024",
        "title": "Suspiciously long or HTML-formatted description",
        "severity": Severity.LOW,
        "category": CAT_METADATA,
        "rationale": "Long descriptions often hide instructions inside markup.",
        "recommendation": "Keep descriptions concise plain text.",
    },
    # D. Dynamic behaviour
    {
        "id": "MCPG025",
        "title": "Path traversal succeeded",
        "severity": Severity.CRITICAL,
        "category": CAT_DYNAMIC,
        "rationale": "Tool returned the contents of a file outside the intended directory.",
        "recommendation": "Resolve and canonicalize paths; enforce an allowlist.",
    },
    {
        "id": "MCPG026",
        "title": "Command injection marker observed",
        "severity": Severity.CRITICAL,
        "category": CAT_DYNAMIC,
        "rationale": "A harmless marker payload was executed by the tool implementation.",
        "recommendation": "Use argv-form subprocess; never call `shell=True` with concatenated input.",
    },
    {
        "id": "MCPG027",
        "title": "SSRF payload accepted without validation",
        "severity": Severity.HIGH,
        "category": CAT_DYNAMIC,
        "rationale": (
            "URLs targeting loopback, link-local, or metadata IPs were not "
            "rejected by the tool."
        ),
        "recommendation": "Validate URLs against an allowlist; deny RFC1918 and link-local.",
    },
    {
        "id": "MCPG028",
        "title": "Prompt injection payload reflected",
        "severity": Severity.MEDIUM,
        "category": CAT_DYNAMIC,
        "rationale": (
            "Tool returned attacker text verbatim with no separation between "
            "tool output and instructions."
        ),
        "recommendation": "Wrap tool output in an explicit envelope and treat it as untrusted.",
    },
    {
        "id": "MCPG029",
        "title": "Server timed out on oversize input",
        "severity": Severity.MEDIUM,
        "category": CAT_DYNAMIC,
        "rationale": "Large input caused the server to hang or exceed the call timeout.",
        "recommendation": "Add a request-size cap and bounded I/O.",
    },
    {
        "id": "MCPG030",
        "title": "Malformed input passed validation",
        "severity": Severity.MEDIUM,
        "category": CAT_DYNAMIC,
        "rationale": "Tool accepted input that violates its declared schema.",
        "recommendation": "Validate against the declared JSON schema before dispatch.",
    },
    {
        "id": "MCPG031",
        "title": "Sensitive value in tool output",
        "severity": Severity.HIGH,
        "category": CAT_DYNAMIC,
        "rationale": (
            "Tool returned content matching a secret pattern (private key, "
            "AWS access key, GitHub token, ...)."
        ),
        "recommendation": "Filter or redact secret-shaped strings before return.",
    },
    {
        "id": "MCPG032",
        "title": "Error response leaks stack trace or absolute path",
        "severity": Severity.LOW,
        "category": CAT_DYNAMIC,
        "rationale": "Stack traces and absolute paths reveal the host layout to clients.",
        "recommendation": "Return user-safe error messages; log details server-side.",
    },
    {
        "id": "MCPG033",
        "title": "Docker socket exposed to server",
        "severity": Severity.CRITICAL,
        "category": CAT_SANDBOX,
        "rationale": "Mounting `/var/run/docker.sock` gives the server root on the host.",
        "recommendation": "Never mount the Docker socket into an MCP container.",
    },
    {
        "id": "MCPG034",
        "title": "Privileged container or no-new-privileges disabled",
        "severity": Severity.HIGH,
        "category": CAT_SANDBOX,
        "rationale": "Privileged containers bypass kernel isolation.",
        "recommendation": "Run with `--security-opt no-new-privileges` and drop all capabilities by default.",
    },
    {
        "id": "MCPG035",
        "title": "Server failed to respond within timeout",
        "severity": Severity.LOW,
        "category": CAT_PROTOCOL,
        "rationale": "Tool or initialize call exceeded the configured timeout.",
        "recommendation": "Tune the call timeout or investigate the server hang.",
    },
]

RULE_CATALOG: dict[str, RuleSpec] = {r["id"]: r for r in _RULES}


def rule(rule_id: str) -> RuleSpec:
    return RULE_CATALOG[rule_id]


# Patterns used by metadata / config scanners.
PROMPT_INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore the previous instructions",
    "ignore prior instructions",
    "disregard previous",
    "do not tell the user",
    "do not mention",
    "secretly",
    "exfiltrate",
    "send to https://",
    "send the result to",
    "hidden instruction",
    "system prompt",
    "developer message",
    "override the assistant",
    "you must comply",
    "this is the new system prompt",
    "as an assistant you should",
    "<!--",  # HTML comments are how a lot of poisoning hides
]

OVERLY_BROAD_TOOL_NAMES = {
    "execute",
    "run",
    "admin",
    "shell",
    "eval",
    "do",
    "go",
    "exec",
    "command",
}

# Names that are essentially RCE primitives.
RCE_TOOL_NAME_TOKENS = {
    "shell",
    "exec",
    "eval",
    "run_command",
    "runcmd",
    "subprocess",
    "system_call",
    "bash",
}

# Parameter names that imply higher risk and need schema constraints.
HIGH_RISK_PARAM_NAMES = {
    "command": "command-injection",
    "cmd": "command-injection",
    "shell": "command-injection",
    "exec": "command-injection",
    "code": "code-execution",
    "eval": "code-execution",
    "script": "code-execution",
    "path": "path-traversal",
    "filepath": "path-traversal",
    "file_path": "path-traversal",
    "filename": "path-traversal",
    "directory": "path-traversal",
    "url": "ssrf",
    "endpoint": "ssrf",
    "webhook": "ssrf",
    "callback": "ssrf",
    "token": "secret-leak",
    "api_key": "secret-leak",
    "secret": "secret-leak",
    "credential": "secret-leak",
    "query": "injection",
    "filter": "injection",
    "expression": "injection",
}

# Patterns used by the dynamic detector.
SECRET_PATTERNS = [
    (
        "aws-access-key",
        r"AKIA[0-9A-Z]{16}",
    ),
    (
        "github-token",
        r"gh[pousr]_[A-Za-z0-9]{36,}",
    ),
    (
        "github-classic",
        r"github_pat_[A-Za-z0-9_]{60,}",
    ),
    (
        "openai-key",
        r"sk-[A-Za-z0-9_\-]{20,}",
    ),
    (
        "anthropic-key",
        r"sk-ant-[A-Za-z0-9_\-]{20,}",
    ),
    (
        "private-key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----",
    ),
    (
        "google-api-key",
        r"AIza[0-9A-Za-z_\-]{30,}",
    ),
    (
        "slack-token",
        r"xox[abprs]-[A-Za-z0-9-]{10,}",
    ),
]

# Patterns that should not appear inside start commands.
DANGEROUS_START_PATTERNS = [
    (r"\bcurl\b[^|]*\|\s*(?:sh|bash|zsh|sh\s+-)", "MCPG002"),
    (r"\bwget\b[^|]*\|\s*(?:sh|bash|zsh|sh\s+-)", "MCPG002"),
    (r"base64\s+(?:-d|--decode)[^|]*\|\s*(?:sh|bash|python)", "MCPG002"),
    (r"\bsudo\b", "MCPG003"),
    (r"\brm\s+-[rRf]{1,2}\b", "MCPG004"),
    (r"\bmkfs\b", "MCPG004"),
    (r"\bchmod\s+777\b", "MCPG004"),
    (r"~/?\.ssh\b", "MCPG005"),
    (r"~/?\.aws\b", "MCPG005"),
    (r"~/?\.gnupg\b", "MCPG005"),
    (r"/var/run/docker\.sock", "MCPG033"),
    (r"--privileged\b", "MCPG034"),
]

# Marker token used by the safe command-injection fuzzer.
FUZZ_MARKER = "MCPG_FUZZ_MARKER_8f2a"

DEFAULT_TIMEOUTS = {
    "initialize": 10.0,
    "tools_list": 10.0,
    "tools_call": 8.0,
    "oversize_call": 4.0,
}
