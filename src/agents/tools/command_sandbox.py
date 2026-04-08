"""Command sandbox — allowlist-based validation for executor commands.

Every command the executor agent wants to run on a remote host must pass
through this sandbox before execution.  The sandbox enforces:

  1. **Command allowlist** — only pre-approved binaries may be invoked.
  2. **Argument validation** — flags/arguments are checked against per-command
     rules (regex patterns, forbidden values, max length).
  3. **Injection prevention** — shell metacharacters are rejected.
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Characters that could enable shell injection
SHELL_METACHARACTERS = re.compile(r"[;&|`$(){}!\n\r\\]")

# Maximum total command length (bytes)
MAX_COMMAND_LENGTH = 4096

# Paths that file-accessing commands may operate on
ALLOWED_FILE_PATHS: list[str] = [
    "/etc/ssh/",
    "/etc/nginx/",
    "/etc/apache2/",
    "/etc/mysql/",
    "/etc/postgresql/",
    "/etc/sysctl.d/",
    "/etc/security/",
    "/etc/pam.d/",
    "/etc/ufw/",
    "/etc/iptables/",
    "/etc/os-release",
    "/etc/hostname",
    "/etc/hosts",
    "/var/log/",
    "/tmp/",
]

# Commands that require file path validation against ALLOWED_FILE_PATHS
FILE_COMMANDS: frozenset[str] = frozenset({
    "cat", "grep", "ls", "chmod", "chown", "sed", "tee", "cp", "mv",
})


@dataclass(frozen=True)
class CommandRule:
    """Validation rule for a single allowed command."""

    binary: str
    allowed_flags: frozenset[str] = field(default_factory=frozenset)
    # Flags that consume the next token as their value (e.g. --max-time 5)
    flags_with_values: frozenset[str] = field(default_factory=frozenset)
    # Regex patterns that each positional argument must match
    arg_patterns: list[re.Pattern] = field(default_factory=list)
    # If set, the first positional arg MUST match this pattern (subcommand)
    subcommand_pattern: re.Pattern | None = None
    # Whether to allow arbitrary positional args (e.g. package names)
    allow_positional: bool = False
    max_args: int = 20


# --- Default allowlist -------------------------------------------------------
# These are the commands the executor is permitted to run on target hosts.

_PACKAGE_NAME = re.compile(r"^[a-zA-Z0-9._+:~-]+$")
_FILE_PATH = re.compile(r"^/(?!.*\.\./)[a-zA-Z0-9._/~-]+$")
_SERVICE_NAME = re.compile(r"^[a-zA-Z0-9._@-]+$")
_SYSCTL_KEY = re.compile(r"^[a-z0-9._-]+=[a-zA-Z0-9._-]+$")
_LOCALHOST_URL = re.compile(
    r"^https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?(/[a-zA-Z0-9._/?&=%+-]*)?$"
)
_SED_PATTERN = re.compile(r"^[a-zA-Z0-9._/\\:; ^$*+?{}()|[\]-]+$")
_IPTABLES_ARG = re.compile(r"^[a-zA-Z0-9._:/-]+$")
_SERVICE_ACTION = re.compile(r"^(start|stop|restart|reload|status|force-reload|condrestart)$")

DEFAULT_ALLOWLIST: dict[str, CommandRule] = {
    # Package management
    "apt-get": CommandRule(
        binary="apt-get",
        allowed_flags=frozenset({"-y", "--yes", "-q", "--quiet", "--no-install-recommends", "--only-upgrade"}),
        arg_patterns=[re.compile(r"^(update|upgrade|install|remove|autoremove|dist-upgrade)$"), _PACKAGE_NAME],
        allow_positional=True,
        max_args=30,
    ),
    "dnf": CommandRule(
        binary="dnf",
        allowed_flags=frozenset({"-y", "--assumeyes", "-q", "--quiet", "--best", "--security"}),
        arg_patterns=[re.compile(r"^(update|upgrade|install|remove|check-update)$"), _PACKAGE_NAME],
        allow_positional=True,
        max_args=30,
    ),
    "yum": CommandRule(
        binary="yum",
        allowed_flags=frozenset({"-y", "--assumeyes", "-q", "--quiet", "--security"}),
        arg_patterns=[re.compile(r"^(update|upgrade|install|remove|check-update)$"), _PACKAGE_NAME],
        allow_positional=True,
        max_args=30,
    ),
    # Service management
    "systemctl": CommandRule(
        binary="systemctl",
        allowed_flags=frozenset({"--no-pager", "--quiet", "--now"}),
        arg_patterns=[re.compile(r"^(start|stop|restart|reload|enable|disable|status|is-active|daemon-reload)$"), _SERVICE_NAME],
        allow_positional=True,
        max_args=5,
    ),
    # File operations (limited)
    "chmod": CommandRule(
        binary="chmod",
        allowed_flags=frozenset({"-R", "--recursive"}),
        arg_patterns=[re.compile(r"^[0-7]{3,4}$"), _FILE_PATH],
        allow_positional=True,
        max_args=5,
    ),
    "chown": CommandRule(
        binary="chown",
        allowed_flags=frozenset({"-R", "--recursive"}),
        arg_patterns=[re.compile(r"^[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+$"), _FILE_PATH],
        allow_positional=True,
        max_args=5,
    ),
    # Kernel tuning
    "sysctl": CommandRule(
        binary="sysctl",
        allowed_flags=frozenset({"-w", "--write", "-p", "--load"}),
        arg_patterns=[_SYSCTL_KEY],
        allow_positional=True,
        max_args=5,
    ),
    # Firewall
    "ufw": CommandRule(
        binary="ufw",
        allowed_flags=frozenset(set()),
        arg_patterns=[re.compile(r"^(allow|deny|reject|delete|enable|disable|status|reload)$")],
        allow_positional=True,
        max_args=10,
    ),
    # Info gathering (read-only)
    "cat": CommandRule(binary="cat", arg_patterns=[_FILE_PATH], allow_positional=True, max_args=3),
    "ls": CommandRule(binary="ls", allowed_flags=frozenset({"-la", "-l", "-a", "-lh"}), arg_patterns=[_FILE_PATH], allow_positional=True, max_args=5),
    "grep": CommandRule(
        binary="grep",
        allowed_flags=frozenset({"-i", "-r", "-n", "-c", "-l", "-E", "-w"}),
        arg_patterns=[re.compile(r"^[a-zA-Z0-9._=:/ *@#%^-]+$"), _FILE_PATH],
        allow_positional=True,
        max_args=5,
    ),
    "whoami": CommandRule(binary="whoami", max_args=0),
    "uname": CommandRule(binary="uname", allowed_flags=frozenset({"-a", "-r", "-s"}), max_args=2),
    "id": CommandRule(binary="id", max_args=1),
    "dpkg": CommandRule(binary="dpkg", allowed_flags=frozenset({"-l", "--list", "-s", "--status", "--get-selections"}), allow_positional=True, max_args=5),
    "rpm": CommandRule(binary="rpm", allowed_flags=frozenset({"-qa", "-qi", "-q", "--query"}), allow_positional=True, max_args=5),
    # Config editing
    "sed": CommandRule(
        binary="sed",
        allowed_flags=frozenset({"-i", "--in-place", "-e", "-E"}),
        arg_patterns=[_SED_PATTERN, _FILE_PATH],
        allow_positional=True,
        max_args=5,
    ),
    "tee": CommandRule(
        binary="tee",
        allowed_flags=frozenset({"-a", "--append"}),
        arg_patterns=[_FILE_PATH],
        allow_positional=True,
        max_args=3,
    ),
    "cp": CommandRule(
        binary="cp",
        allowed_flags=frozenset({"-p", "--preserve", "-a", "--archive"}),
        arg_patterns=[_FILE_PATH],
        allow_positional=True,
        max_args=5,
    ),
    "mv": CommandRule(
        binary="mv",
        allowed_flags=frozenset(),
        arg_patterns=[_FILE_PATH],
        allow_positional=True,
        max_args=3,
    ),
    # Health checks (restricted to local/internal URLs)
    "curl": CommandRule(
        binary="curl",
        allowed_flags=frozenset({"-s", "--silent", "--max-time", "--connect-timeout", "-w", "-k", "-f", "--fail", "-sf", "-sk", "-ks"}),
        flags_with_values=frozenset({"--max-time", "--connect-timeout", "-w"}),
        arg_patterns=[_LOCALHOST_URL],
        allow_positional=True,
        max_args=5,
    ),
    # Socket/network verification
    "ss": CommandRule(
        binary="ss",
        allowed_flags=frozenset({"-t", "-u", "-l", "-n", "-p", "-tlnp", "-tunlp"}),
        max_args=0,
    ),
    "netstat": CommandRule(
        binary="netstat",
        allowed_flags=frozenset({"-t", "-u", "-l", "-n", "-p", "-tlnp", "-tunlp"}),
        max_args=0,
    ),
    # Firewall
    "iptables": CommandRule(
        binary="iptables",
        allowed_flags=frozenset({"-A", "-I", "-D", "-L", "-n", "--list", "-p", "--dport", "--sport", "-j", "-s", "-d"}),
        arg_patterns=[_IPTABLES_ARG],
        allow_positional=True,
        max_args=15,
    ),
    # Python packages
    "pip": CommandRule(
        binary="pip",
        allowed_flags=frozenset({"--upgrade", "--user", "--no-deps", "-q", "--quiet"}),
        subcommand_pattern=re.compile(r"^(install)$"),
        arg_patterns=[_PACKAGE_NAME],
        allow_positional=True,
        max_args=10,
    ),
    # Legacy service management
    "service": CommandRule(
        binary="service",
        allowed_flags=frozenset(),
        subcommand_pattern=_SERVICE_NAME,
        arg_patterns=[_SERVICE_ACTION],
        allow_positional=True,
        max_args=3,
    ),
}


@dataclass(frozen=True)
class SandboxVerdict:
    """Result of a sandbox check."""

    allowed: bool
    command: str
    reason: str = ""


class CommandSandbox:
    """Validates commands against an allowlist before remote execution."""

    def __init__(self, allowlist: dict[str, CommandRule] | None = None) -> None:
        self._rules = allowlist or DEFAULT_ALLOWLIST

    def _validate_file_paths(self, binary: str, positionals: list[str], command: str) -> SandboxVerdict | None:
        """Check file path arguments against the allowed paths list."""
        if binary not in FILE_COMMANDS:
            return None
        for arg in positionals:
            if arg.startswith("/"):
                if not any(arg.startswith(prefix) for prefix in ALLOWED_FILE_PATHS):
                    return SandboxVerdict(
                        allowed=False,
                        command=command,
                        reason=f"Path '{arg}' is not in the allowed file paths",
                    )
        return None

    def validate(self, command: str) -> SandboxVerdict:
        """Check whether *command* is safe to execute remotely."""
        if not command or not command.strip():
            return SandboxVerdict(allowed=False, command=command, reason="Empty command")

        if len(command) > MAX_COMMAND_LENGTH:
            return SandboxVerdict(allowed=False, command=command, reason=f"Command exceeds max length ({MAX_COMMAND_LENGTH})")

        # Reject shell metacharacters to prevent injection
        if SHELL_METACHARACTERS.search(command):
            return SandboxVerdict(
                allowed=False,
                command=command,
                reason="Command contains forbidden shell metacharacters",
            )

        try:
            tokens = shlex.split(command)
        except ValueError as e:
            return SandboxVerdict(allowed=False, command=command, reason=f"Unparseable command: {e}")

        if not tokens:
            return SandboxVerdict(allowed=False, command=command, reason="Empty command after parsing")

        binary = tokens[0].split("/")[-1]  # handle /usr/bin/apt-get → apt-get
        rule = self._rules.get(binary)
        if rule is None:
            return SandboxVerdict(
                allowed=False,
                command=command,
                reason=f"Binary '{binary}' is not in the allowlist",
            )

        # Separate flags from positional arguments, consuming flag values
        flags: list[str] = []
        positionals: list[str] = []
        args = tokens[1:]
        i = 0
        while i < len(args):
            tok = args[i]
            if tok.startswith("-"):
                flags.append(tok)
                # If this flag consumes a value, skip the next token
                if tok in rule.flags_with_values and i + 1 < len(args):
                    i += 1  # skip the value token
            else:
                positionals.append(tok)
            i += 1

        # Validate flags
        for flag in flags:
            if flag not in rule.allowed_flags:
                return SandboxVerdict(
                    allowed=False,
                    command=command,
                    reason=f"Flag '{flag}' is not allowed for '{binary}'",
                )

        # Validate argument count
        if len(positionals) > rule.max_args:
            return SandboxVerdict(
                allowed=False,
                command=command,
                reason=f"Too many arguments ({len(positionals)} > {rule.max_args})",
            )

        # Validate subcommand (first positional) if required
        if rule.subcommand_pattern and positionals:
            if not rule.subcommand_pattern.match(positionals[0]):
                return SandboxVerdict(
                    allowed=False,
                    command=command,
                    reason=f"Subcommand '{positionals[0]}' is not allowed for '{binary}'",
                )

        # Validate positional arguments against patterns
        # If subcommand_pattern is set, skip the first positional (already validated)
        args_to_check = positionals[1:] if rule.subcommand_pattern and positionals else positionals
        if args_to_check and rule.arg_patterns:
            for arg in args_to_check:
                if not any(pat.match(arg) for pat in rule.arg_patterns):
                    return SandboxVerdict(
                        allowed=False,
                        command=command,
                        reason=f"Argument '{arg}' does not match any allowed pattern for '{binary}'",
                    )
        elif args_to_check and not rule.allow_positional:
            return SandboxVerdict(
                allowed=False,
                command=command,
                reason=f"'{binary}' does not accept positional arguments",
            )

        # Validate file paths against allowed prefixes
        path_verdict = self._validate_file_paths(binary, positionals, command)
        if path_verdict is not None:
            return path_verdict

        return SandboxVerdict(allowed=True, command=command)
