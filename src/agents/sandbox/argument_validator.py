"""Argument validation — injection prevention, dangerous pattern blocking, path validation.

Runs on ALL commands (allowlisted and unknown) as the first layer of the
sandbox pipeline. This layer catches shell injection and known-dangerous
operations before the allowlist or LLM risk scorer even see the command.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

MAX_COMMAND_LENGTH = 4096

ALLOWED_PATH_PREFIXES: list[str] = [
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
    "/etc/ssl/",
    "/etc/default/",
    "/etc/cron.d/",
    "/etc/os-release",
    "/etc/hostname",
    "/etc/hosts",
    "/var/log/",
    "/tmp/",
]

CREDENTIAL_FILES: frozenset[str] = frozenset({
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
})

PATH_EXEMPT_COMMANDS: frozenset[str] = frozenset({
    "apt-get", "apt", "yum", "dnf", "pip",
    "systemctl", "service",
    "whoami", "uname", "id",
    "ss", "netstat",
    "sysctl",
    "ufw",
    "dpkg", "rpm",
})

FILE_COMMANDS: frozenset[str] = frozenset({
    "cat", "grep", "ls", "chmod", "chown", "sed", "tee", "cp", "mv",
})

INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\|"), "pipe operator"),
    (re.compile(r";"), "semicolon"),
    (re.compile(r"&&"), "double ampersand"),
    (re.compile(r"\|\|"), "double pipe"),
    (re.compile(r"\$\("), "command substitution $()"),
    (re.compile(r"`"), "backtick"),
    (re.compile(r">\s*/dev/"), "redirect to device"),
]

DANGEROUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+.*)?/\s*$"), "dangerous: rm -rf /"),
    (re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/"), "dangerous: recursive force delete from root"),
    (re.compile(r"\bdd\s+if="), "dangerous: dd disk operation"),
    (re.compile(r"\bmkfs"), "dangerous: filesystem formatting"),
    (re.compile(r"\bwget\b"), "dangerous: wget download"),
    (re.compile(r"\bcurl\s+.*-[a-zA-Z]*o\b"), "dangerous: curl file download"),
    (re.compile(r"\bchmod\s+777\b"), "dangerous: world-writable permissions"),
]


@dataclass(frozen=True)
class ValidationResult:
    """Result of argument validation."""

    valid: bool
    sanitized_command: str | None = None
    rejection_reason: str | None = None


class ArgumentValidator:
    """Validates command arguments for injection and dangerous patterns."""

    def __init__(
        self,
        allowed_paths: list[str] | None = None,
        credential_files: frozenset[str] | None = None,
    ) -> None:
        self._allowed_paths = allowed_paths or ALLOWED_PATH_PREFIXES
        self._credential_files = credential_files or CREDENTIAL_FILES

    def validate(self, command: str) -> ValidationResult:
        if not command or not command.strip():
            return ValidationResult(valid=False, rejection_reason="Empty command")

        command = command.strip()

        if len(command) > MAX_COMMAND_LENGTH:
            return ValidationResult(
                valid=False,
                rejection_reason=f"Command exceeds max length ({MAX_COMMAND_LENGTH})",
            )

        for pattern, description in INJECTION_PATTERNS:
            if pattern.search(command):
                return ValidationResult(
                    valid=False,
                    rejection_reason=f"Injection blocked: {description}",
                )

        for pattern, description in DANGEROUS_PATTERNS:
            if pattern.search(command):
                return ValidationResult(
                    valid=False,
                    rejection_reason=f"Dangerous pattern blocked: {description}",
                )

        for cred_file in self._credential_files:
            if cred_file in command:
                binary = command.split()[0].split("/")[-1] if command.split() else ""
                if binary not in ("cat", "grep", "ls"):
                    return ValidationResult(
                        valid=False,
                        rejection_reason=f"Dangerous path blocked: write to {cred_file}",
                    )

        binary = command.split()[0].split("/")[-1] if command.split() else ""
        if binary in FILE_COMMANDS and binary not in PATH_EXEMPT_COMMANDS:
            result = self._validate_paths(command, binary)
            if result is not None:
                return result

        return ValidationResult(valid=True, sanitized_command=command)

    def _validate_paths(self, command: str, binary: str) -> ValidationResult | None:
        try:
            tokens = shlex.split(command)
        except ValueError:
            return ValidationResult(valid=False, rejection_reason="Unparseable command")

        for token in tokens[1:]:
            if token.startswith("-"):
                continue
            if token.startswith("/"):
                if not any(token.startswith(prefix) for prefix in self._allowed_paths):
                    return ValidationResult(
                        valid=False,
                        rejection_reason=f"Path not allowed: {token}",
                    )
        return None
