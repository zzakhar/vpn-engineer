"""
VPN Engineer - Robust SSH & Remote Execution Client
Includes read-only safety guard, dry-run mode, and atomic remote file updates.
"""

import os
import stat
import time
import socket
import tempfile
from typing import Optional, Tuple, Dict, Any, List
import paramiko

class SSHExecutionError(Exception):
    pass

class ReadOnlyViolationError(Exception):
    pass

class RemoteSSHClient:
    """Safe, resilient SSH client for remote Linux VPN management."""

    # Commands that alter state on the remote machine
    MUTATING_COMMAND_TRIGGERS = [
        "systemctl restart", "systemctl stop", "systemctl disable", "systemctl enable",
        "rm ", "mv ", "cp ", "sed -i", "apt ", "apt-get", "yum ", "dnf ",
        "iptables -A", "iptables -D", "iptables -I", "iptables -F",
        "nft ", "ufw ", "reboot", "shutdown", ">", "tee ", "install "
    ]

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        timeout: int = 15,
        read_only: bool = True,
        dry_run: bool = False
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.timeout = timeout
        self.read_only = read_only
        self.dry_run = dry_run
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    def connect(self) -> None:
        """Establishes SSH and SFTP connections with auto-accept host keys."""
        if self._client:
            return

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self._client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout
            )
        except Exception as e:
            self._client = None
            raise SSHExecutionError(f"Failed to connect to {self.host}:{self.port} as {self.username}: {e}")

    def close(self) -> None:
        """Closes SFTP and SSH connections."""
        if self._sftp:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def sftp(self) -> paramiko.SFTPClient:
        if not self._sftp:
            self.connect()
            self._sftp = self._client.open_sftp()
        return self._sftp

    def is_mutating_command(self, cmd: str) -> bool:
        cmd_lower = cmd.lower()
        return any(trigger in cmd_lower for trigger in self.MUTATING_COMMAND_TRIGGERS)

    def execute(self, cmd: str, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Executes a remote shell command.
        Honors read-only and dry-run flags.
        """
        self.connect()
        is_mutating = self.is_mutating_command(cmd)

        if is_mutating:
            if self.read_only:
                raise ReadOnlyViolationError(
                    f"Command '{cmd[:60]}...' rejected in READ-ONLY mode. Disable read_only to execute."
                )
            if self.dry_run:
                return (0, f"[DRY-RUN] Command skipped: {cmd}\n", "")

        t = timeout or self.timeout
        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=t)
        
        # Read results
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        return exit_code, out, err

    def read_remote_file(self, path: str) -> Optional[str]:
        """Safely reads content of a remote file, returns None if not found."""
        try:
            with self.sftp.file(path, "r") as f:
                return f.read().decode("utf-8", errors="replace")
        except IOError:
            return None

    def write_remote_file_atomic(self, path: str, content: str, mode: int = 0o644) -> bool:
        """
        Atomically writes file on remote system:
        Uploads to temporary file first, then moves atomically to target path.
        """
        if self.read_only:
            raise ReadOnlyViolationError(f"Cannot write file '{path}' in READ-ONLY mode.")

        if self.dry_run:
            return True

        tmp_path = f"{path}.tmp.{int(time.time())}"
        try:
            with self.sftp.file(tmp_path, "w") as f:
                f.write(content.encode("utf-8"))
            self.sftp.chmod(tmp_path, mode)
            
            # Atomic mv via shell
            exit_code, _, err = self.execute(f"mv '{tmp_path}' '{path}'")
            if exit_code != 0:
                raise SSHExecutionError(f"Atomic mv failed: {err}")
            return True
        except Exception as e:
            # Clean up tmp if failed
            try:
                self.sftp.remove(tmp_path)
            except Exception:
                pass
            raise SSHExecutionError(f"Failed to atomically write remote file {path}: {e}")

    def remote_file_exists(self, path: str) -> bool:
        """Checks if remote file exists."""
        try:
            self.sftp.stat(path)
            return True
        except IOError:
            return False

    def test_port_local(self, port: int, proto: str = "tcp", timeout: float = 2.0) -> bool:
        """Tests if port is open from current client machine directly to host."""
        if proto.lower() == "tcp":
            try:
                with socket.create_connection((self.host, port), timeout=timeout):
                    return True
            except (socket.timeout, ConnectionRefusedError, OSError):
                return False
        return False
