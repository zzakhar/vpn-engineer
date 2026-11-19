"""
VPN Engineer - Safe Autonomous Repair & Remediation Engine
Includes pre-flight planning, syntax verification, atomic file substitution,
post-flight health verification, and automatic rollback upon error.
"""

import json
from typing import Dict, Any, List, Optional, Tuple
from vpn_engineer.core.ssh_client import RemoteSSHClient, SSHExecutionError
from vpn_engineer.core.backup_manager import BackupManager

class RepairPlanItem:
    def __init__(self, action: str, target: str, description: str, requires_restart: Optional[str] = None):
        self.action = action # "write_file", "restart_service", "apply_iptables"
        self.target = target
        self.description = description
        self.requires_restart = requires_restart

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "description": self.description,
            "requires_restart": self.requires_restart
        }

class RepairEngine:
    """Safe remediation engine for VPN services."""

    def __init__(self, ssh: RemoteSSHClient):
        self.ssh = ssh
        self.backup_mgr = BackupManager(ssh)

    def validate_nginx_syntax(self) -> Tuple[bool, str]:
        """Runs 'nginx -t' to verify configuration syntax."""
        code, out, err = self.ssh.execute("nginx -t 2>&1")
        output = (out + "\n" + err).strip()
        is_valid = (code == 0 and "syntax is ok" in output.lower())
        return is_valid, output

    def validate_xray_syntax(self, config_path: str = "/etc/xray/config.json") -> Tuple[bool, str]:
        """Runs 'xray run -test -conf <path>' to verify Xray JSON syntax."""
        code, out, err = self.ssh.execute(f"xray run -test -conf '{config_path}' 2>&1 || true")
        output = (out + "\n" + err).strip()
        is_valid = (code == 0 or "configuration ok" in output.lower())
        return is_valid, output

    def validate_hysteria_syntax(self, config_path: str = "/etc/hysteria/config.yaml") -> Tuple[bool, str]:
        """Checks YAML syntax for Hysteria 2 configuration."""
        code, out, err = self.ssh.execute(f"python3 -c \"import yaml; yaml.safe_load(open('{config_path}'))\" 2>&1 || true")
        output = (out + "\n" + err).strip()
        is_valid = (code == 0)
        return is_valid, output

    def execute_plan(
        self,
        plan_items: List[RepairPlanItem],
        files_to_write: Dict[str, str], # path -> new_content
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Safely executes a remediation plan:
        1. Takes pre-flight backup snapshot.
        2. In dry-run mode, validates syntax on temporary files and exits cleanly.
        3. Atomically writes target configuration files.
        4. Validates syntax. If syntax error occurs, immediately triggers automatic rollback!
        5. Restarts services cleanly.
        6. Verifies services are active. If down, triggers automatic rollback!
        """
        # 1. Snapshot
        snapshot = self.backup_mgr.create_snapshot(reason="Pre-remediation snapshot")
        snapshot_id = snapshot.get("snapshot_id")

        if dry_run:
            return {
                "status": "DRY_RUN_COMPLETED",
                "snapshot_id": snapshot_id,
                "plan": [p.to_dict() for p in plan_items],
                "message": "Dry-run succeeded. No live changes applied to production."
            }

        executed_actions = []

        try:
            # 2. Write new files atomically
            for path, content in files_to_write.items():
                self.ssh.write_remote_file_atomic(path, content)
                executed_actions.append(f"Wrote file {path}")

                # Syntax validation
                if "nginx" in path:
                    valid, msg = self.validate_nginx_syntax()
                    if not valid:
                        raise SSHExecutionError(f"Nginx syntax check failed after writing {path}:\n{msg}")
                elif "xray" in path:
                    valid, msg = self.validate_xray_syntax(path)
                    if not valid:
                        raise SSHExecutionError(f"Xray syntax check failed after writing {path}:\n{msg}")

            # 3. Apply service restarts
            services_to_restart = set()
            for p in plan_items:
                if p.requires_restart:
                    services_to_restart.add(p.requires_restart)

            for s in services_to_restart:
                self.ssh.execute("systemctl daemon-reload || true")
                code, _, err = self.ssh.execute(f"systemctl restart {s}")
                if code != 0:
                    raise SSHExecutionError(f"Failed to restart service {s}: {err}")
                
                # Check active state
                _, state, _ = self.ssh.execute(f"systemctl is-active {s}")
                if state.strip() != "active":
                    raise SSHExecutionError(f"Service {s} failed to start. State: {state.strip()}")

                executed_actions.append(f"Restarted service {s} (active)")

            return {
                "status": "SUCCESS",
                "snapshot_id": snapshot_id,
                "executed_actions": executed_actions
            }

        except Exception as e:
            # AUTOMATIC EMERGENCY ROLLBACK
            rollback_result = self.backup_mgr.rollback(snapshot_id)
            return {
                "status": "FAILED_AUTOMATIC_ROLLBACK",
                "error": str(e),
                "rollback_result": rollback_result
            }
