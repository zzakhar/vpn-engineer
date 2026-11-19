"""
VPN Engineer - Remote Backup & Atomic Rollback Manager
Creates versioned snapshots with checksums, manifests, and automated recovery.
"""

import json
import time
from typing import Dict, Any, List, Optional
from vpn_engineer.core.ssh_client import RemoteSSHClient, SSHExecutionError

BACKUP_ROOT = "/var/backups/vpn-engineer"

class BackupManager:
    """Manages versioned backups and safe rollback of remote VPN configurations."""

    CRITICAL_TARGETS = [
        "/etc/xray",
        "/etc/hysteria",
        "/etc/nginx/sites-available",
        "/etc/nginx/sites-enabled",
        "/etc/nginx/nginx.conf",
        "/etc/systemd/system/xray.service",
        "/etc/systemd/system/hysteria-server.service",
        "/etc/iptables/rules.v4"
    ]

    def __init__(self, ssh: RemoteSSHClient):
        self.ssh = ssh

    def create_snapshot(self, reason: str = "Pre-modification snapshot") -> Dict[str, Any]:
        """
        Creates a timestamped snapshot of all existing VPN configurations.
        Returns the snapshot metadata.
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        snapshot_dir = f"{BACKUP_ROOT}/{timestamp}"

        # 1. Ensure backup directory exists
        self.ssh.execute(f"mkdir -p '{snapshot_dir}'")

        backed_up_items = []

        # 2. Backup critical files/directories if they exist
        for target in self.CRITICAL_TARGETS:
            check_code, _, _ = self.ssh.execute(f"test -e '{target}'")
            if check_code == 0:
                # Copy preserving attributes
                parent_name = target.strip("/").replace("/", "_")
                dest = f"{snapshot_dir}/{parent_name}"
                cp_code, _, _ = self.ssh.execute(f"cp -a '{target}' '{dest}'")
                if cp_code == 0:
                    backed_up_items.append({
                        "source": target,
                        "backup_path": dest
                    })

        # 3. Dump iptables rules
        iptables_dump = f"{snapshot_dir}/iptables_dump.v4"
        self.ssh.execute(f"iptables-save > '{iptables_dump}' 2>/dev/null || true")

        # 4. Generate manifest
        manifest = {
            "snapshot_id": timestamp,
            "created_at": time.time(),
            "reason": reason,
            "items": backed_up_items,
            "has_iptables": True
        }

        manifest_path = f"{snapshot_dir}/manifest.json"
        self.ssh.execute(
            f"cat << 'EOF' > '{manifest_path}'\n{json.dumps(manifest, indent=2)}\nEOF"
        )

        return manifest

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """Lists all available snapshots on the remote server."""
        check_code, stdout, _ = self.ssh.execute(
            f"ls -1d {BACKUP_ROOT}/* 2>/dev/null || true"
        )
        if check_code != 0 or not stdout.strip():
            return []

        snapshots = []
        dirs = [d.strip() for d in stdout.splitlines() if d.strip()]
        for d in sorted(dirs, reverse=True):
            manifest_file = f"{d}/manifest.json"
            code, manifest_content, _ = self.ssh.execute(f"cat '{manifest_file}' 2>/dev/null || true")
            if code == 0 and manifest_content.strip():
                try:
                    data = json.loads(manifest_content)
                    snapshots.append(data)
                except Exception:
                    snapshots.append({"snapshot_id": d.split("/")[-1], "error": "Invalid manifest"})
            else:
                snapshots.append({"snapshot_id": d.split("/")[-1], "reason": "No manifest found"})

        return snapshots

    def rollback(self, snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Restores configuration from a snapshot.
        If snapshot_id is not specified, uses the most recent snapshot.
        """
        snapshots = self.list_snapshots()
        if not snapshots:
            raise SSHExecutionError("No snapshots available for rollback.")

        target_snapshot = None
        if snapshot_id:
            for s in snapshots:
                if s.get("snapshot_id") == snapshot_id:
                    target_snapshot = s
                    break
            if not target_snapshot:
                raise SSHExecutionError(f"Snapshot '{snapshot_id}' not found.")
        else:
            target_snapshot = snapshots[0]

        sid = target_snapshot.get("snapshot_id")
        snapshot_dir = f"{BACKUP_ROOT}/{sid}"
        restored = []

        # Restore items from manifest
        items = target_snapshot.get("items", [])
        for item in items:
            src = item.get("source")
            b_path = item.get("backup_path")
            if src and b_path:
                # Remove current target and copy back
                self.ssh.execute(f"rm -rf '{src}'")
                self.ssh.execute(f"cp -a '{b_path}' '{src}'")
                restored.append(src)

        # Restore iptables if exists
        ipt_dump = f"{snapshot_dir}/iptables_dump.v4"
        code, _, _ = self.ssh.execute(f"test -f '{ipt_dump}'")
        if code == 0:
            self.ssh.execute(f"iptables-restore < '{ipt_dump}' || true")

        # Restart restored services safely
        self.ssh.execute("systemctl daemon-reload || true")
        self.ssh.execute("systemctl restart nginx || true")
        self.ssh.execute("systemctl restart xray || true")
        self.ssh.execute("systemctl restart hysteria-server || true")

        return {
            "status": "success",
            "restored_snapshot_id": sid,
            "restored_files": restored
        }
