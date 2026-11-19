"""
VPN Engineer - Unified Command Line Interface
"""

import sys
import json
import click
from vpn_engineer.core.banner import print_banner
from vpn_engineer.core.ssh_client import RemoteSSHClient
from vpn_engineer.core.ip_checker import IPDiagnosticEngine
from vpn_engineer.core.auditor import ServerAuditor
from vpn_engineer.core.diagnostician import IntelligentDiagnostician
from vpn_engineer.core.backup_manager import BackupManager
from vpn_engineer.knowledge.battle_log import FIELD_LESSONS, find_lessons_by_keyword, get_lesson_by_id
from vpn_engineer.knowledge.rulesets import get_v2rayn_rules_json
from vpn_engineer.protocols.cloudflare import CloudflareRescueManager

@click.group()
@click.option("--no-banner", is_flag=True, help="Suppress ASCII banner.")
def cli(no_banner):
    """VPN Engineer - Autonomous AI Agent & Engineering Toolkit for Anti-Censorship VPNs."""
    if not no_banner:
        print_banner(sys.stderr)

@cli.command("version")
def cmd_version():
    """Display version and attribution."""
    click.echo("VPN Engineer v1.0.0")
    click.echo("Author: https://github.com/zzakhar")
    click.echo("License: MIT")

@cli.command("ruleset")
@click.option("--format", "fmt", default="v2rayn", type=click.Choice(["v2rayn", "xray"]), help="Output format.")
def cmd_ruleset(fmt):
    """Output clean, battle-tested client routing ruleset (bypasses RU, proxies AI/foreign)."""
    click.echo(get_v2rayn_rules_json(indent=2))

@cli.command("cloudflare")
@click.option("--uuid", required=True, help="VLESS client UUID.")
@click.option("--domain", required=True, help="Cloudflare proxied domain.")
@click.option("--vps-ip", required=True, help="Real VPS IP address.")
@click.option("--path", default="/freedom-ws", help="WebSocket path.")
def cmd_cloudflare(uuid, domain, vps_ip, path):
    """Generate Cloudflare CDN fronting links with Clean IPs and setup guide."""
    guide = CloudflareRescueManager.get_setup_guide(domain=domain, vps_ip=vps_ip)
    click.echo("=== Cloudflare CDN Anti-Block Rescue Guide ===")
    for step in guide["steps"]:
        click.echo(f"\nStep {step['step']}: {step['action']}")
        click.echo(f"  {step['detail']}")

    click.echo("\n=== Verified Clean Cloudflare IP Links ===")
    links = CloudflareRescueManager.generate_cloudflare_rescue_links(uuid=uuid, domain=domain, ws_path=path)
    for l in links:
        click.echo(f"\n[{l['label']}] (IP: {l['clean_ip']})")
        click.echo(f"  {l['uri']}")

@cli.command("case")
@click.argument("query", required=False)
def cmd_case(query):
    """Query real-world field lessons and solutions from the battle log."""
    if not query:
        click.echo("=== Field Intelligence Battle Log ===")
        for c in FIELD_LESSONS:
            click.echo(f"[{c['id']}] {c['title']} (Severity: {c['severity']})")
        return

    # Check by ID or keyword
    lesson = get_lesson_by_id(query.upper())
    if lesson:
        results = [lesson]
    else:
        results = find_lessons_by_keyword(query)

    if not results:
        click.echo(f"No cases found matching '{query}'.")
        return

    for c in results:
        click.echo(f"\n--- {c['id']}: {c['title']} ---")
        click.echo(f"Severity: {c['severity']}")
        click.echo("Symptoms:")
        for s in c["symptoms"]:
            click.echo(f"  • {s}")
        click.echo(f"Root Cause: {c['root_cause']}")
        click.echo(f"Verified Solution:\n  {c['verified_solution']}\n")

@cli.command("audit")
@click.option("--host", required=True, help="Remote server IP or hostname.")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="SSH password.")
@click.option("--key", "key_file", default=None, help="Path to private SSH key.")
@click.option("--json", "as_json", is_flag=True, help="Output structured JSON.")
def cmd_audit(host, port, user, password, key_file, as_json):
    """Audit remote server OS, services, listening ports, firewall, and certificates."""
    ssh = RemoteSSHClient(host=host, port=port, username=user, password=password, key_filename=key_file, read_only=True)
    auditor = ServerAuditor(ssh)
    try:
        report = auditor.run_full_audit()
        if as_json:
            click.echo(json.dumps(report, indent=2))
        else:
            click.echo(f"=== Server Audit: {host} ===")
            click.echo(f"OS: {report['os']['distro']} ({report['os']['kernel'][:40]}...)")
            click.echo("\n--- Services ---")
            for s, info in report["services"].items():
                status_icon = "🟢" if info["is_running"] else "🔴"
                click.echo(f"  {status_icon} {s:16} state: {info['active_state']:12} enabled: {info['is_enabled']}")
            click.echo("\n--- Listening Ports ---")
            for sock in report["listening_ports"]:
                click.echo(f"  [{sock['proto'].upper():3}] Port {sock['port']:5} bound to {sock['address']:21} ({sock['process']})")
    finally:
        ssh.close()

@cli.command("doctor")
@click.option("--host", required=True, help="Remote server IP.")
@click.option("--domain", default=None, help="Configured domain name.")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="SSH password.")
@click.option("--key", "key_file", default=None, help="Path to private SSH key.")
@click.option("--json", "as_json", is_flag=True, help="Output structured JSON.")
def cmd_doctor(host, domain, port, user, password, key_file, as_json):
    """Run full 10-step intelligent diagnostic pipeline with ranked hypotheses."""
    ssh = RemoteSSHClient(host=host, port=port, username=user, password=password, key_filename=key_file, read_only=True)
    diagnostician = IntelligentDiagnostician(ssh, domain=domain)
    try:
        report = diagnostician.diagnose_all()
        if as_json:
            click.echo(json.dumps(report, indent=2))
        else:
            click.echo(f"=== VPN Doctor Diagnostics: {host} (Domain: {domain or 'None'}) ===")
            click.echo(f"Status: {report['status']}")
            click.echo("\n--- Ranked Hypotheses & Remediation ---")
            for i, h in enumerate(report["hypotheses"], 1):
                conf_pct = int(h["confidence"] * 100)
                click.echo(f"\n{i}. [{conf_pct}% Confidence] {h['title']}")
                click.echo("   Evidence:")
                for ev in h["evidence"]:
                    click.echo(f"     • {ev}")
                click.echo(f"   💡 Recommendation: {h['remediation']}")
    finally:
        ssh.close()

@cli.command("backup")
@click.option("--host", required=True, help="Remote server IP.")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="SSH password.")
@click.option("--key", "key_file", default=None, help="Path to private SSH key.")
@click.option("--reason", default="Manual CLI backup", help="Reason for snapshot.")
def cmd_backup(host, port, user, password, key_file, reason):
    """Create an atomic remote configuration snapshot."""
    ssh = RemoteSSHClient(host=host, port=port, username=user, password=password, key_filename=key_file, read_only=False)
    mgr = BackupManager(ssh)
    try:
        snapshot = mgr.create_snapshot(reason=reason)
        click.echo(f"✅ Snapshot created successfully! ID: {snapshot['snapshot_id']}")
        click.echo(f"Items backed up: {len(snapshot['items'])}")
    finally:
        ssh.close()

@cli.command("rollback")
@click.option("--host", required=True, help="Remote server IP.")
@click.option("--port", default=22, help="SSH port.")
@click.option("--user", default="root", help="SSH username.")
@click.option("--password", default=None, help="SSH password.")
@click.option("--key", "key_file", default=None, help="Path to private SSH key.")
@click.option("--snapshot-id", default=None, help="Snapshot ID to restore (defaults to latest).")
def cmd_rollback(host, port, user, password, key_file, snapshot_id):
    """Safely restore remote configurations from a snapshot."""
    ssh = RemoteSSHClient(host=host, port=port, username=user, password=password, key_filename=key_file, read_only=False)
    mgr = BackupManager(ssh)
    try:
        res = mgr.rollback(snapshot_id=snapshot_id)
        click.echo(f"✅ Rollback successful! Restored snapshot: {res['restored_snapshot_id']}")
        for f in res["restored_files"]:
            click.echo(f"  • Restored: {f}")
    finally:
        ssh.close()

def main():
    cli()

if __name__ == "__main__":
    main()
