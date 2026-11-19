import pytest
from click.testing import CliRunner
from vpn_engineer.cli import cli

def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "VPN Engineer" in result.output
    assert "https://github.com/zzakhar" in result.output

def test_cli_ruleset():
    runner = CliRunner()
    result = runner.invoke(cli, ["ruleset"])
    assert result.exit_code == 0
    assert "geosite:category-ru" in result.output
    assert "geosite:google" in result.output

def test_cli_case_query():
    runner = CliRunner()
    result = runner.invoke(cli, ["case", "CASE-001"])
    assert result.exit_code == 0
    assert "CASE-001" in result.output
    assert "Port 443" in result.output
