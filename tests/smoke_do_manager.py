#!/usr/bin/env python3
"""
Offline checks for DOManager.py (no DigitalOcean account or network needed).

  python3 tests/smoke_do_manager.py
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = tempfile.mkdtemp()
os.environ["V2RAYGEN_CONFIG_DIR"] = TMP
os.environ.pop("DIGITALOCEAN_TOKEN", None)
sys.path.insert(0, str(ROOT))

import DOManager as dm  # noqa: E402


def check_user_data():
    plain = dm.build_user_data()
    assert plain.startswith("#!/bin/bash\n")
    assert "cd /root" in plain
    assert "tcp_congestion_control=bbr" in plain
    assert "python3 - --vless --tcp --reality --vision" in plain
    assert "--sni" not in plain

    sni = dm.build_user_data(sni="www.cloudflare.com")
    assert "--sni www.cloudflare.com --reality-dest www.cloudflare.com:443" in sni

    quoted = dm.build_user_data(sni="a.com; rm -rf /")
    assert "'a.com; rm -rf /'" in quoted

    # The generated script must be valid bash.
    subprocess.run(["bash", "-n"], input=sni, text=True, check=True)


def check_parse_links():
    text = (
        "[2026-11-21 10:00:00 +0000] vless xray: vless://uuid@1.2.3.4:443?security=reality#xray\n"
        "garbage line\n"
        "[2026-11-21 11:00:00 +0000] vless xray: vless://uuid2@1.2.3.4:443?x=y#n\n"
    )
    links = dm.parse_links(text)
    assert links == [
        "vless://uuid@1.2.3.4:443?security=reality#xray",
        "vless://uuid2@1.2.3.4:443?x=y#n",
    ], links
    assert dm.parse_links("") == []


def check_env_file():
    values = dm.parse_env_file(
        "# comment\nexport DIGITALOCEAN_TOKEN='abc'\nDO_DEFAULT_REGION = fra1\n\nnot a pair\n"
    )
    assert values == {"DIGITALOCEAN_TOKEN": "abc", "DO_DEFAULT_REGION": "fra1"}, values


def check_permission_guard():
    dm.CONFIG_FILE.write_text("DIGITALOCEAN_TOKEN=x\n")
    os.chmod(dm.CONFIG_FILE, 0o644)
    try:
        dm.load_config()
    except SystemExit:
        pass
    else:
        raise AssertionError("world-readable do.env was accepted")
    os.chmod(dm.CONFIG_FILE, 0o600)
    assert dm.load_config()["DIGITALOCEAN_TOKEN"] == "x"
    dm.CONFIG_FILE.unlink()


def check_public_ip():
    droplet = {"networks": {"v4": [
        {"type": "private", "ip_address": "10.0.0.2"},
        {"type": "public", "ip_address": "203.0.113.5"},
    ]}}
    assert dm.public_ipv4(droplet) == "203.0.113.5"
    assert dm.public_ipv4({"networks": {"v4": []}}) is None


def main():
    check_user_data()
    check_parse_links()
    check_env_file()
    check_permission_guard()
    check_public_ip()
    print("DOManager smoke checks passed")


if __name__ == "__main__":
    main()
