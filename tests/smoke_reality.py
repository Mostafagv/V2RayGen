#!/usr/bin/env python3
"""
Smoke checks for VLESS TCP REALITY Vision support.

Manual CLI checks:
  sudo python3 V2RayGen.py --vless --tcp --reality --vision
  python3 V2RayGen.py --vmess --reality
  python3 V2RayGen.py --shadowsocks --reality
  python3 V2RayGen.py --vless --vision
  python3 V2RayGen.py --vless --reality --tls
  python3 V2RayGen.py --vless --reality --xtls
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "V2RayGen.py").read_text()


def assert_contains(value):
    if value not in SOURCE:
        raise AssertionError("{} not found".format(value))


def main():
    expected = [
        "--reality",
        "--vision",
        "--reality-dest",
        "--reality-server-name",
        "--reality-short-id",
        "vlesstcprealityvision",
        "xtls-rprx-vision",
        '"security": "reality"',
        '"realitySettings"',
        "xray\", \"x25519",
        "type=tcp&security=reality&pbk={}&fp=chrome&sni={}",
        "&flow=xtls-rprx-vision",
        "REALITY replaces normal TLS certificate handling",
    ]
    for value in expected:
        assert_contains(value)

    invalid_combo_checks = [
        "--reality is only supported with --vless",
        "--reality cannot be used with vmess, trojan, or shadowsocks",
        "--reality cannot be combined with --tls or --xtls",
        "--vision requires --reality",
    ]
    for value in invalid_combo_checks:
        assert_contains(value)

    print("REALITY smoke checks passed")


if __name__ == "__main__":
    main()
