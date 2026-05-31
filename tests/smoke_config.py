#!/usr/bin/env python3
"""
Validate and smoke-test Xray client configs.

Examples:
  python3 tests/smoke_config.py --link 'vless://...' --syntax-only
  python3 tests/smoke_config.py --link 'vless://...' --live --download-xray
  python3 tests/smoke_config.py --config client.json --live --xray /path/to/xray
"""

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import urlopen


DEFAULT_TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"
DEFAULT_SOCKS_PORT = 10808
XRAY_RELEASE_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"


class SmokeError(Exception):
    pass


def load_json_url(url, timeout):
    with urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def download_file(url, path, timeout):
    with urlopen(url, timeout=timeout) as response:
        path.write_bytes(response.read())


def xray_asset_name():
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        os_name = "macos"
    elif system == "linux":
        os_name = "linux"
    elif system == "windows":
        os_name = "windows"
    else:
        raise SmokeError("unsupported OS for auto-download: {}".format(platform.system()))

    if machine in ("x86_64", "amd64"):
        arch = "64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64-v8a"
    else:
        raise SmokeError("unsupported architecture for auto-download: {}".format(platform.machine()))

    return "Xray-{}-{}.zip".format(os_name, arch)


def parse_digest(dgst_text):
    for line in dgst_text.splitlines():
        if line.startswith("SHA2-256="):
            return line.split("=", 1)[1].strip().lower()
    raise SmokeError("release digest did not include SHA2-256")


def ensure_xray(download_dir, timeout):
    found = shutil.which("xray")
    if found:
        return Path(found)

    download_dir.mkdir(parents=True, exist_ok=True)
    asset = xray_asset_name()
    release = load_json_url(XRAY_RELEASE_API, timeout)
    by_name = {item["name"]: item for item in release.get("assets", [])}
    if asset not in by_name or asset + ".dgst" not in by_name:
        raise SmokeError("latest Xray release does not include {}".format(asset))

    zip_path = download_dir / asset
    digest_path = download_dir / (asset + ".dgst")
    extract_dir = download_dir / asset.replace(".zip", "")
    xray_path = extract_dir / ("xray.exe" if platform.system().lower() == "windows" else "xray")

    if not zip_path.exists():
        download_file(by_name[asset]["browser_download_url"], zip_path, timeout)
    if not digest_path.exists():
        download_file(by_name[asset + ".dgst"]["browser_download_url"], digest_path, timeout)

    expected = parse_digest(digest_path.read_text())
    actual = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    if actual != expected:
        raise SmokeError("downloaded Xray SHA256 mismatch: expected {}, got {}".format(expected, actual))

    if not xray_path.exists():
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)
        if platform.system().lower() != "windows":
            xray_path.chmod(xray_path.stat().st_mode | 0o111)

    return xray_path


def require_single(values, name):
    if name not in values or not values[name]:
        raise SmokeError("missing required VLESS query parameter: {}".format(name))
    return values[name][0]


def parse_vless_link(link):
    parsed = urlparse(link)
    if parsed.scheme != "vless":
        raise SmokeError("only vless:// links are supported by --link")
    if not parsed.username:
        raise SmokeError("VLESS link is missing UUID")
    if not parsed.hostname:
        raise SmokeError("VLESS link is missing host")
    if parsed.port is None:
        raise SmokeError("VLESS link is missing port")

    try:
        uuid.UUID(parsed.username)
    except ValueError as exc:
        raise SmokeError("invalid VLESS UUID: {}".format(parsed.username)) from exc

    query = parse_qs(parsed.query)
    network = require_single(query, "type")
    security = require_single(query, "security")
    encryption = query.get("encryption", ["none"])[0]

    if encryption != "none":
        raise SmokeError("VLESS encryption must be none, got {}".format(encryption))
    if network not in ("tcp", "ws", "grpc", "xhttp", "httpupgrade", "splithttp"):
        raise SmokeError("unsupported VLESS network: {}".format(network))

    stream = {
        "network": network,
        "security": security,
    }

    if security == "reality":
        if network != "tcp":
            raise SmokeError("REALITY smoke test currently expects type=tcp")
        short_id = query.get("sid", [""])[0]
        if short_id and not re.fullmatch(r"[0-9a-fA-F]*", short_id):
            raise SmokeError("REALITY short ID must be hex")
        if len(short_id) % 2 != 0:
            raise SmokeError("REALITY short ID must have even length")
        if len(short_id) > 16:
            raise SmokeError("REALITY short ID must be at most 16 hex characters")

        stream["realitySettings"] = {
            "serverName": require_single(query, "sni"),
            "fingerprint": query.get("fp", ["chrome"])[0],
            "publicKey": require_single(query, "pbk"),
            "shortId": short_id,
            "spiderX": unquote(query.get("spx", ["/"])[0]),
        }
    elif security == "tls":
        stream["tlsSettings"] = {
            "serverName": query.get("sni", [parsed.hostname])[0],
            "allowInsecure": query.get("allowInsecure", ["0"])[0] in ("1", "true", "True"),
        }
    elif security not in ("none", ""):
        raise SmokeError("unsupported VLESS security: {}".format(security))

    user = {
        "id": parsed.username,
        "encryption": "none",
    }
    flow = query.get("flow", [""])[0]
    if flow:
        user["flow"] = flow

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": stream,
    }
    return outbound


def config_from_outbound(outbound, socks_port, loglevel):
    return {
        "log": {"loglevel": loglevel},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        ],
        "outbounds": [outbound],
    }


def load_config(path):
    try:
        return json.loads(Path(path).read_text())
    except json.JSONDecodeError as exc:
        raise SmokeError("invalid JSON config: {}".format(exc)) from exc


def validate_xray_config_shape(config):
    if not isinstance(config, dict):
        raise SmokeError("config must be a JSON object")
    if not config.get("outbounds"):
        raise SmokeError("config is missing outbounds")
    if not isinstance(config["outbounds"], list):
        raise SmokeError("outbounds must be a list")


def wait_for_port(port, process, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise SmokeError("xray exited before opening SOCKS port")
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise SmokeError("timed out waiting for SOCKS port {}".format(port))


def find_free_port(preferred):
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex(("127.0.0.1", preferred)) != 0:
            return preferred
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_curl_through_socks(port, test_url, timeout):
    curl = shutil.which("curl")
    if not curl:
        raise SmokeError("curl is required for --live")
    cmd = [
        curl,
        "-L",
        "--socks5-hostname",
        "127.0.0.1:{}".format(port),
        "--max-time",
        str(timeout),
        test_url,
    ]
    result = subprocess.run(cmd, text=True, capture_output=True)
    if result.returncode != 0:
        raise SmokeError("curl through proxy failed: {}".format(result.stderr.strip() or result.stdout.strip()))
    return result.stdout


def run_xray_config_test(xray, config):
    with tempfile.TemporaryDirectory(prefix="xray-config-test-") as tmp:
        config_path = Path(tmp) / "client.json"
        config_path.write_text(json.dumps(config, indent=2))
        cmd = [str(xray), "run", "-test", "-config", str(config_path)]
        result = subprocess.run(cmd, text=True, capture_output=True)
    if result.returncode != 0:
        output = (result.stderr or result.stdout).strip()
        raise SmokeError("xray config test failed: {}".format(output))


def run_live_smoke(xray, config, socks_port, test_url, timeout):
    with tempfile.TemporaryDirectory(prefix="xray-smoke-") as tmp:
        config_path = Path(tmp) / "client.json"
        config_path.write_text(json.dumps(config, indent=2))
        cmd = [str(xray), "run", "-config", str(config_path)]
        process = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            wait_for_port(socks_port, process, timeout)
            body = run_curl_through_socks(socks_port, test_url, timeout)
            return body
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def summarize_trace(body):
    details = {}
    for line in body.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            details[key] = value
    if not details:
        return None
    keys = ["ip", "loc", "tls", "http", "colo", "warp"]
    return ", ".join("{}={}".format(key, details[key]) for key in keys if key in details)


def main():
    parser = argparse.ArgumentParser(description="Smoke-test Xray client configs and VLESS share links.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--link", help="VLESS share URL to validate and test")
    source.add_argument("--config", help="Existing Xray client JSON config to test")
    parser.add_argument("--syntax-only", action="store_true", help="Only parse and validate local config shape")
    parser.add_argument("--live", action="store_true", help="Run Xray and test a request through its SOCKS inbound")
    parser.add_argument("--xray", help="Path to xray binary. Defaults to PATH, or auto-download with --download-xray")
    parser.add_argument("--download-xray", action="store_true", help="Download official Xray-core when xray is not installed")
    parser.add_argument("--download-dir", default="/private/tmp/xray-smoke", help="Directory for downloaded Xray artifacts")
    parser.add_argument("--test-url", default=DEFAULT_TEST_URL, help="URL to request through the proxy")
    parser.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT, help="Local SOCKS port for generated link configs")
    parser.add_argument("--timeout", type=int, default=20, help="Network timeout in seconds")
    parser.add_argument("--loglevel", default="warning", help="Xray log level for generated link configs")
    args = parser.parse_args()

    if not args.syntax_only and not args.live:
        args.syntax_only = True

    try:
        if args.link:
            outbound = parse_vless_link(args.link)
            socks_port = find_free_port(args.socks_port) if args.live else args.socks_port
            config = config_from_outbound(outbound, socks_port, args.loglevel)
        else:
            config = load_config(args.config)
            socks_port = args.socks_port

        validate_xray_config_shape(config)
        print("syntax: OK")

        xray = None
        if args.xray:
            xray = Path(args.xray)
        elif args.download_xray:
            xray = ensure_xray(Path(args.download_dir), args.timeout)
        elif args.live:
            found = shutil.which("xray")
            if not found:
                raise SmokeError("xray not found; pass --xray or --download-xray")
            xray = Path(found)

        if xray is not None:
            run_xray_config_test(xray, config)
            print("xray-config: OK")

        if args.syntax_only and not args.live:
            return 0

        body = run_live_smoke(xray, config, socks_port, args.test_url, args.timeout)
        print("live: OK")
        trace = summarize_trace(body)
        if trace:
            print("trace: {}".format(trace))
        return 0
    except (SmokeError, OSError, URLError, subprocess.SubprocessError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
