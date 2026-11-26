#!/usr/bin/env python3
"""
Offline checks for Discover.py (no xray, Telegram or internet needed).

  python3 tests/smoke_discover.py
"""

import asyncio
import base64
import contextlib
import http.server
import json
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ["V2RAYGEN_CONFIG_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, str(ROOT))

import Discover as d  # noqa: E402

REALITY = (
    "vless://11111111-2222-3333-4444-555555555555@45.67.89.10:443?type=tcp&security=reality"
    "&sni=www.cloudflare.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision#orig"
)
VMESS_JSON = {"add": "45.67.89.11", "port": "8443", "id": "uuid-vmess", "net": "ws",
              "tls": "tls", "host": "cdn.example.com", "path": "/ws", "sni": "cdn.example.com"}
VMESS = "vmess://" + base64.b64encode(json.dumps(VMESS_JSON).encode()).decode()
TROJAN = "trojan://pa%24%24@45.67.89.12:443?type=grpc&security=tls&sni=t.example.com&serviceName=svc#t"
SS = "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode().rstrip("=") + "@45.67.89.13:8388#ss"
SS_LEGACY = "ss://" + base64.b64encode(b"aes-256-gcm:secret@45.67.89.14:8388").decode()
IPV6 = "vless://uuid@[2606:4700::1]:443?security=none#v6"


def check_extract():
    text = "hello {} and {}\nnoise ss://".format(REALITY, TROJAN)
    assert d.extract_links(text) == [REALITY, TROJAN]
    sub = base64.b64encode("\n".join([REALITY, SS]).encode()).decode()
    assert d.extract_links(sub) == [REALITY, SS]
    assert d.extract_links("nothing here") == []


def check_extract_wrapped():
    # Telegram posts often wrap links in backticks, brackets or parentheses.
    bare = "vless://uuid@45.67.89.10:443?security=none"
    text = "`{0}` and ({0}) and [{0}]".format(bare)
    assert d.extract_links(text) == [bare, bare, bare]


def check_parse():
    n = d.parse_link(REALITY)
    assert (n["protocol"], n["host"], n["port"]) == ("vless", "45.67.89.10", 443)
    assert n["link"].startswith(REALITY.split("#")[0] + "#discovered-")
    assert n["key"] == "vless-45.67.89.10-443-11111111-2222-3333-4444-555555555555"

    v = d.parse_link(VMESS)
    assert (v["host"], v["port"], v["user_id"]) == ("45.67.89.11", 8443, "uuid-vmess")

    # A vmess link with junk after the padding is stored in clean canonical form.
    padded = json.dumps(VMESS_JSON)
    while not base64.b64encode(padded.encode()).decode().endswith("="):
        padded += " "
    dirty = d.parse_link("vmess://" + base64.b64encode(padded.encode()).decode() + "ss#whatever")
    assert dirty is not None and dirty["link"].startswith("vmess://") and "#" not in dirty["link"]
    clean = json.loads(base64.b64decode(dirty["link"][len("vmess://"):]))
    assert clean["add"] == "45.67.89.11" and clean["ps"].startswith("discovered-")
    assert d.parse_link(dirty["link"])["host"] == "45.67.89.11"

    assert d.parse_link(TROJAN)["user_id"] == "pa$$"
    for link, host in ((SS, "45.67.89.13"), (SS_LEGACY, "45.67.89.14")):
        s = d.parse_link(link)
        assert (s["host"], s["port"], s["user_id"], s["method"]) == (host, 8388, "secret", "aes-256-gcm")
    assert d.parse_link(IPV6)["host"] == "2606:4700::1"

    # Malformed and unsafe links are rejected.
    assert d.parse_link("vless://nohost") is None
    assert d.parse_link("vmess://!!!notbase64") is None
    assert d.parse_link("vless://uuid@127.0.0.1:443") is None
    assert d.parse_link("vless://uuid@192.168.1.5:443") is None
    assert d.parse_link("trojan://pw@localhost:443") is None
    assert d.parse_link("vless://uuid@45.67.89.10:99999") is None


def check_xray_config():
    cfg = d.build_xray_config(d.parse_link(REALITY), 10808)
    out = cfg["outbounds"][0]
    assert cfg["inbounds"][0]["listen"] == "127.0.0.1"
    assert out["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    reality = out["streamSettings"]["realitySettings"]
    assert out["streamSettings"]["security"] == "reality"
    assert reality["publicKey"] == "PUBKEY" and reality["shortId"] == "ab12"
    assert reality["serverName"] == "www.cloudflare.com"

    ws = d.build_xray_config(d.parse_link(VMESS), 1)["outbounds"][0]["streamSettings"]
    assert ws["network"] == "ws" and ws["security"] == "tls"
    assert ws["wsSettings"] == {"path": "/ws", "headers": {"Host": "cdn.example.com"}}
    assert "allowInsecure" not in ws["tlsSettings"]

    grpc = d.build_xray_config(d.parse_link(TROJAN), 1)["outbounds"][0]
    assert grpc["streamSettings"]["grpcSettings"]["serviceName"] == "svc"
    assert grpc["settings"]["servers"][0]["password"] == "pa$$"

    ss = d.build_xray_config(d.parse_link(SS), 1)["outbounds"][0]
    assert ss["protocol"] == "shadowsocks" and ss["settings"]["servers"][0]["method"] == "aes-256-gcm"

    # Transports we cannot test are skipped, not mangled; REALITY needs a public key.
    assert d.build_xray_config(d.parse_link(REALITY.replace("type=tcp", "type=xhttp")), 1) is None
    assert d.build_xray_config(d.parse_link(REALITY.replace("pbk=PUBKEY&", "")), 1) is None


async def local_tcp_and_mirror():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        assert await d.tcp_ok("127.0.0.1", port)
    assert not await d.tcp_ok("127.0.0.1", port)  # closed now

    body = "\n".join([REALITY, SS]).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    with contextlib.redirect_stderr(open(os.devnull, "w")):
        links = await d.collect_mirrors(["http://127.0.0.1:{}/".format(httpd.server_port), "http://127.0.0.1:1/x"])
    httpd.shutdown()
    assert links == [REALITY, SS]

    # Only http(s) mirrors are fetched.
    try:
        d.fetch_mirror("file:///etc/hosts")
        raise AssertionError("file:// mirror was accepted")
    except ValueError:
        pass

    # Many probes at once must not exhaust file descriptors (limit is 256 on macOS).
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    sem = asyncio.Semaphore(d.MAX_PROBES)
    async with server:
        results = await asyncio.gather(*[d.tcp_ok("127.0.0.1", port, sem) for _ in range(600)])
    assert all(results), "{} of 600 probes failed".format(results.count(False))


async def fake_xray_failure():
    # An xray that dies immediately: speed_test must report 0.0 and leave no temp config behind.
    fake = Path(os.environ["V2RAYGEN_CONFIG_DIR"]) / "fake_xray.sh"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    before = set(Path(tempfile.gettempdir()).glob("xray_test_*.json"))
    node = d.parse_link(REALITY)
    assert await d.speed_test(str(fake), node) == (0.0, None)
    assert set(Path(tempfile.gettempdir()).glob("xray_test_*.json")) == before
    # A node whose transport cannot be tested is skipped without launching anything.
    assert await d.speed_test(str(fake), d.parse_link(REALITY.replace("type=tcp", "type=xhttp"))) == (0.0, None)


def check_store_and_list():
    assert d.load_store() == {}
    d.save_store({
        "a": {"key": "a", "link": "vless://slow", "speed_kbps": 10},
        "b": {"key": "b", "link": "vless://fast", "speed_kbps": 500},
    })
    assert [n["link"] for n in d.ranked(d.load_store())] == ["vless://fast", "vless://slow"]
    assert oct(d.STORE_FILE.stat().st_mode & 0o777) == "0o600"


def check_stats_and_ranking():
    node = d.parse_link(REALITY)
    steady = d.new_entry(node, 100.0, 300)
    for speed in (110.0, 90.0, 100.0, 105.0):
        d.record_result(steady, speed, 300)
    assert d.stats(steady) == (5, 5)
    assert steady["speed_kbps"] == 100.0 and steady["ttfb_ms"] == 300

    flaky = d.new_entry(d.parse_link(VMESS), 150.0, 200)  # faster, but fails most tests
    for speed in (0.0, 0.0, 0.0, 140.0):
        d.record_result(flaky, speed, 200)
    assert d.stats(flaky) == (5, 2)
    assert d.reliability(steady) > d.reliability(flaky)
    assert flaky["speed_kbps"] == 145.0  # median of the two successes

    # A failed test counts as an attempt without touching the speed.
    before = steady["speed_kbps"]
    d.record_result(steady, 0.0, None)
    assert d.stats(steady) == (6, 5) and steady["speed_kbps"] == before

    # Entries stored before stats existed still rank and update cleanly.
    legacy = {"key": "k", "protocol": "ss", "host": "h", "port": 1, "link": "ss://x", "speed_kbps": 50.0}
    assert d.stats(legacy) == (1, 1)
    d.record_result(legacy, 70.0, 100)
    assert d.stats(legacy) == (2, 2) and legacy["speeds"] == [50.0, 70.0] and legacy["speed_kbps"] == 60.0

    store = {"steady": steady, "flaky": flaky}
    assert [n["key"] for n in d.ranked(store, "speed")] == [flaky["key"], steady["key"]]
    assert [n["key"] for n in d.ranked(store, "reliability")] == [steady["key"], flaky["key"]]
    assert [n["key"] for n in d.ranked(store, "score")] == [steady["key"], flaky["key"]]
    table = d.format_details(d.ranked(store))
    assert "rel" in table and "45.67.89.10:443" in table


def check_test_command():
    # With an xray that never works, every round fails and unreliable nodes are dropped.
    fake = Path(os.environ["V2RAYGEN_CONFIG_DIR"]) / "fake_xray.sh"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    keep = d.new_entry(d.parse_link(REALITY), 100.0, 300)
    d.save_store({keep["key"]: keep, "junk": {"key": "junk", "link": "not-a-link"}})
    quiet = open(os.devnull, "w")
    with contextlib.redirect_stderr(quiet), contextlib.redirect_stdout(quiet):
        d.main(["test", "--rounds", "1", "--xray", str(fake)])
        stored = d.load_store()
        assert list(stored) == [keep["key"]]  # unreadable entry removed; 1 pass in 2 tests is kept
        assert d.stats(stored[keep["key"]]) == (2, 1)
        d.main(["test", "--rounds", "1", "--xray", str(fake)])
    assert d.load_store() == {}  # 1 pass in 3 tests (33%) is below the keep threshold


def check_cli_errors():
    with contextlib.redirect_stderr(open(os.devnull, "w")):
        for argv in (["scan"], ["scan", "--mirror", "http://x", "--xray", "/nonexistent"]):
            try:
                d.main(argv)
            except SystemExit as exc:
                assert exc.code == 1


if __name__ == "__main__":
    check_extract()
    check_extract_wrapped()
    check_parse()
    check_xray_config()
    asyncio.run(local_tcp_and_mirror())
    asyncio.run(fake_xray_failure())
    check_stats_and_ranking()
    check_store_and_list()
    check_test_command()
    check_cli_errors()
    print("Discover smoke tests passed")
