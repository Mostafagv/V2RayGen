#!/usr/bin/env python3
"""
Discover - find working proxy links (vless, vmess, trojan, ss) from public sources.

Runs on your own computer. Uses only the Python standard library, plus the
system `curl` and an `xray` binary for the speed test. Telegram channels need
the optional `telethon` package (pip install telethon).

Pipeline (ported from https://github.com/sinachaichi/scanner with the original
author's permission):

  collect -> parse -> TCP probe -> xray speed test -> store (ranked by speed)

Commands:
  scan  [--mirror URL] [--channel NAME] ...   collect, test and store working links
  test  [--rounds N] [--interval SECONDS]     re-test stored links; tracks reliability over time
  list  [--sort score|speed|reliability]      print stored links, best first
        [--details] [--count N] [--output FILE]

Speed and reliability are measured from the machine you run this on. To rank
nodes for Iran, run scan/test on a computer inside Iran (a server abroad only
shows how the nodes look from abroad). Run `test` several times, spaced out, for
a meaningful reliability figure.

Sources can also come from ~/.config/v2raygen/mirrors.txt and channels.txt
(one URL / channel name per line). Telegram credentials (TELEGRAM_API_ID,
TELEGRAM_API_HASH) are read from the environment or ~/.config/v2raygen/discover.env
(which must be chmod 600). Results are stored in ~/.config/v2raygen/discovered.json.

Discovered nodes are run by third parties: traffic you send through them can be
read by their operators. Use them for testing, not for anything sensitive.
"""

import argparse
import asyncio
import base64
import ipaddress
import json
import os
import random
import re
import shutil
import signal
import socket
import stat
import statistics
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit
from urllib.request import Request, urlopen

CONFIG_DIR = Path(os.environ.get("V2RAYGEN_CONFIG_DIR", Path.home() / ".config" / "v2raygen"))
ENV_FILE = CONFIG_DIR / "discover.env"
MIRRORS_FILE = CONFIG_DIR / "mirrors.txt"
CHANNELS_FILE = CONFIG_DIR / "channels.txt"
STORE_FILE = CONFIG_DIR / "discovered.json"

PROTOCOLS = ("vless", "vmess", "trojan", "ss")
LINK_RE = re.compile(r"\b(?:vless|vmess|trojan|ss)://[^\s\"'<>`)\]]+")

TCP_TIMEOUT = 2.0
TCP_MAX_MS = 1050
SPEED_BYTES = 100 * 1024
# Cloudflare's speed endpoint is edge-cached and rarely filtered by country.
SPEED_URL = "https://speed.cloudflare.com/__down?bytes={}".format(SPEED_BYTES)
SPEED_TIMEOUT = 12
MAX_FETCH_BYTES = 5 * 1024 * 1024
# macOS allows only 256 open files by default; stay well under it.
MAX_PROBES = 100
KEEP_SPEEDS = 10  # recent successful speeds kept per node


def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(1)


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ------------------------------------------------------------------ config ---


def parse_env_file(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        values[key] = value.strip().strip("'\"")
    return values


def load_config():
    config = {}
    if ENV_FILE.exists():
        if ENV_FILE.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            die("{} is readable by other users. Run: chmod 600 {}".format(ENV_FILE, ENV_FILE))
        config.update(parse_env_file(ENV_FILE.read_text()))
    for key in ("TELEGRAM_API_ID", "TELEGRAM_API_HASH"):
        if os.environ.get(key):
            config[key] = os.environ[key]
    return config


def ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)


def read_lines(path):
    if not path or not Path(path).exists():
        return []
    out = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


# ------------------------------------------------------------------ parsing ---


def b64decode(text):
    text = text.strip()
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except ValueError:
        return base64.b64decode(text + pad)


def extract_links(text):
    """Return every proxy link found in arbitrary text (incl. a base64 subscription body)."""
    links = LINK_RE.findall(text)
    if not links:
        # Many subscription URLs return the whole list base64-encoded.
        try:
            decoded = b64decode("".join(text.split())).decode("utf-8", "replace")
        except (ValueError, UnicodeDecodeError):
            return []
        links = LINK_RE.findall(decoded)
    return [link.strip() for link in links]


def host_is_public(host):
    """Reject loopback/private/link-local targets so hostile links cannot probe your LAN."""
    if not host or host.lower() in ("localhost", "localhost.localdomain"):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # a domain name; resolved at connect time
    return ip.is_global


def parse_link(raw):
    """Parse a proxy link into a dict, or None if it is malformed or unsafe."""
    proto = raw.split("://", 1)[0].lower()
    if proto not in PROTOCOLS:
        return None
    try:
        if proto == "vmess":
            payload = re.match(r"[A-Za-z0-9+/_-]+={0,2}", raw.split("://", 1)[1])  # drop junk after the padding
            if payload is None:
                return None
            data = json.loads(b64decode(payload.group(0)))
            host, port = str(data["add"]), int(data["port"])
            node = {"user_id": data.get("id"), "method": None, "params": data}
        elif proto == "ss":
            node = parse_ss(raw)
            host, port = node.pop("host"), node.pop("port")
        else:
            parts = urlsplit(raw)
            host, port = parts.hostname, parts.port
            node = {
                "user_id": unquote(parts.username) if parts.username else None,
                "method": None,
                "params": dict(parse_qsl(parts.query)),
            }
    except (ValueError, KeyError, IndexError, TypeError, UnicodeDecodeError):
        return None
    if not host or not port or not 0 < port < 65536 or not node.get("user_id"):
        return None
    if not host_is_public(host):
        return None
    node.update(protocol=proto, host=host, port=port)
    remark = "discovered-{}".format(random.randint(1000, 9999))
    if proto == "vmess":
        # Re-encode from the decoded JSON so junk after the base64 padding cannot leak into the stored link.
        data = dict(node["params"], ps=remark)
        node["link"] = "vmess://" + base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()
    else:
        node["link"] = raw.split("#", 1)[0] + "#" + remark
    node["key"] = "{}-{}-{}-{}".format(proto, host, port, node["user_id"])
    return node


def parse_ss(raw):
    """ss://base64(method:pass)@host:port or the legacy ss://base64(method:pass@host:port)."""
    body = raw.split("://", 1)[1].split("#")[0].split("?")[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        creds = unquote(userinfo)
        if ":" not in creds:
            creds = b64decode(creds).decode()
    else:
        creds, hostport = b64decode(body).decode().rsplit("@", 1)
    method, password = creds.split(":", 1)
    host, port = hostport.rsplit(":", 1)
    return {"user_id": password, "method": method, "host": host.strip("[]"), "port": int(port), "params": {}}


# ------------------------------------------------------------------ sources ---


def fetch_mirror(url):
    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("only http(s) mirrors are supported")
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=10) as resp:
        return resp.read(MAX_FETCH_BYTES).decode("utf-8", "replace")


async def collect_mirrors(urls):
    async def one(url):
        try:
            links = extract_links(await asyncio.to_thread(fetch_mirror, url))
            log("mirror {}: {} links".format(url, len(links)))
            return links
        except (OSError, ValueError) as exc:
            log("mirror {} failed: {}".format(url, exc))
            return []

    return [link for links in await asyncio.gather(*[one(u) for u in urls]) for link in links]


async def collect_telegram(channels, config):
    try:
        from telethon import TelegramClient
    except ImportError:
        log("Telegram channels skipped: pip install telethon")
        return []
    api_id, api_hash = config.get("TELEGRAM_API_ID"), config.get("TELEGRAM_API_HASH")
    if not (api_id and api_hash):
        log("Telegram channels skipped: set TELEGRAM_API_ID and TELEGRAM_API_HASH (see my.telegram.org)")
        return []

    import datetime

    today = datetime.date.today()
    recent = {today, today - datetime.timedelta(days=1)}
    session = str(CONFIG_DIR / "telegram_session")
    found = []
    async with TelegramClient(session, int(api_id), api_hash) as client:
        for name in channels:
            try:
                entity = await client.get_entity(name)
            except Exception as exc:  # telethon raises many unrelated error types
                log("channel {} unavailable: {}".format(name, exc))
                continue
            count = 0
            async for message in client.iter_messages(entity, limit=500):
                if message.date.date() in recent and message.text:
                    links = extract_links(message.text)
                    count += len(links)
                    found.extend(links)
            log("channel {}: {} links".format(name, count))
    if os.path.exists(session + ".session"):
        os.chmod(session + ".session", 0o600)
    return found


# ------------------------------------------------------------------- probes ---


async def tcp_ping(host, port):
    """Round-trip time in ms, or -1 on failure."""
    try:
        start = time.monotonic()
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
        elapsed = time.monotonic() - start
        writer.close()
        await writer.wait_closed()
        return max(1, int(elapsed * 1000))  # 0 would read as failure for sub-millisecond connects
    except (OSError, asyncio.TimeoutError):
        return -1


async def tcp_ok(host, port, sem=None):
    """True if the port answers fast enough. `sem` bounds how many sockets are open at once."""
    if sem is None:
        return 0 < await tcp_ping(host, port) < TCP_MAX_MS
    async with sem:
        return 0 < await tcp_ping(host, port) < TCP_MAX_MS


def build_stream(node):
    """xray streamSettings for a parsed node, or None if its transport is unsupported."""
    p = node["params"]
    if node["protocol"] == "vmess":
        network = p.get("net") or "tcp"
        security = "tls" if p.get("tls") == "tls" else "none"
        sni, host, path = p.get("sni") or p.get("host"), p.get("host"), p.get("path") or "/"
        service, fp, alpn = p.get("path", ""), p.get("fp"), p.get("alpn")
        pbk = sid = spx = None
    else:
        network = p.get("type") or "tcp"
        security = p.get("security") or "none"
        sni, host, path = p.get("sni"), p.get("host"), p.get("path") or "/"
        service, fp, alpn = p.get("serviceName", ""), p.get("fp"), p.get("alpn")
        pbk, sid, spx = p.get("pbk"), p.get("sid"), p.get("spx")

    if network not in ("tcp", "ws", "grpc") or security not in ("none", "tls", "reality"):
        return None
    stream = {"network": network}
    if security == "tls":
        tls = {"serverName": sni or host or node["host"]}
        if fp:
            tls["fingerprint"] = fp
        if alpn:
            tls["alpn"] = alpn.split(",")
        stream.update(security="tls", tlsSettings=tls)
    elif security == "reality":
        if not pbk:
            return None
        stream.update(security="reality", realitySettings={
            "serverName": sni or node["host"], "fingerprint": fp or "chrome",
            "publicKey": pbk, "shortId": sid or "", "spiderX": spx or "",
        })
    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host or node["host"]}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": service, "multiMode": False}
    return stream


def build_outbound(node, stream):
    proto, host, port, uid = node["protocol"], node["host"], node["port"], node["user_id"]
    p = node["params"]
    if proto == "vless":
        user = {"id": uid, "encryption": p.get("encryption", "none")}
        if p.get("flow"):
            user["flow"] = p["flow"]
        settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    elif proto == "vmess":
        settings = {"vnext": [{"address": host, "port": port, "users": [{"id": uid, "security": "auto"}]}]}
    elif proto == "trojan":
        settings = {"servers": [{"address": host, "port": port, "password": uid}]}
    else:
        proto = "shadowsocks"
        settings = {"servers": [{"address": host, "port": port, "password": uid, "method": node["method"]}]}
    return {"protocol": proto, "settings": settings, "streamSettings": stream}


def build_xray_config(node, socks_port):
    stream = build_stream(node)
    if stream is None:
        return None
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"port": socks_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [build_outbound(node, stream)],
    }


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def wait_for_port(port, timeout=4.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=0.2)
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.1)
    return False


async def speed_test(xray, node):
    """Download 100 KB through the node via xray.

    Returns (KB/s, ms until the first byte arrived), or (0.0, None) if the test failed.
    """
    failed = (0.0, None)
    socks_port = free_port()
    config = build_xray_config(node, socks_port)
    if config is None:
        return failed
    fd, path = tempfile.mkstemp(suffix=".json", prefix="xray_test_")
    proc = None
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f)
        proc = await asyncio.create_subprocess_exec(
            xray, "run", "-c", path,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
        if not await wait_for_port(socks_port):
            return failed
        curl = await asyncio.create_subprocess_exec(
            "curl", "-s", "--socks5-hostname", "127.0.0.1:{}".format(socks_port),
            "-o", os.devnull, "-m", str(SPEED_TIMEOUT), "--connect-timeout", "5",
            "-w", "%{size_download} %{speed_download} %{time_starttransfer}", SPEED_URL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(curl.communicate(), timeout=SPEED_TIMEOUT + 5)
        if curl.returncode != 0:
            return failed
        size, speed, ttfb = out.decode().split()
        if int(size) < SPEED_BYTES:
            return failed
        return round(float(speed) / 1024, 2), int(float(ttfb) * 1000)
    except (OSError, ValueError, asyncio.TimeoutError):
        return failed
    finally:
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                await proc.wait()
            except OSError:
                pass
        try:
            os.unlink(path)
        except OSError:
            pass


# -------------------------------------------------------------------- store ---


def load_store():
    if not STORE_FILE.exists():
        return {}
    try:
        return json.loads(STORE_FILE.read_text())
    except ValueError:
        return {}


def save_store(store):
    ensure_config_dir()
    tmp = STORE_FILE.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(store, f, indent=1)
    os.replace(tmp, STORE_FILE)


def stats(entry):
    """(attempts, passes). Entries stored before stats existed count as one passed test."""
    attempts = entry.get("attempts", 1)
    passes = entry.get("passes", 1 if entry.get("speed_kbps", 0) > 0 else 0)
    return attempts, passes


def reliability(entry):
    """Share of tests passed, smoothed so one lucky test does not outrank five good ones."""
    attempts, passes = stats(entry)
    return (passes + 1) / (attempts + 2)


def record_result(entry, speed, ttfb):
    """Add one test outcome to an entry. `speed` is KB/s, 0 means the test failed."""
    attempts, passes = stats(entry)
    entry["attempts"] = attempts + 1
    entry["passes"] = passes
    entry["last_checked"] = int(time.time())
    if speed > 0:
        entry["passes"] = passes + 1
        entry["last_ok"] = entry["last_checked"]
        speeds = entry["speeds"] if "speeds" in entry else [entry["speed_kbps"]] if entry.get("speed_kbps", 0) > 0 else []
        entry["speeds"] = [x for x in speeds + [speed] if x > 0][-KEEP_SPEEDS:]
        entry["speed_kbps"] = round(statistics.median(entry["speeds"]), 2)
        ttfbs = entry.get("ttfbs", []) + [ttfb]
        entry["ttfbs"] = ttfbs[-KEEP_SPEEDS:]
        entry["ttfb_ms"] = int(statistics.median(entry["ttfbs"]))


def new_entry(node, speed, ttfb):
    """Store entry for a node that has just passed its first test."""
    now = int(time.time())
    return {
        "key": node["key"], "protocol": node["protocol"], "host": node["host"], "port": node["port"],
        "link": node["link"], "attempts": 1, "passes": 1 if speed > 0 else 0, "last_checked": now,
        "speed_kbps": speed, "speeds": [speed] if speed > 0 else [],
        "ttfb_ms": ttfb, "ttfbs": [ttfb] if ttfb is not None else [], "last_ok": now if speed > 0 else None,
    }


SORTS = {
    # reliability x speed: a fast node that often fails ranks below a slightly slower steady one
    "score": lambda n: reliability(n) * n.get("speed_kbps", 0),
    "speed": lambda n: n.get("speed_kbps", 0),
    "reliability": lambda n: (reliability(n), n.get("speed_kbps", 0)),
}


def ranked(store, by="score"):
    return sorted(store.values(), key=SORTS[by], reverse=True)


# ----------------------------------------------------------------- commands ---


async def run_scan(args, config):
    mirrors = list(args.mirror) + read_lines(args.mirrors_file or MIRRORS_FILE)
    channels = list(args.channel) + read_lines(args.channels_file or CHANNELS_FILE)
    if not mirrors and not channels:
        die("No sources. Pass --mirror URL / --channel NAME, or fill {} / {}.".format(MIRRORS_FILE, CHANNELS_FILE))

    xray = None
    if not args.no_speedtest:
        xray = shutil.which(args.xray) if args.xray else shutil.which("xray")
        if not xray:
            die("xray not found. Install it, pass --xray PATH, or use --no-speedtest (TCP check only).")
        if not shutil.which("curl"):
            die("curl not found (needed for the speed test). Use --no-speedtest to skip it.")

    batches = await asyncio.gather(
        collect_mirrors(mirrors) if mirrors else asyncio.sleep(0, result=[]),
        collect_telegram(channels, config) if channels else asyncio.sleep(0, result=[]),
    )
    nodes, seen = [], set()
    raw_total = 0
    for links in batches:
        for raw in links:
            raw_total += 1
            node = parse_link(raw)
            if node and node["key"] not in seen:
                seen.add(node["key"])
                nodes.append(node)
    log("collected {} links, {} usable after parsing and de-duplication".format(raw_total, len(nodes)))

    store = load_store()
    new_nodes = [n for n in nodes if n["key"] not in store]

    probe_sem = asyncio.Semaphore(MAX_PROBES)
    reachable = await asyncio.gather(*[tcp_ok(n["host"], n["port"], probe_sem) for n in new_nodes])
    passing = [n for n, ok in zip(new_nodes, reachable) if ok]
    log("TCP probe: {}/{} new nodes reachable".format(len(passing), len(new_nodes)))

    if xray:
        sem = asyncio.Semaphore(args.concurrency)

        async def test(node):
            async with sem:
                node["speed_kbps"], node["ttfb_ms"] = await speed_test(xray, node)
                return node

        tested = await asyncio.gather(*[test(n) for n in passing])
        passing = [n for n in tested if n["speed_kbps"] > 0]
        log("speed test: {} working".format(len(passing)))

    # Re-check what we already had: keep only nodes whose port still answers.
    old = [n for n in store.values() if "host" in n and "port" in n]
    for key in [k for k, n in store.items() if "host" not in n or "port" not in n]:
        del store[key]  # unreadable entries
    alive = await asyncio.gather(*[tcp_ok(n["host"], n["port"], probe_sem) for n in old])
    dropped = 0
    for node, ok in zip(old, alive):
        if ok:
            node["last_checked"] = int(time.time())
        else:
            del store[node["key"]]
            dropped += 1

    for node in passing:
        store[node["key"]] = new_entry(node, node.get("speed_kbps", 0.0), node.get("ttfb_ms"))
    save_store(store)
    print("Added {}, dropped {} dead, {} stored. See: list".format(len(passing), dropped, len(store)))


def cmd_scan(args, config):
    try:
        asyncio.run(run_scan(args, config))
    except KeyboardInterrupt:
        sys.exit(130)


async def run_test(args):
    xray = shutil.which(args.xray) if args.xray else shutil.which("xray")
    if not xray:
        die("xray not found. Install it or pass --xray PATH.")
    if not shutil.which("curl"):
        die("curl not found (needed for the speed test).")
    store = load_store()
    if not store:
        die("Nothing stored yet. Run: scan")

    nodes = {}
    for key, entry in list(store.items()):
        node = parse_link(entry.get("link", ""))
        if node is None:
            del store[key]  # unreadable or unsafe entry
        else:
            node["link"] = entry["link"]  # keep the stored link and remark
            nodes[key] = node
    sem = asyncio.Semaphore(args.concurrency)

    async def one(key):
        async with sem:
            return key, await speed_test(xray, nodes[key])

    for round_no in range(1, args.rounds + 1):
        if round_no > 1 and args.interval:
            log("waiting {}s before round {}".format(args.interval, round_no))
            await asyncio.sleep(args.interval)
        results = await asyncio.gather(*[one(k) for k in nodes])
        for key, (speed, ttfb) in results:
            record_result(store[key], speed, ttfb)
        save_store(store)  # keep progress if interrupted
        log("round {}/{}: {}/{} passed".format(round_no, args.rounds, sum(1 for _, r in results if r[0] > 0), len(results)))

    dropped = 0
    if not args.keep_failing:
        for key in [k for k, n in store.items() if stats(n)[0] >= 3 and stats(n)[1] / stats(n)[0] < 0.34]:
            del store[key]
            dropped += 1
        save_store(store)
    print("Tested {} nodes, dropped {} unreliable, {} stored. See: list --details".format(len(nodes), dropped, len(store)))


def cmd_test(args, config):
    try:
        asyncio.run(run_test(args))
    except KeyboardInterrupt:
        sys.exit(130)


def format_details(entries):
    lines = ["{:>3}  {:>5}  {:>9}  {:>8}  {:>6}  {}".format("#", "rel", "KB/s", "ttfb ms", "tests", "node")]
    for i, n in enumerate(entries, 1):
        attempts, passes = stats(n)
        lines.append("{:>3}  {:>4.0%}  {:>9.1f}  {:>8}  {:>6}  {} {}:{}".format(
            i, passes / attempts, n.get("speed_kbps", 0), n.get("ttfb_ms") or "-", attempts,
            n["protocol"], n["host"], n["port"]))
    return "\n".join(lines)


def cmd_list(args, config):
    entries = ranked(load_store(), args.sort)
    if args.count:
        entries = entries[: args.count]
    if not entries:
        die("Nothing stored yet. Run: scan")
    if args.details:
        print(format_details(entries))
        return
    links = [n["link"] for n in entries]
    text = "\n".join(links) + "\n"
    if args.output:
        Path(args.output).write_text(text)
        print("Wrote {} links to {}".format(len(links), args.output))
    else:
        sys.stdout.write(text)


def build_parser():
    parser = argparse.ArgumentParser(prog="Discover", description="Find working proxy links from public sources.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="collect, test and store working links")
    scan.add_argument("--mirror", action="append", default=[], metavar="URL", help="subscription/mirror URL (repeatable)")
    scan.add_argument("--channel", action="append", default=[], metavar="NAME", help="public Telegram channel (repeatable)")
    scan.add_argument("--mirrors-file", help="file with one mirror URL per line (default: {})".format(MIRRORS_FILE))
    scan.add_argument("--channels-file", help="file with one channel per line (default: {})".format(CHANNELS_FILE))
    scan.add_argument("--xray", help="path to the xray binary (default: found on PATH)")
    scan.add_argument("--concurrency", type=int, default=5, help="parallel xray speed tests (default: 5)")
    scan.add_argument("--no-speedtest", action="store_true", help="TCP check only; skip the xray speed test")

    test = sub.add_parser("test", help="re-test stored links through xray and update their reliability")
    test.add_argument("--rounds", type=int, default=3, help="speed tests per node (default: 3)")
    test.add_argument("--interval", type=int, default=0, help="seconds to wait between rounds (default: 0)")
    test.add_argument("--xray", help="path to the xray binary (default: found on PATH)")
    test.add_argument("--concurrency", type=int, default=5, help="parallel xray speed tests (default: 5)")
    test.add_argument("--keep-failing", action="store_true", help="do not drop nodes that fail most tests")

    lst = sub.add_parser("list", help="print stored links, best first")
    lst.add_argument("--sort", choices=sorted(SORTS), default="score",
                     help="score = reliability x speed (default), speed, or reliability")
    lst.add_argument("--details", action="store_true", help="show a table of speed, reliability and latency instead of links")
    lst.add_argument("--count", type=int, help="only the N best")
    lst.add_argument("--output", help="write links to this file instead of stdout")
    return parser


COMMANDS = {"scan": cmd_scan, "test": cmd_test, "list": cmd_list}


def main(argv=None):
    args = build_parser().parse_args(argv)
    COMMANDS[args.command](args, load_config())


if __name__ == "__main__":
    main()
