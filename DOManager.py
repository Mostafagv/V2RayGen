#!/usr/bin/env python3
"""
DOManager - manage V2RayGen proxy servers on DigitalOcean.

Runs on your own computer (not on the server). Uses only the Python standard
library and the system `ssh` client.

Commands:
  regions                      list regions you can create servers in
  create  --region fra1        create a new server and install the proxy on it
  list    [--links]            list servers (optionally with their proxy links)
  stop    <name|id>            shut a server down (still billed by DigitalOcean)
  start   <name|id>            power a stopped server back on
  destroy <name|id>            delete a server permanently (stops billing)

Credentials are never stored in this repository. The API token is read from
the DIGITALOCEAN_TOKEN environment variable, or from ~/.config/v2raygen/do.env
(which must be chmod 600). See README.md for setup.
"""

import argparse
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API = "https://api.digitalocean.com/v2"
TAG = "v2raygen"
CONFIG_DIR = Path(os.environ.get("V2RAYGEN_CONFIG_DIR", Path.home() / ".config" / "v2raygen"))
CONFIG_FILE = CONFIG_DIR / "do.env"
LINKS_CACHE = CONFIG_DIR / "links.json"
KNOWN_HOSTS = CONFIG_DIR / "known_hosts"
REMOTE_LINK_FILE = "/root/v2raygen-links.txt"
SCRIPT_URL = "https://raw.githubusercontent.com/Mostafagv/V2RayGen/main/V2RayGen.py"

DEFAULTS = {
    "DO_DEFAULT_SIZE": "s-1vcpu-512mb-10gb",
    "DO_DEFAULT_IMAGE": "ubuntu-24-04-x64",
    "DO_MAX_DROPLETS": "5",
    "DO_SSH_PUBKEY": "",
}

LINK_RE = re.compile(r"\b(?:vless|vmess|trojan|ss)://\S+")


def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(1)


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
    config = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        mode = CONFIG_FILE.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            die("{} is readable by other users. Run: chmod 600 {}".format(CONFIG_FILE, CONFIG_FILE))
        config.update(parse_env_file(CONFIG_FILE.read_text()))
    for key in list(DEFAULTS) + ["DIGITALOCEAN_TOKEN", "DO_DEFAULT_REGION"]:
        if os.environ.get(key):
            config[key] = os.environ[key]
    return config


def ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)


# --------------------------------------------------------------------- API ---


class DigitalOcean:
    def __init__(self, token):
        if not token:
            die(
                "No DigitalOcean token. Set DIGITALOCEAN_TOKEN or put "
                "DIGITALOCEAN_TOKEN=... in {} (chmod 600).".format(CONFIG_FILE)
            )
        self.token = token

    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = Request(
            API + path,
            data=data,
            method=method,
            headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except HTTPError as err:
            try:
                detail = json.loads(err.read()).get("message", "")
            except (ValueError, AttributeError):
                detail = ""
            die("DigitalOcean API {} {} failed: {} {}".format(method, path, err.code, detail))
        except URLError as err:
            die("Cannot reach DigitalOcean API: {}".format(err.reason))

    def regions(self):
        return self.request("GET", "/regions?per_page=200")["regions"]

    def droplets(self):
        return self.request("GET", "/droplets?per_page=200&tag_name=" + TAG)["droplets"]

    def droplet(self, droplet_id):
        return self.request("GET", "/droplets/{}".format(droplet_id))["droplet"]

    def ssh_keys(self):
        return self.request("GET", "/account/keys?per_page=200")["ssh_keys"]

    def add_ssh_key(self, name, public_key):
        return self.request("POST", "/account/keys", {"name": name, "public_key": public_key})["ssh_key"]

    def create_droplet(self, body):
        return self.request("POST", "/droplets", body)["droplet"]

    def action(self, droplet_id, action_type):
        return self.request("POST", "/droplets/{}/actions".format(droplet_id), {"type": action_type})["action"]

    def delete_droplet(self, droplet_id):
        self.request("DELETE", "/droplets/{}".format(droplet_id))


def public_ipv4(droplet):
    for net in droplet.get("networks", {}).get("v4", []):
        if net.get("type") == "public":
            return net.get("ip_address")
    return None


def find_droplet(api, ident):
    """Find a v2raygen-tagged droplet by id or name. Never touches untagged droplets."""
    matches = [d for d in api.droplets() if str(d["id"]) == ident or d["name"] == ident]
    if not matches:
        die("No v2raygen server named or numbered '{}'. Run: list".format(ident))
    if len(matches) > 1:
        die("More than one server is named '{}'; use the numeric id instead.".format(ident))
    return matches[0]


# ------------------------------------------------------------------- setup ---


def build_user_data(sni=None, reality_dest=None, port=None):
    """Cloud-init script: enable BBR, then run the README install command as root."""
    gen_args = ["--vless", "--tcp", "--reality", "--vision"]
    if sni:
        gen_args += ["--sni", sni, "--reality-dest", reality_dest or "{}:443".format(sni)]
    elif reality_dest:
        gen_args += ["--reality-dest", reality_dest]
    if port:
        gen_args += ["--port", str(port)]
    return "\n".join(
        [
            "#!/bin/bash",
            "set -euo pipefail",
            "export HOME=/root",
            "cd /root",
            'printf "net.core.default_qdisc=fq\\nnet.ipv4.tcp_congestion_control=bbr\\n" '
            "> /etc/sysctl.d/99-bbr.conf",
            "sysctl --system >/dev/null",
            "curl -fsSL {} | python3 - {}".format(SCRIPT_URL, " ".join(shlex.quote(a) for a in gen_args)),
            "",
        ]
    )


def local_public_key(config, override=None):
    chosen = override or config.get("DO_SSH_PUBKEY")
    candidates = [chosen] if chosen else ["~/.ssh/id_ed25519.pub", "~/.ssh/id_ecdsa.pub", "~/.ssh/id_rsa.pub"]
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.exists():
            return path, path.read_text().strip()
    die(
        "No SSH public key found (looked at {}). Create one with: ssh-keygen -t ed25519".format(
            ", ".join(candidates)
        )
    )


def ensure_ssh_key(api, config, override=None):
    """Return the DigitalOcean id of the local SSH key, uploading it if needed."""
    path, public_key = local_public_key(config, override)
    key_body = " ".join(public_key.split()[:2])
    for key in api.ssh_keys():
        if " ".join(key["public_key"].split()[:2]) == key_body:
            return key["id"]
    print("Uploading SSH key {} to DigitalOcean".format(path))
    return api.add_ssh_key("v2raygen-" + path.stem, public_key)["id"]


# --------------------------------------------------------------------- ssh ---


def ssh(ip, command, timeout=20):
    ensure_config_dir()
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile={}".format(KNOWN_HOSTS),
        "-o", "LogLevel=ERROR",
        "root@{}".format(ip),
        command,
    ]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def forget_host(ip):
    if ip and KNOWN_HOSTS.exists():
        subprocess.run(
            ["ssh-keygen", "-R", ip, "-f", str(KNOWN_HOSTS)],
            capture_output=True,
        )


def parse_links(text):
    return LINK_RE.findall(text or "")


def fetch_links(ip):
    result = ssh(ip, "cat {} 2>/dev/null; true".format(REMOTE_LINK_FILE))
    if result is None or result.returncode != 0:
        return None
    return parse_links(result.stdout)


def load_cache():
    try:
        return json.loads(LINKS_CACHE.read_text())
    except (OSError, ValueError):
        return {}


def save_cache(cache):
    ensure_config_dir()
    LINKS_CACHE.write_text(json.dumps(cache, indent=2))
    os.chmod(LINKS_CACHE, 0o600)


def remember_links(droplet, ip, links):
    cache = load_cache()
    cache[str(droplet["id"])] = {"name": droplet["name"], "ip": ip, "links": links}
    save_cache(cache)


def wait_for_setup(droplet, ip, timeout):
    """Poll over SSH until the generator wrote its link file, or cloud-init failed."""
    deadline = time.time() + timeout
    probe = "cat {} 2>/dev/null; echo; cloud-init status 2>/dev/null || true".format(REMOTE_LINK_FILE)
    while time.time() < deadline:
        result = ssh(ip, probe)
        if result is not None and result.returncode == 0:
            links = parse_links(result.stdout)
            if links:
                remember_links(droplet, ip, links)
                return links
            if "status: error" in result.stdout:
                die(
                    "Setup failed on {}. Inspect it with: ssh root@{} "
                    "tail -n 50 /var/log/cloud-init-output.log".format(droplet["name"], ip)
                )
        print("  waiting for setup to finish...")
        time.sleep(15)
    die("Timed out waiting for {}. Try later: list --links --refresh".format(droplet["name"]))


# ---------------------------------------------------------------- commands ---


def cmd_regions(api, config, args):
    for region in sorted(api.regions(), key=lambda r: r["slug"]):
        if region["available"]:
            print("{:<6} {}".format(region["slug"], region["name"]))


def cmd_create(api, config, args):
    region = args.region or config.get("DO_DEFAULT_REGION")
    if not region:
        die("Specify --region (see: regions), or set DO_DEFAULT_REGION")
    size = args.size or config["DO_DEFAULT_SIZE"]

    regions = {r["slug"]: r for r in api.regions()}
    if region not in regions or not regions[region]["available"]:
        die("Region '{}' is not available. Run: regions".format(region))
    if size not in regions[region]["sizes"]:
        die("Size '{}' is not offered in {}. Offered: {}".format(size, region, ", ".join(regions[region]["sizes"])))

    limit = int(config["DO_MAX_DROPLETS"])
    if len(api.droplets()) >= limit:
        die("Already at DO_MAX_DROPLETS={} v2raygen servers. Destroy one or raise the limit.".format(limit))

    name = args.name or "v2raygen-{}-{}".format(region, secrets.token_hex(2))
    key_id = ensure_ssh_key(api, config, args.ssh_pubkey)
    droplet = api.create_droplet(
        {
            "name": name,
            "region": region,
            "size": size,
            "image": config["DO_DEFAULT_IMAGE"],
            "ssh_keys": [key_id],
            "tags": [TAG],
            "user_data": build_user_data(args.sni, args.reality_dest, args.port),
        }
    )
    print("Creating {} (id {}) in {} [{}]".format(name, droplet["id"], region, size))

    ip = None
    deadline = time.time() + 300
    while time.time() < deadline:
        droplet = api.droplet(droplet["id"])
        ip = public_ipv4(droplet)
        if droplet["status"] == "active" and ip:
            break
        time.sleep(5)
    else:
        die("Server did not become active in time. Check: list")
    print("Server is up at {}".format(ip))
    forget_host(ip)  # DigitalOcean reuses IPs; drop any stale host key.

    if args.no_wait:
        print("Not waiting for setup. Get the link later with: list --links")
        return
    links = wait_for_setup(droplet, ip, args.timeout)
    print("\nReady: {}".format(name))
    for link in links:
        print(link)


def cmd_list(api, config, args):
    droplets = api.droplets()
    if not droplets:
        print("No v2raygen servers.")
        return
    cache = load_cache()
    for d in sorted(droplets, key=lambda d: d["created_at"]):
        ip = public_ipv4(d) or "-"
        print("{:<28} {:<10} {:<6} {:<16} {:<8} {}".format(
            d["name"], d["id"], d["region"]["slug"], ip, d["status"], d["size_slug"]))
        if not args.links:
            continue
        cached = cache.get(str(d["id"]))
        links = cached["links"] if cached and cached.get("ip") == ip and not args.refresh else None
        if links is None and d["status"] == "active" and ip != "-":
            links = fetch_links(ip)
            if links:
                remember_links(d, ip, links)
        if links:
            for link in links:
                print("    " + link)
        elif d["status"] != "active":
            print("    (server is {}; no links fetched)".format(d["status"]))
        else:
            print("    (no link yet; setup may still be running, or SSH failed)")


def wait_action(api, action, verb):
    deadline = time.time() + 180
    while action["status"] == "in-progress" and time.time() < deadline:
        time.sleep(5)
        action = api.request("GET", "/actions/{}".format(action["id"]))["action"]
    if action["status"] != "completed":
        die("{} did not complete (status: {})".format(verb, action["status"]))


def cmd_stop(api, config, args):
    d = find_droplet(api, args.server)
    if d["status"] == "off":
        print("{} is already off.".format(d["name"]))
        return
    action_type = "power_off" if args.force else "shutdown"
    print("Stopping {} ({})...".format(d["name"], action_type))
    wait_action(api, api.action(d["id"], action_type), "Stop")
    print("Stopped. Note: DigitalOcean still bills stopped servers; use destroy to stop billing.")


def cmd_start(api, config, args):
    d = find_droplet(api, args.server)
    if d["status"] == "active":
        print("{} is already running.".format(d["name"]))
        return
    print("Starting {}...".format(d["name"]))
    wait_action(api, api.action(d["id"], "power_on"), "Start")
    print("Running at {}".format(public_ipv4(api.droplet(d["id"]))))


def cmd_destroy(api, config, args):
    d = find_droplet(api, args.server)
    ip = public_ipv4(d)
    if not args.yes:
        answer = input("Permanently destroy {} (id {}, {})? Type the name to confirm: ".format(d["name"], d["id"], ip))
        if answer.strip() != d["name"]:
            die("Not confirmed; nothing destroyed.")
    api.delete_droplet(d["id"])
    forget_host(ip)
    cache = load_cache()
    if cache.pop(str(d["id"]), None) is not None:
        save_cache(cache)
    print("Destroyed {}.".format(d["name"]))


def build_parser():
    parser = argparse.ArgumentParser(prog="DOManager", description="Manage V2RayGen servers on DigitalOcean.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("regions", help="list available regions")

    create = sub.add_parser("create", help="create a new server and install the proxy")
    create.add_argument("--region", help="region slug, e.g. fra1 (see: regions)")
    create.add_argument("--size", help="droplet size slug (default: {})".format(DEFAULTS["DO_DEFAULT_SIZE"]))
    create.add_argument("--name", help="server name (default: v2raygen-<region>-<random>)")
    create.add_argument("--sni", help="REALITY SNI, e.g. www.cloudflare.com")
    create.add_argument("--reality-dest", help="REALITY dest host:port (default: <sni>:443)")
    create.add_argument("--port", type=int, help="proxy port (default: chosen by V2RayGen)")
    create.add_argument("--ssh-pubkey", help="SSH public key file to install (default: ~/.ssh/id_ed25519.pub)")
    create.add_argument("--no-wait", action="store_true", help="return once the server is up; skip waiting for the link")
    create.add_argument("--timeout", type=int, default=600, help="seconds to wait for setup (default: 600)")

    lst = sub.add_parser("list", help="list servers")
    lst.add_argument("--links", action="store_true", help="also show each server's proxy links (via SSH)")
    lst.add_argument("--refresh", action="store_true", help="re-fetch links instead of using the local cache")

    for name, help_text in (("stop", "shut a server down (still billed)"), ("start", "power a stopped server on")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("server", help="server name or id")
        if name == "stop":
            p.add_argument("--force", action="store_true", help="hard power-off instead of graceful shutdown")

    destroy = sub.add_parser("destroy", help="delete a server permanently")
    destroy.add_argument("server", help="server name or id")
    destroy.add_argument("--yes", "-y", action="store_true", help="skip the confirmation prompt")
    return parser


COMMANDS = {
    "regions": cmd_regions,
    "create": cmd_create,
    "list": cmd_list,
    "stop": cmd_stop,
    "start": cmd_start,
    "destroy": cmd_destroy,
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    config = load_config()
    api = DigitalOcean(config.get("DIGITALOCEAN_TOKEN"))
    try:
        COMMANDS[args.command](api, config, args)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
