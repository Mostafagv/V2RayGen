#!/usr/bin/env python3
"""
Bot - an invite-only Telegram bot that gives each member their own proxy link.

Runs on the server that runs xray, next to the config.json and
v2raygen-links.txt that V2RayGen created. Uses only the Python standard
library. Each member gets their own xray user (UUID), so one person can be
removed without changing anyone else's link.

Commands:
  run                  start the bot (talks to Telegram by long polling)
  install-service      run the bot as a systemd service that starts at boot
  invite [--admin]     print a one-time invite link
  users                list members
  revoke <telegram id> remove a member and their xray user

Telegram commands:
  /start <code>   join with an invite link (the link does this)
  /config         get your link again
  /new_config     get a new link; the old one stops working
  /invite         (admin) make a one-time invite link; "/invite admin" for an admin
  /users          (admin) list members
  /revoke <id>    (admin) remove a member

The bot token is read from TELEGRAM_BOT_TOKEN or ~/.config/v2raygen/bot.env
(chmod 600), never from this repository. See README.md for setup.
"""

import argparse
import contextlib
import fcntl
import html
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen

CONFIG_DIR = Path(os.environ.get("V2RAYGEN_CONFIG_DIR", Path.home() / ".config" / "v2raygen"))
CONFIG_FILE = CONFIG_DIR / "bot.env"
STORE_FILE = CONFIG_DIR / "bot.json"
LOCK_FILE = CONFIG_DIR / "bot.lock"
SERVICE_FILE = Path("/etc/systemd/system/v2raygen-bot.service")

DEFAULTS = {
    "TELEGRAM_API": "https://api.telegram.org",
    "XRAY_CONFIG": "/root/config.json",
    "XRAY_LINK_FILE": "/root/v2raygen-links.txt",
    "XRAY_RESTART_CMD": "",
    "BOT_INVITE_DAYS": "7",
    "BOT_LANGUAGE": "fa",
}
POLL_SECONDS = 50
VLESS_RE = re.compile(r"vless://\S+")

NEW_CONFIG_COOLDOWN = 600  # seconds; every new config restarts xray for everyone

# Everything members see in Telegram. Pick with BOT_LANGUAGE (fa or en).
TEXTS = {
    "en": {
        "welcome": "Welcome! ",
        "link": (
            "This is your personal link. Copy it into v2rayNG, Hiddify, Streisand "
            "or another V2Ray app:\n\n<code>{link}</code>\n\n"
            "Don't share it: it belongs to you, and sharing it can get it cut off. "
            "Send /config to get it again."
        ),
        "new_link": "Your old link has stopped working. ",
        "too_soon": "You can get a new link once every 10 minutes. Try again in {minutes} min.",
        "is_admin": "\n\nYou are an admin. Send /help for the admin commands.",
        "help": (
            "/config - get your link again\n"
            "/new_config - get a new link (the old one stops working)\n"
            "/help - this message"
        ),
        "admin_help": (
            "\n\nAdmin:\n"
            "/invite - one-time invite link\n"
            "/invite admin - invite another admin\n"
            "/users - list members\n"
            "/revoke &lt;id&gt; - remove a member"
        ),
        "unknown": "Unknown command.\n\n",
        "invite": "One-time invite, valid for {days} days:\n\n{url}",
        "admin_invite": "One-time admin invite, valid for {days} days:\n\n{url}",
        "no_users": "No members yet.",
        "user_line": "{uid} {name} {handle}{admin} - joined {date}",
        "admin_tag": " (admin)",
        "revoke_usage": "Usage: /revoke &lt;id&gt; (ids are in /users)",
        "revoke_self": "You can't revoke yourself.",
        "no_member": "No member with id {uid}. Ids are in /users.",
        "removed": "Removed {name}. Their link stopped working.",
        "error": "Something went wrong on the server. Try again later.",
        "cmd_config": "Get your link",
        "cmd_new_config": "Get a new link",
        "cmd_help": "Help",
    },
    "fa": {
        "welcome": "خوش آمدید! ",
        "link": (
            "این لینک شخصی شماست. آن را در v2rayNG، Hiddify، Streisand "
            "یا یک برنامهٔ V2Ray دیگر وارد کنید:\n\n<code>{link}</code>\n\n"
            "آن را با کسی به اشتراک نگذارید: این لینک مخصوص شماست و اشتراک‌گذاری آن "
            "ممکن است باعث قطع شدنش شود. برای دریافت دوباره /config را بفرستید."
        ),
        "new_link": "لینک قبلی شما دیگر کار نمی‌کند. ",
        "too_soon": "هر ۱۰ دقیقه فقط یک بار می‌توانید لینک جدید بگیرید. {minutes} دقیقهٔ دیگر دوباره امتحان کنید.",
        "is_admin": "\n\nشما مدیر هستید. برای دیدن دستورهای مدیریت /help را بفرستید.",
        "help": (
            "/config - دریافت دوبارهٔ لینک\n"
            "/new_config - دریافت لینک جدید (لینک قبلی از کار می‌افتد)\n"
            "/help - همین راهنما"
        ),
        "admin_help": (
            "\n\nمدیریت:\n"
            "/invite - لینک دعوت یک‌بارمصرف\n"
            "/invite admin - دعوت یک مدیر دیگر\n"
            "/users - فهرست اعضا\n"
            "/revoke &lt;id&gt; - حذف یک عضو"
        ),
        "unknown": "دستور ناشناخته.\n\n",
        "invite": "لینک دعوت یک‌بارمصرف، معتبر تا {days} روز:\n\n{url}",
        "admin_invite": "لینک دعوت مدیر (یک‌بارمصرف)، معتبر تا {days} روز:\n\n{url}",
        "no_users": "هنوز عضوی وجود ندارد.",
        "user_line": "{uid} {name} {handle}{admin} - عضویت {date}",
        "admin_tag": " (مدیر)",
        "revoke_usage": "روش استفاده: /revoke &lt;id&gt; (شناسه‌ها در /users هستند)",
        "revoke_self": "نمی‌توانید خودتان را حذف کنید.",
        "no_member": "عضوی با شناسهٔ {uid} وجود ندارد. شناسه‌ها در /users هستند.",
        "removed": "{name} حذف شد و لینکش دیگر کار نمی‌کند.",
        "error": "مشکلی در سرور پیش آمد. لطفاً بعداً دوباره امتحان کنید.",
        "cmd_config": "دریافت لینک",
        "cmd_new_config": "دریافت لینک جدید",
        "cmd_help": "راهنما",
    },
}


def t(settings, key, **values):
    texts = TEXTS.get(settings.get("BOT_LANGUAGE"), TEXTS["en"])
    return texts[key].format(**values) if values else texts[key]


class BotError(Exception):
    pass


def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(1)


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S ") + msg, flush=True)


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


def load_settings():
    settings = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        if CONFIG_FILE.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            die("{} is readable by other users. Run: chmod 600 {}".format(CONFIG_FILE, CONFIG_FILE))
        settings.update(parse_env_file(CONFIG_FILE.read_text()))
    for key in list(DEFAULTS) + ["TELEGRAM_BOT_TOKEN"]:
        if os.environ.get(key):
            settings[key] = os.environ[key]
    return settings


def ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)


# ------------------------------------------------------------------- store ---


def empty_store():
    return {"users": {}, "invites": {}, "offset": 0}


@contextlib.contextmanager
def store_lock():
    """Hold the store for read-modify-write; the service and the CLI share it."""
    ensure_config_dir()
    with open(LOCK_FILE, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        store = load_store()
        before = json.dumps(store, sort_keys=True)
        yield store
        if json.dumps(store, sort_keys=True) != before:
            save_store(store)


def load_store():
    if not STORE_FILE.exists():
        return empty_store()
    try:
        store = json.loads(STORE_FILE.read_text())
    except ValueError:
        die("{} is not valid JSON; fix or remove it".format(STORE_FILE))
    for key, value in empty_store().items():
        store.setdefault(key, value)
    return store


def save_store(store):
    tmp = STORE_FILE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(store, fh, indent=2, sort_keys=True)
    os.replace(tmp, STORE_FILE)


def drop_expired_invites(store, now=None):
    now = now or time.time()
    for code in [c for c, inv in store["invites"].items() if inv.get("expires", 0) < now]:
        del store["invites"][code]


def new_invite(store, settings, admin=False, by=None):
    drop_expired_invites(store)
    code = secrets.token_urlsafe(16)
    now = time.time()
    store["invites"][code] = {
        "created": int(now),
        "expires": int(now + float(settings["BOT_INVITE_DAYS"]) * 86400),
        "admin": bool(admin),
        "by": by,
    }
    return code


def invite_url(bot_username, code):
    return "https://t.me/{}?start={}".format(bot_username, code)


# -------------------------------------------------------------------- xray ---


def template_link(settings):
    """The server's own vless link, as written by V2RayGen; members' links copy it."""
    path = Path(settings["XRAY_LINK_FILE"])
    try:
        links = VLESS_RE.findall(path.read_text())
    except OSError as err:
        raise BotError("cannot read {}: {}".format(path, err.strerror))
    if not links:
        raise BotError("no vless link in {}".format(path))
    return links[-1]


def member_link(template, user_uuid, label):
    parts = urlsplit(template)
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, user_uuid + "@" + host, parts.path, parts.query, quote(label)))


def link_label(user):
    base = user.get("username") or user.get("name") or "member"
    return re.sub(r"[^A-Za-z0-9_.-]", "", base)[:24] or "member"


def read_xray_config(settings):
    path = Path(settings["XRAY_CONFIG"])
    try:
        config = json.loads(path.read_text())
    except OSError as err:
        raise BotError("cannot read {}: {}".format(path, err.strerror))
    except ValueError:
        raise BotError("{} is not valid JSON".format(path))
    for inbound in config.get("inbounds", []):
        if inbound.get("protocol") == "vless":
            clients = inbound.setdefault("settings", {}).setdefault("clients", [])
            return path, config, clients
    raise BotError("no vless inbound in {}".format(path))


def write_xray_config(path, config):
    # Rewrite in place: docker bind-mounts the file, so a new inode would not be seen.
    shutil.copy2(path, str(path) + ".bak")
    with open(path, "r+") as fh:
        fh.seek(0)
        json.dump(config, fh, indent=2)
        fh.write("\n")
        fh.truncate()


def restart_xray(settings):
    cmd = settings["XRAY_RESTART_CMD"]
    if not cmd:
        cmd = "docker-compose restart" if shutil.which("docker-compose") else "docker compose restart"
    cwd = Path(settings["XRAY_CONFIG"]).parent
    try:
        proc = subprocess.run(shlex.split(cmd), cwd=cwd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as err:
        raise BotError("restarting xray failed: {}".format(err))
    if proc.returncode != 0:
        raise BotError("restarting xray failed: {}".format((proc.stderr or proc.stdout).strip()[-300:]))


def client_email(user_id):
    return "tg{}".format(user_id)


def set_xray_user(settings, user_id, user_uuid):
    """Add (or with user_uuid=None, remove) a member's xray user and restart xray."""
    path, config, clients = read_xray_config(settings)
    email = client_email(user_id)
    kept = [c for c in clients if c.get("email") != email]
    if user_uuid:
        client = {"id": user_uuid, "level": 0, "email": email}
        flow = parse_qs(urlsplit(template_link(settings)).query).get("flow", [""])[0]
        if flow:
            client["flow"] = flow
        kept.append(client)
    if kept == clients:
        return
    clients[:] = kept
    write_xray_config(path, config)
    try:
        restart_xray(settings)
    except BotError:
        # Put the old config back so the next restart doesn't load a change nobody recorded.
        with open(str(path) + ".bak") as old, open(path, "r+") as fh:
            fh.write(old.read())
            fh.truncate()
        raise


# ---------------------------------------------------------------- telegram ---


class Telegram:
    def __init__(self, settings):
        token = settings.get("TELEGRAM_BOT_TOKEN")
        if not token:
            die(
                "No bot token. Set TELEGRAM_BOT_TOKEN or put TELEGRAM_BOT_TOKEN=... "
                "in {} (chmod 600).".format(CONFIG_FILE)
            )
        self.base = "{}/bot{}/".format(settings["TELEGRAM_API"].rstrip("/"), token)
        self.username = None

    def call(self, method, params=None, timeout=30):
        req = Request(
            self.base + method,
            data=json.dumps(params or {}).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
        except HTTPError as err:
            try:
                detail = json.loads(err.read()).get("description", "")
            except (ValueError, AttributeError):
                detail = ""
            raise BotError("Telegram {} failed: {} {}".format(method, err.code, detail))
        except (URLError, OSError) as err:
            raise BotError("cannot reach Telegram: {}".format(getattr(err, "reason", err)))
        except ValueError:
            raise BotError("Telegram {} returned invalid JSON".format(method))
        if not body.get("ok"):
            raise BotError("Telegram {} failed: {}".format(method, body.get("description", "")))
        return body["result"]

    def me(self):
        if not self.username:
            self.username = self.call("getMe")["username"]
        return self.username

    def send(self, chat_id, text):
        self.call("sendMessage", {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        })


# ---------------------------------------------------------------- handlers ---


def display_name(tg_user):
    name = " ".join(p for p in (tg_user.get("first_name"), tg_user.get("last_name")) if p)
    return name or str(tg_user.get("id"))


def link_message(settings, user, head=""):
    link = member_link(template_link(settings), user["uuid"], link_label(user))
    return head + t(settings, "link", link=html.escape(link))


def new_config(settings, store, uid):
    """Give a member a fresh UUID; their old link stops working."""
    user = store["users"][uid]
    wait = user.get("renewed", 0) + NEW_CONFIG_COOLDOWN - time.time()
    if wait > 0:
        return t(settings, "too_soon", minutes=int(wait // 60) + 1)
    fresh = str(uuid.uuid4())
    set_xray_user(settings, uid, fresh)
    user["uuid"] = fresh
    user["renewed"] = int(time.time())
    return link_message(settings, user, t(settings, "new_link"))


def join(settings, store, code, tg_user):
    invite = store["invites"].get(code)
    if not invite or invite.get("expires", 0) < time.time():
        return None
    uid = str(tg_user["id"])
    existing = store["users"].get(uid)
    if existing:
        if invite.get("admin"):  # a regular invite stays unused for someone new
            existing["admin"] = True
            del store["invites"][code]
        return existing
    user = {
        "name": display_name(tg_user),
        "username": tg_user.get("username") or "",
        "uuid": str(uuid.uuid4()),
        "joined": int(time.time()),
        "admin": bool(invite.get("admin")),
        "invited_by": invite.get("by"),
    }
    set_xray_user(settings, uid, user["uuid"])
    store["users"][uid] = user
    del store["invites"][code]
    return user


def revoke(settings, store, uid):
    user = store["users"].get(uid)
    if not user:
        raise BotError("no member with id {}".format(uid))
    set_xray_user(settings, uid, None)
    del store["users"][uid]
    return user


def format_users(store, settings=None, markup=False):
    settings = settings or {"BOT_LANGUAGE": "en"}
    if not store["users"]:
        return t(settings, "no_users")
    lines = []
    for uid, user in sorted(store["users"].items(), key=lambda kv: kv[1].get("joined", 0)):
        text = t(
            settings, "user_line", uid=uid, name=user.get("name", ""),
            handle="@" + user["username"] if user.get("username") else "",
            admin=t(settings, "admin_tag") if user.get("admin") else "",
            date=time.strftime("%Y-%m-%d", time.gmtime(user.get("joined", 0))),
        )
        lines.append(html.escape(text) if markup else text)
    return "\n".join(lines)


def reply_for(settings, tg, store, message):
    """Return the reply text for one private message, or None to stay silent."""
    tg_user = message.get("from") or {}
    if "id" not in tg_user or tg_user.get("is_bot"):
        return None
    uid = str(tg_user["id"])
    text = (message.get("text") or "").strip()
    command, _, arg = text.partition(" ")
    command = command.split("@", 1)[0].lower()
    arg = arg.strip()
    user = store["users"].get(uid)

    if command == "/start" and arg and (not user or not user.get("admin")):
        joined = join(settings, store, arg, tg_user)
        if joined is None and not user:
            return None
        if joined is not None:
            reply = link_message(settings, joined, t(settings, "welcome"))
            return reply + (t(settings, "is_admin") if joined.get("admin") else "")

    if not user:
        return None  # strangers get no answer at all

    if command in ("/start", "/config", "/link"):
        return link_message(settings, user)
    if command in ("/new_config", "/newconfig"):
        return new_config(settings, store, uid)
    help_text = t(settings, "help") + (t(settings, "admin_help") if user.get("admin") else "")
    if command == "/help" or not command.startswith("/"):
        return help_text
    if not user.get("admin"):
        return t(settings, "unknown") + help_text

    if command == "/invite":
        admin = arg.lower() == "admin"
        code = new_invite(store, settings, admin=admin, by=uid)
        return t(settings, "admin_invite" if admin else "invite",
                 days=settings["BOT_INVITE_DAYS"], url=invite_url(tg.me(), code))
    if command == "/users":
        return format_users(store, settings, markup=True)
    if command == "/revoke":
        if not arg:
            return t(settings, "revoke_usage")
        if arg == uid:
            return t(settings, "revoke_self")
        if arg not in store["users"]:
            return t(settings, "no_member", uid=html.escape(arg))
        removed = revoke(settings, store, arg)
        return t(settings, "removed", name=html.escape(removed.get("name", arg)))
    return t(settings, "unknown") + help_text


def handle_update(settings, tg, update):
    message = update.get("message")
    if not message or (message.get("chat") or {}).get("type") != "private":
        return
    with store_lock() as store:
        try:
            reply = reply_for(settings, tg, store, message)
        except BotError as err:
            log("error: {}".format(err))
            reply = t(settings, "error") if (
                str((message.get("from") or {}).get("id")) in store["users"]
            ) else None
    if reply:
        tg.send(message["chat"]["id"], reply)


# ---------------------------------------------------------------- commands ---


def cmd_run(args, settings):
    tg = Telegram(settings)
    template_link(settings)
    read_xray_config(settings)
    try:
        log("running as @{}".format(tg.me()))
        tg.call("setMyCommands", {"commands": [
            {"command": "config", "description": t(settings, "cmd_config")},
            {"command": "new_config", "description": t(settings, "cmd_new_config")},
            {"command": "help", "description": t(settings, "cmd_help")},
        ]})
    except BotError as err:
        die(str(err))
    delay = 1
    while True:
        with store_lock() as store:
            offset = store["offset"]
        try:
            updates = tg.call(
                "getUpdates",
                {"offset": offset, "timeout": 0 if args.once else POLL_SECONDS, "allowed_updates": ["message"]},
                timeout=POLL_SECONDS + 15,
            )
            delay = 1
        except BotError as err:
            log("error: {}".format(err))
            if args.once:
                return 1
            time.sleep(delay)
            delay = min(delay * 2, 60)
            continue
        for update in updates:
            try:
                handle_update(settings, tg, update)
            except Exception as err:  # never let one bad update stop the bot
                log("error handling update {}: {}: {}".format(update.get("update_id"), type(err).__name__, err))
            with store_lock() as store:
                store["offset"] = max(store["offset"], update["update_id"] + 1)
        if args.once:
            return 0


def cmd_invite(args, settings):
    tg = Telegram(settings)
    try:
        username = tg.me()
    except BotError as err:
        die(str(err))
    with store_lock() as store:
        code = new_invite(store, settings, admin=args.admin, by="cli")
    kind = "admin invite" if args.admin else "invite"
    print("One-time {}, valid for {} days:".format(kind, settings["BOT_INVITE_DAYS"]))
    print(invite_url(username, code))
    return 0


def cmd_users(args, settings):
    with store_lock() as store:
        print(format_users(store))
    return 0


def cmd_revoke(args, settings):
    with store_lock() as store:
        try:
            user = revoke(settings, store, args.id)
        except BotError as err:
            die(str(err))
    print("Removed {} ({}).".format(user.get("name", ""), args.id))
    return 0


def cmd_install_service(args, settings):
    if os.geteuid() != 0:
        die("install-service needs root (it writes {})".format(SERVICE_FILE))
    if not shutil.which("systemctl"):
        die("systemctl not found; run `python3 Bot.py run` under your own supervisor")
    Telegram(settings)  # fail now if there is no token
    script = Path(__file__).resolve()
    env = ""
    if os.environ.get("V2RAYGEN_CONFIG_DIR"):
        env = "Environment=V2RAYGEN_CONFIG_DIR={}\n".format(CONFIG_DIR)
    SERVICE_FILE.write_text(
        "[Unit]\nDescription=V2RayGen Telegram bot\nAfter=network-online.target docker.service\n"
        "Wants=network-online.target\n\n[Service]\n{}ExecStart={} {} run\n"
        "Restart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n".format(
            env, sys.executable, script
        )
    )
    for cmd in (["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", "v2raygen-bot"],
                ["systemctl", "restart", "v2raygen-bot"]):
        subprocess.run(cmd, check=True)
    print("Installed and started. Logs: journalctl -u v2raygen-bot -f")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="Bot", description="Invite-only Telegram bot for V2RayGen links.")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="start the bot")
    run.add_argument("--once", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("install-service", help="run the bot as a systemd service")
    invite = sub.add_parser("invite", help="print a one-time invite link")
    invite.add_argument("--admin", action="store_true", help="the person who opens it becomes an admin")
    sub.add_parser("users", help="list members")
    rev = sub.add_parser("revoke", help="remove a member")
    rev.add_argument("id", help="Telegram user id (see `users`)")
    return parser


COMMANDS = {
    "run": cmd_run,
    "install-service": cmd_install_service,
    "invite": cmd_invite,
    "users": cmd_users,
    "revoke": cmd_revoke,
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    settings = load_settings()
    try:
        float(settings["BOT_INVITE_DAYS"])
    except ValueError:
        die("BOT_INVITE_DAYS must be a number")
    if settings["BOT_LANGUAGE"] not in TEXTS:
        die("BOT_LANGUAGE must be one of: " + ", ".join(sorted(TEXTS)))
    try:
        return COMMANDS[args.command](args, settings)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
