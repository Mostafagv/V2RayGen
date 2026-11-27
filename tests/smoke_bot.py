#!/usr/bin/env python3
"""
Offline checks for Bot.py: a fake Telegram API, a temporary xray config and a
fake restart command. No token, docker or internet needed.

  python3 tests/smoke_bot.py
"""

import contextlib
import http.server
import io
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = Path(tempfile.mkdtemp())
os.environ["V2RAYGEN_CONFIG_DIR"] = str(WORK / "conf")
sys.path.insert(0, str(ROOT))

import Bot as b  # noqa: E402

TEMPLATE = (
    "vless://00000000-0000-0000-0000-000000000000@45.67.89.10:443?type=tcp&security=reality"
    "&pbk=PUBKEY&fp=chrome&sni=www.microsoft.com&sid=533a&spx=%2F&flow=xtls-rprx-vision#xray"
)
XRAY_CONFIG = {
    "inbounds": [{
        "port": 443,
        "protocol": "vless",
        "settings": {"clients": [{"id": "00000000-0000-0000-0000-000000000000", "level": 0,
                                  "email": "client@example.com", "flow": "xtls-rprx-vision"}],
                     "decryption": "none"},
    }],
    "outbounds": [{"protocol": "freedom", "settings": {}}],
}


class FakeTelegram(http.server.BaseHTTPRequestHandler):
    updates = []
    sent = []
    next_id = 1

    def do_POST(self):
        match = re.match(r"^/botTEST:TOKEN/(\w+)$", self.path)
        params = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
        if not match:
            return self.answer(401, {"ok": False, "description": "Unauthorized"})
        method = match.group(1)
        if method == "getMe":
            result = {"id": 1, "is_bot": True, "username": "TestBot"}
        elif method == "getUpdates":
            result = [u for u in FakeTelegram.updates if u["update_id"] >= params.get("offset", 0)]
        elif method == "sendMessage":
            FakeTelegram.sent.append(params)
            result = {"message_id": 1}
        else:
            result = True
        self.answer(200, {"ok": True, "result": result})

    def answer(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def message(user_id, text, chat_type="private", username=None):
    update = {
        "update_id": FakeTelegram.next_id,
        "message": {
            "message_id": FakeTelegram.next_id,
            "from": {"id": user_id, "is_bot": False, "first_name": "User{}".format(user_id),
                     "username": username or "user{}".format(user_id)},
            "chat": {"id": user_id if chat_type == "private" else -5, "type": chat_type},
            "text": text,
        },
    }
    FakeTelegram.next_id += 1
    FakeTelegram.updates.append(update)


def run_once(*updates):
    """Queue messages, run one polling round and return the replies, keyed by chat."""
    for upd in updates:
        message(*upd)
    FakeTelegram.sent.clear()
    with contextlib.redirect_stdout(io.StringIO()):
        assert b.main(["run", "--once"]) == 0
    replies = {}
    for sent in FakeTelegram.sent:
        replies.setdefault(sent["chat_id"], []).append(sent["text"])
    return replies


def xray_clients():
    return json.loads((WORK / "config.json").read_text())["inbounds"][0]["settings"]["clients"]


def code_in(text):
    return re.search(r"https://t\.me/TestBot\?start=([A-Za-z0-9_-]+)", text).group(1)


def cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert b.main(list(argv)) == 0
    return out.getvalue()


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeTelegram)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    (WORK / "config.json").write_text(json.dumps(XRAY_CONFIG, indent=1))
    (WORK / "links.txt").write_text("[2026-11-22] VLESS xray: {}\n".format(TEMPLATE))
    os.environ.update({
        "TELEGRAM_BOT_TOKEN": "TEST:TOKEN",
        "TELEGRAM_API": "http://127.0.0.1:{}".format(server.server_port),
        "XRAY_CONFIG": str(WORK / "config.json"),
        "XRAY_LINK_FILE": str(WORK / "links.txt"),
        "XRAY_RESTART_CMD": "sh -c 'echo x >> restarts'",
        "BOT_LANGUAGE": "en",
    })

    # The first admin joins with an invite made on the command line.
    admin_code = code_in(cli("invite", "--admin"))
    replies = run_once((100, "/start " + admin_code))
    assert "You are an admin" in replies[100][0]
    links = re.findall(r"vless://[^<\s]+", replies[100][0])
    assert len(links) == 1
    admin_uuid = links[0].split("://")[1].split("@")[0]
    assert links[0].endswith("#user100") and "pbk=PUBKEY" in links[0] and "@45.67.89.10:443?" in links[0]
    clients = xray_clients()
    assert clients[0]["email"] == "client@example.com", "the server's own user is kept"
    assert clients[1] == {"id": admin_uuid, "level": 0, "email": "tg100", "flow": "xtls-rprx-vision"}
    assert (WORK / "restarts").read_text().count("x") == 1
    assert (WORK / "config.json.bak").exists()
    assert stat.S_IMODE(b.STORE_FILE.stat().st_mode) == 0o600

    # Strangers, reused codes, group chats and garbage get no answer.
    replies = run_once((200, "/config"), (201, "/start " + admin_code), (202, "/start nonsense"),
                       (100, "/config", "group"), (203, "hello"))
    assert replies == {}, replies

    # The admin invites a member, who joins once; the code is single-use.
    replies = run_once((100, "/invite"))
    code = code_in(replies[100][0])
    replies = run_once((300, "/start " + code), (301, "/start " + code))
    assert "Welcome!" in replies[300][0] and "You are an admin" not in replies[300][0]
    assert 301 not in replies
    member_uuid = re.search(r"vless://([0-9a-f-]{36})@", replies[300][0]).group(1)
    assert member_uuid != admin_uuid
    assert [c["email"] for c in xray_clients()] == ["client@example.com", "tg100", "tg300"]

    # Members get their own link back, and no admin commands.
    replies = run_once((300, "/config"), (300, "/invite"), (300, "hi"), (300, "/users"))
    assert member_uuid in replies[300][0]
    assert replies[300][1].startswith("Unknown command") and "/revoke" not in replies[300][1]
    assert "/config" in replies[300][2] and "Admin" not in replies[300][2]
    assert replies[300][3].startswith("Unknown command")

    # /new_config swaps the member's UUID; /config then returns the new link.
    replies = run_once((300, "/new_config"))
    assert "old link has stopped working" in replies[300][0]
    renewed_uuid = re.search(r"vless://([0-9a-f-]{36})@", replies[300][0]).group(1)
    assert renewed_uuid != member_uuid
    emails = {c["email"]: c["id"] for c in xray_clients()}
    assert emails["tg300"] == renewed_uuid and member_uuid not in emails.values()
    assert renewed_uuid in run_once((300, "/config"))[300][0]
    replies = run_once((300, "/new_config"))
    assert "once every 10 minutes" in replies[300][0] and "Try again in 10 min" in replies[300][0]
    assert {c["email"]: c["id"] for c in xray_clients()}["tg300"] == renewed_uuid
    member_uuid = renewed_uuid

    # A member opening a second normal invite does not use it up.
    replies = run_once((100, "/invite"))
    spare = code_in(replies[100][0])
    replies = run_once((300, "/start " + spare), (302, "/start " + spare))
    assert member_uuid in replies[300][0] and "Welcome!" in replies[302][0]

    # Admin lists and revokes.
    replies = run_once((100, "/users"), (100, "/revoke 300"), (100, "/revoke 100"), (100, "/revoke 999"))
    assert "300 User300 @user300" in replies[100][0] and "(admin)" in replies[100][0]
    assert "Removed User300" in replies[100][1]
    assert "can't revoke yourself" in replies[100][2]
    assert "No member with id 999" in replies[100][3]
    assert "tg300" not in [c["email"] for c in xray_clients()]
    assert run_once((300, "/config")) == {}, "a revoked member is a stranger again"

    # If xray cannot be restarted, nobody joins and the invite stays valid.
    replies = run_once((100, "/invite"))
    code = code_in(replies[100][0])
    os.environ["XRAY_RESTART_CMD"] = "false"
    before = (WORK / "config.json").read_text()
    assert run_once((400, "/start " + code)) == {}
    assert "400" not in b.load_store()["users"] and code in b.load_store()["invites"]
    assert (WORK / "config.json").read_text() == before, "a failed restart puts the old config back"
    with b.store_lock() as store:
        store["users"]["100"]["renewed"] = 0
    replies = run_once((100, "/new_config"))
    assert "went wrong" in replies[100][0]
    assert b.load_store()["users"]["100"]["uuid"] == admin_uuid
    assert (WORK / "config.json").read_text() == before
    os.environ["XRAY_RESTART_CMD"] = "true"
    replies = run_once((400, "/start " + code))
    assert "Welcome!" in replies[400][0]
    assert [c["email"] for c in xray_clients()].count("tg400") == 1

    # Persian.
    os.environ["BOT_LANGUAGE"] = "fa"
    replies = run_once((100, "/config"), (100, "/help"), (100, "/revoke 999"), (400, "/nope"))
    assert "این لینک شخصی شماست" in replies[100][0] and admin_uuid in replies[100][0]
    assert "/new_config" in replies[100][1] and "مدیریت" in replies[100][1]
    assert "عضوی با شناسهٔ 999" in replies[100][2]
    assert replies[400][0].startswith("دستور ناشناخته") and "مدیریت" not in replies[400][0]
    os.environ["BOT_LANGUAGE"] = "xx"
    with contextlib.redirect_stderr(io.StringIO()) as err:
        try:
            b.main(["users"])
            raise AssertionError("expected exit")
        except SystemExit:
            pass
    assert "BOT_LANGUAGE" in err.getvalue()
    os.environ["BOT_LANGUAGE"] = "en"

    # Expired invites do nothing.
    with b.store_lock() as store:
        code = b.new_invite(store, b.load_settings())
        store["invites"][code]["expires"] = int(time.time()) - 1
    assert run_once((500, "/start " + code)) == {}

    # A malformed update is skipped instead of stopping the bot.
    FakeTelegram.updates.append({"update_id": FakeTelegram.next_id, "message": {"chat": {"type": "private"}}})
    FakeTelegram.next_id += 1
    assert run_once((100, "/config"))[100]
    assert b.load_store()["offset"] == FakeTelegram.next_id

    # CLI.
    out = cli("users")
    assert "100 User100" in out and "400 User400" in out
    assert "Removed" in cli("revoke", "400")
    assert "tg400" not in [c["email"] for c in xray_clients()]

    # Wrong token and loose permissions fail clearly.
    os.environ["TELEGRAM_BOT_TOKEN"] = "WRONG"
    with contextlib.redirect_stderr(io.StringIO()) as err:
        try:
            b.main(["invite"])
            raise AssertionError("expected exit")
        except SystemExit:
            pass
    assert "401" in err.getvalue() and "WRONG" not in err.getvalue()
    os.environ["TELEGRAM_BOT_TOKEN"] = "TEST:TOKEN"
    b.CONFIG_FILE.write_text("BOT_INVITE_DAYS=3\n")
    os.chmod(b.CONFIG_FILE, 0o644)
    with contextlib.redirect_stderr(io.StringIO()) as err:
        try:
            b.main(["users"])
            raise AssertionError("expected exit")
        except SystemExit:
            pass
    assert "chmod 600" in err.getvalue()

    server.shutdown()
    print("all bot checks passed")


if __name__ == "__main__":
    main()
