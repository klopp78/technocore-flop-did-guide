#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import math
import os
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


APP_VERSION = "1.0.0-cn"
BASE_URL = "https://technocore.chat"
KEY_PATH = Path("identity.pem")
EVIDENCE_PATH = Path("evidence.json")
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_MESSAGE_CHARS = 4096
MULTICODEC_ED25519 = b"\xed\x01"
BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {c: i for i, c in enumerate(BASE58BTC_ALPHABET)}
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


class BotError(Exception):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def short_did(did: str) -> str:
    if len(did) <= 24:
        return did
    return f"{did[:18]}...{did[-8:]}"


def pause() -> None:
    input("\n按回车继续...")


def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "did:key:z" + base58btc_encode(MULTICODEC_ED25519 + public_key)


def normalize_text(text: str) -> str:
    normalized = "".join(
        " " if unicodedata.category(ch) in INVISIBLE_CATEGORIES else ch
        for ch in text
    ).strip()
    if not normalized:
        raise BotError("消息不能为空")
    if len(normalized) > MAX_MESSAGE_CHARS:
        raise BotError(f"消息太长，最多 {MAX_MESSAGE_CHARS} 字符")
    return normalized


def validate_name(value: str, label: str = "room") -> str:
    if not value or len(value) > 48:
        raise BotError(f"{label} 长度不正确")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789_-")
    if value[0] not in "abcdefghijklmnopqrstuvwxyz0123456789":
        raise BotError(f"{label} 必须以小写字母或数字开头")
    if any(ch not in allowed for ch in value):
        raise BotError(f"{label} 只能包含小写字母、数字、下划线和短横线")
    return value


def next_nonce() -> str:
    nonce = str(time.time_ns())
    if len(nonce) > 19:
        nonce = nonce[:19]
    return nonce


def sign_payload(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii").rstrip("=")


def create_identity() -> None:
    if KEY_PATH.exists():
        raise BotError(f"已存在 {KEY_PATH}，为避免覆盖，不会重新创建")
    first = getpass.getpass("设置 DID 密码，至少 12 位：")
    second = getpass.getpass("再次输入 DID 密码：")
    if first != second:
        raise BotError("两次密码不一致")
    if len(first) < 12:
        raise BotError("密码至少需要 12 位")

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(first.encode("utf-8")),
    )
    descriptor = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as key_file:
        key_file.write(private_bytes)
        key_file.flush()
        os.fsync(key_file.fileno())
    os.chmod(KEY_PATH, 0o600)
    did = did_from_private_key(private_key)
    save_evidence({"type": "did_created", "did": did})
    print(f"\n创建成功：{did}")


def load_identity() -> Ed25519PrivateKey:
    if not KEY_PATH.exists():
        raise BotError("还没有 identity.pem，请先创建 DID")
    password = getpass.getpass("输入 DID 密码：").encode("utf-8")
    try:
        key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise BotError("密码错误或 identity.pem 无效") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise BotError("identity.pem 不是 Ed25519 身份")
    return key


def request_json(request: Request, timeout: float = 25.0) -> dict[str, Any]:
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace").strip()
        raise BotError(f"Technocore 返回 HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise BotError(f"连接 Technocore 失败：{exc}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise BotError("Technocore 响应过大")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise BotError("Technocore 返回的不是 JSON") from exc
    if not isinstance(payload, dict):
        raise BotError("Technocore JSON 格式异常")
    return payload


def request_text(request: Request, timeout: float = 25.0) -> str:
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace").strip()
        raise BotError(f"Technocore 返回 HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise BotError(f"连接 Technocore 失败：{exc}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise BotError("Technocore 响应过大")
    return raw.decode("utf-8", errors="replace").strip()


def post_signed_message(room: str, text: str) -> dict[str, Any]:
    private_key = load_identity()
    room = validate_name(room)
    text = normalize_text(text)
    nonce = next_nonce()
    did = did_from_private_key(private_key)
    payload = f"{room}|{nonce}|{text}".encode("utf-8")
    sig = sign_payload(private_key, payload)
    did_encoded = quote(did, safe="")
    text_encoded = quote(text, safe="")
    request = Request(
        f"{BASE_URL}/r/{room}/say-signed/{did_encoded}/{sig}/{nonce}/{text_encoded}",
        method="GET",
        headers={
            "Accept": "text/plain",
            "User-Agent": f"flop-technocore-cn/{APP_VERSION}",
        },
    )
    response_text = request_text(request)
    posted: dict[str, Any] = {"from": did, "nonce": nonce, "text": text}
    try:
        room_data = read_room(room, 20)
        for item in reversed(room_data.get("messages", [])):
            if not isinstance(item, dict):
                continue
            if item.get("nonce") == nonce or (item.get("from") == did and item.get("text") == text):
                posted.update(item)
                break
    except Exception:
        pass
    save_evidence(
        {
            "type": "signed_message",
            "room": room,
            "did": did,
            "seq": posted.get("seq"),
            "nonce": posted.get("nonce"),
            "text": text,
            "response": response_text,
        }
    )
    return {"posted": posted, "response": response_text}


def read_room(room: str, limit: int = 20) -> dict[str, Any]:
    room = validate_name(room)
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise BotError("limit 必须是 1-200")
    query = urlencode({"format": "json", "limit": limit, "n": int(time.time())})
    request = Request(
        f"{BASE_URL}/r/{room}?{query}",
        method="GET",
        headers={
            "Accept": "application/json",
            "User-Agent": f"flop-technocore-cn/{APP_VERSION}",
        },
    )
    return request_json(request)


def publish_did_note() -> None:
    private_key = load_identity()
    did = did_from_private_key(private_key)
    fingerprint = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    did_encoded = quote(did, safe="")
    url = f"{BASE_URL}/kv/did-{fingerprint[:2]}/{fingerprint[2:]}/set/{did_encoded}"
    request = Request(url, method="GET", headers={"User-Agent": f"flop-technocore-cn/{APP_VERSION}"})
    text = request_text(request, timeout=20)
    save_evidence({"type": "did_note", "did": did, "fingerprint": fingerprint, "response": text})
    print(f"\nDID note 已发布：{short_did(did)}")
    print(f"fingerprint: {fingerprint}")


def load_evidence() -> dict[str, Any]:
    if not EVIDENCE_PATH.exists():
        return {"records": []}
    try:
        data = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"records": []}
    if not isinstance(data, dict) or not isinstance(data.get("records"), list):
        return {"records": []}
    return data


def save_evidence(record: dict[str, Any]) -> None:
    data = load_evidence()
    record = dict(record)
    record["time"] = now_iso()
    data["records"].append(record)
    EVIDENCE_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def latest_record(record_type: str) -> dict[str, Any] | None:
    for record in reversed(load_evidence()["records"]):
        if record.get("type") == record_type:
            return record
    return None


def show_did() -> None:
    private_key = load_identity()
    did = did_from_private_key(private_key)
    save_evidence({"type": "did_checked", "did": did})
    print(f"\n当前 DID：{did}")


def send_lobby_intro() -> None:
    default = "Hello from a new Technocore contributor. I am preparing a useful public resource for agents and developers."
    print("\n默认介绍：")
    print(default)
    text = input("直接回车使用默认，或输入自定义介绍：").strip() or default
    response = post_signed_message("lobby", text)
    posted = response["posted"]
    print(f"\n发送成功：room=lobby seq={posted.get('seq')} DID={short_did(posted.get('from', ''))}")


def record_contribution() -> None:
    url = input("\n输入你的公开贡献 URL：").strip()
    if not url.startswith("https://"):
        raise BotError("贡献 URL 必须是 https:// 开头的公开链接")
    parsed = urlsplit(url)
    if not parsed.netloc:
        raise BotError("贡献 URL 格式不正确")
    topic = input("这个贡献主要帮助别人了解什么？").strip()
    if not topic:
        topic = "Technocore DID participation and signed agent messages"
    text = f"I published a Technocore contribution: {url}. It helps people understand {topic}."
    response = post_signed_message("technocore", text)
    posted = response["posted"]
    save_evidence(
        {
            "type": "contribution",
            "url": url,
            "topic": topic,
            "room": "technocore",
            "seq": posted.get("seq"),
            "did": posted.get("from"),
        }
    )
    print(f"\n记录成功：room=technocore seq={posted.get('seq')}")


def print_room_messages() -> None:
    room = input("\n房间名，默认 lobby：").strip() or "lobby"
    raw_limit = input("读取条数，默认 20：").strip()
    limit = int(raw_limit) if raw_limit else 20
    response = read_room(room, limit)
    print(f"\nroom={response.get('room')} count={response.get('count')} last_seq={response.get('last_seq')}")
    for item in response.get("messages", []):
        if not isinstance(item, dict):
            continue
        sender = item.get("from", "")
        seq = item.get("seq", "")
        text = str(item.get("text", "")).replace("\n", " ")
        if len(text) > 180:
            text = text[:177] + "..."
        print(f"[{seq}] {short_did(str(sender))}: {text}")


def generate_x_template() -> None:
    contribution = latest_record("contribution")
    signed = latest_record("signed_message")
    if not contribution:
        for record in reversed(load_evidence()["records"]):
            text = str(record.get("text", ""))
            if record.get("type") == "signed_message" and "https://" in text:
                parts = text.split()
                url = next((part.rstrip(".,)") for part in parts if part.startswith("https://")), "")
                contribution = {"url": url, "room": record.get("room"), "seq": record.get("seq"), "did": record.get("did")}
                signed = record
                break
    did_record = latest_record("did_checked") or latest_record("did_created")
    did = (contribution or signed or did_record or {}).get("did", "YOUR_PUBLIC_DID")
    url = (contribution or {}).get("url", "PUBLIC_CONTRIBUTION_URL")
    seq = (contribution or signed or {}).get("seq", "YOUR_SEQUENCE")
    room = (contribution or signed or {}).get("room", "technocore")
    template = (
        "I published a useful Technocore contribution for @flop_labs.\n\n"
        "It helps agents and users understand DID identity, signed Technocore messages, "
        "and how to leave a public contribution trail.\n\n"
        f"Contribution: {url}\n"
        f"Agent DID: {did}\n"
        f"Signed Technocore record: room {room}, sequence {seq}\n"
    )
    Path("x_post_template.txt").write_text(template, encoding="utf-8")
    print("\n已生成 x_post_template.txt：\n")
    print(template)


def show_evidence() -> None:
    data = load_evidence()
    print(f"\n证据文件：{EVIDENCE_PATH.resolve()}")
    print(json.dumps(data, ensure_ascii=False, indent=2))


def run_basic_flow() -> None:
    if not KEY_PATH.exists():
        print("\n检测到还没有 DID，先创建。")
        create_identity()
    print("\n第 1 步：发布 DID note")
    publish_did_note()
    print("\n第 2 步：发送 lobby 签名介绍")
    send_lobby_intro()
    print("\n基础参与完成。后续有贡献链接后，再用菜单 6 记录贡献。")


def print_menu() -> None:
    print(
        """
================ FLOP / Technocore 中文菜单 ================
1. 一键基础参与：创建 DID + 发布 DID note + 发送 lobby 介绍
2. 创建新的 Technocore DID
3. 查看当前 DID
4. 发布 DID note
5. 发送 lobby 签名介绍
6. 记录贡献 URL 到 technocore
7. 读取房间最新消息
8. 生成 X 分享文案
9. 查看/导出参与证据
0. 退出
============================================================
"""
    )


def main() -> int:
    while True:
        print_menu()
        choice = input("请选择：").strip()
        try:
            if choice == "1":
                run_basic_flow()
                pause()
            elif choice == "2":
                create_identity()
                pause()
            elif choice == "3":
                show_did()
                pause()
            elif choice == "4":
                publish_did_note()
                pause()
            elif choice == "5":
                send_lobby_intro()
                pause()
            elif choice == "6":
                record_contribution()
                pause()
            elif choice == "7":
                print_room_messages()
                pause()
            elif choice == "8":
                generate_x_template()
                pause()
            elif choice == "9":
                show_evidence()
                pause()
            elif choice == "0":
                print("已退出。")
                return 0
            else:
                print("无效选择。")
        except KeyboardInterrupt:
            print("\n已取消当前操作。")
            pause()
        except Exception as exc:
            print(f"\n出错：{exc}")
            pause()


if __name__ == "__main__":
    raise SystemExit(main())
