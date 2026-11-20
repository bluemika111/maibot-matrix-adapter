"""Matrix 适配器离线自检：不连接真实服务器，验证消息映射与关键逻辑。"""

import asyncio
import base64
import importlib.util
import logging
import sys
import types
from pathlib import Path
from types import SimpleNamespace

PLUGIN_PATH = Path(__file__).resolve().parent.parent / "plugin.py"


def _install_mocks() -> None:
    """注入 maibot_sdk 与 nio 的最小 mock。"""

    sdk = types.ModuleType("maibot_sdk")

    class PluginConfigBase:
        pass

    class MaiBotPlugin:
        def __init__(self) -> None:
            self._ctx = None

    def Field(default=None, default_factory=None, description=""):
        del description
        return default if default_factory is None else default_factory

    def MessageGateway(*args, **kwargs):
        del args, kwargs

        def decorator(fn):
            return fn

        return decorator

    sdk.PluginConfigBase = PluginConfigBase
    sdk.MaiBotPlugin = MaiBotPlugin
    sdk.Field = Field
    sdk.MessageGateway = MessageGateway
    sys.modules["maibot_sdk"] = sdk

    nio = types.ModuleType("nio")

    class _Base:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    for name in [
        "AsyncClient",
        "AsyncClientConfig",
        "DownloadError",
        "JoinError",
        "KeysClaimError",
        "KeysQueryError",
        "KeysUploadError",
        "LoginError",
        "MatrixRoom",
        "MegolmEvent",
        "ReactionEvent",
        "RedactionEvent",
        "RoomCreateError",
        "RoomEncryptedMedia",
        "RoomEncryptionEvent",
        "RoomMessageEmote",
        "RoomMessageMedia",
        "RoomMessageNotice",
        "RoomMessageText",
        "RoomPreset",
        "RoomSendError",
        "SyncError",
        "UploadError",
    ]:
        setattr(nio, name, type(name, (_Base,), {}))
    sys.modules["nio"] = nio

    crypto = types.ModuleType("nio.crypto")
    attachments = types.ModuleType("nio.crypto.attachments")
    attachments.decrypt_attachment = lambda data, key, hash_, iv: data
    crypto.attachments = attachments
    sys.modules["nio.crypto"] = crypto
    sys.modules["nio.crypto.attachments"] = attachments


def _load_plugin():
    """加载插件模块。"""

    spec = importlib.util.spec_from_file_location("matrix_adapter_plugin", PLUGIN_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 plugin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_config(module):
    """构造测试用配置。"""

    return SimpleNamespace(
        plugin=SimpleNamespace(enabled=True, config_version="0.1.0"),
        connection=SimpleNamespace(
            homeserver="https://matrix.example.com",
            user_id="@bot:example.com",
            password="secret",
            device_id="DEV1",
            device_name="MaiBot",
            enable_e2ee=True,
            store_path="",
            request_timeout=60,
        ),
        behavior=SimpleNamespace(
            auto_join_invites=True,
            allowed_rooms=[],
            sync_timeout_ms=30000,
            max_media_bytes=1024 * 1024,
            ignore_unverified_devices=True,
            reply_enabled=True,
            send_read_receipts=False,
            room_name_refresh_seconds=300,
            mention_keywords=["麦麦"],
        ),
    )


class FakeNioClient:
    """模拟 matrix-nio 客户端。"""

    def __init__(self) -> None:
        self.rooms = {}
        self.olm = object()
        self.sent = []
        self.uploads = []

    async def room_send(self, room_id, message_type, content, ignore_unverified_devices=False):
        del ignore_unverified_devices
        self.sent.append((room_id, message_type, content))
        return SimpleNamespace(event_id="$sent" + str(len(self.sent)))

    async def download(self, mxc=None):
        del mxc
        return SimpleNamespace(body=b"binary-data")

    async def upload(self, payload, content_type="", filename="", encrypt=False):
        self.uploads.append((payload, content_type, filename, encrypt))
        info = {"key": "k", "iv": "i", "hashes": {"sha256": "h"}, "v": "v2"} if encrypt else None
        return SimpleNamespace(content_uri="mxc://example.com/abc"), info

    async def room_create(self, **kwargs):
        del kwargs
        return SimpleNamespace(room_id="!newdm:example.com")

    async def list_direct_rooms(self):
        return SimpleNamespace(rooms={"@alice:example.com": ["!dm:example.com"]})

    async def room_read_markers(self, *args, **kwargs):
        del args, kwargs
        return None


def _make_room(module, room_id="!room:example.com", members=3, encrypted=False, name="测试群"):
    """构造模拟房间。"""

    users = {"@bot:example.com": object(), "@alice:example.com": object()}
    if members > 2:
        users["@bob:example.com"] = object()
    return SimpleNamespace(
        room_id=room_id,
        member_count=members,
        users=users,
        display_name=name,
        encrypted=encrypted,
    )


def _make_text_event(module, body="你好", content=None, sender="@alice:example.com", event_id="$evt1"):
    """构造模拟文本事件。"""

    payload = content if content is not None else {"msgtype": "m.text", "body": body}
    event = module.RoomMessageText()
    event.sender = sender
    event.event_id = event_id
    event.server_timestamp = 1700000000000
    event.body = body
    event.source = {"content": payload}
    return event


def _make_image_event(module, url="mxc://example.com/img", mime="image/png", encrypted=False):
    """构造模拟图片事件。"""

    cls = module.RoomEncryptedMedia if encrypted else module.RoomMessageMedia
    event = cls()
    event.sender = "@alice:example.com"
    event.event_id = "$img1"
    event.server_timestamp = 1700000000000
    event.body = "photo.png"
    event.url = url
    event.source = {"content": {"msgtype": "m.image", "body": "photo.png", "info": {"mimetype": mime}}}
    if encrypted:
        event.key = {"k": "key"}
        event.iv = "iv"
        event.hashes = {"sha256": "hash"}
    return event


async def _run_checks(module) -> None:
    """执行全部自检。"""

    config = _build_config(module)
    inbound_messages = []

    async def inbound_callback(message):
        inbound_messages.append(message)
        return True

    client = module.MatrixClient(
        config=config,
        data_dir=Path("."),
        logger=logging.getLogger("matrix-adapter-test"),
        inbound_callback=inbound_callback,
    )
    client._user_id = "@bot:example.com"
    client._scope = "matrix.example.com"
    client._ready = True
    fake = FakeNioClient()
    client._client = fake

    # 1. 房间号归一化：零宽字符与不带 :server 的写法
    fake.rooms = {"!abc:example.com": _make_room(module, room_id="!abc:example.com")}
    assert client._normalize_room_id("!abc") == "!abc:example.com"
    assert client._normalize_room_id("!abc\u200b:example.com") == "!abc:example.com"
    assert client._normalize_room_id("!abc:example.com") == "!abc:example.com"

    # 2. 群聊文本入站
    room = _make_room(module)
    message = await client._build_inbound_message(room, _make_text_event(module))
    assert message is not None
    assert message["platform"] == "matrix"
    assert message["account_id"] == "@bot:example.com"
    assert message["scope"] == "matrix.example.com"
    assert message["message_info"]["group_info"]["group_id"] == "!room:example.com"
    assert message["message_info"]["group_info"]["group_name"] == "测试群"
    assert message["raw_message"] == [{"type": "text", "data": "你好"}]
    assert message["is_mentioned"] is False

    # 3. 回复 + @ 提及
    reply_event = _make_text_event(
        module,
        body="麦麦你好",
        content={
            "msgtype": "m.text",
            "body": "麦麦你好",
            "m.relates_to": {"m.in_reply_to": {"event_id": "$prev"}},
            "m.mentions": {"user_ids": ["@bot:example.com"]},
        },
    )
    message = await client._build_inbound_message(room, reply_event)
    assert message is not None
    assert message["reply_to"] == "$prev"
    assert message["is_mentioned"] is True
    assert message["raw_message"][0] == {"type": "reply", "data": {"target_message_id": "$prev"}}
    assert message["raw_message"][1] == {"type": "text", "data": "麦麦你好"}

    # 4. 私聊房间：两人房间不写 group_info
    dm_room = _make_room(module, room_id="!dm:example.com", members=2, encrypted=True)
    message = await client._build_inbound_message(dm_room, _make_text_event(module, body="私聊"))
    assert message is not None
    assert "group_info" not in message["message_info"]
    assert message["message_info"]["additional_config"]["matrix_encrypted"] is True

    # 5. 图片入站（未加密）
    message = await client._build_inbound_message(room, _make_image_event(module))
    assert message is not None
    assert message["is_picture"] is True
    image_component = message["raw_message"][0]
    assert image_component["type"] == "image"
    assert image_component["data"] == "mxc://example.com/img"
    assert base64.b64decode(image_component["binary_data_base64"]) == b"binary-data"

    # 6. 出站文本（群聊）
    result = await client.send_message(
        {
            "message_info": {
                "group_info": {"group_id": "!room:example.com", "group_name": "测试群"},
                "user_info": {"user_id": "@alice:example.com", "user_nickname": "Alice"},
            },
            "raw_message": [{"type": "text", "data": "回复内容"}],
        }
    )
    assert result["success"] is True
    assert fake.sent[-1][0] == "!room:example.com"
    assert fake.sent[-1][2]["msgtype"] == "m.text"
    assert fake.sent[-1][2]["body"] == "回复内容"

    # 7. 出站回复
    result = await client.send_message(
        {
            "message_info": {"group_info": {"group_id": "!room:example.com", "group_name": "测试群"}},
            "raw_message": [
                {"type": "reply", "data": {"target_message_id": "$prev"}},
                {"type": "text", "data": "带回复"},
            ],
        }
    )
    assert result["success"] is True
    assert fake.sent[-1][2]["m.relates_to"]["m.in_reply_to"]["event_id"] == "$prev"

    # 8. 出站图片（未加密房间走 url 字段）
    result = await client.send_message(
        {
            "message_info": {"group_info": {"group_id": "!room:example.com", "group_name": "测试群"}},
            "raw_message": [
                {
                    "type": "image",
                    "data": "mxc://example.com/src",
                    "binary_data_base64": base64.b64encode(b"img-bytes").decode("ascii"),
                }
            ],
        }
    )
    assert result["success"] is True
    assert fake.sent[-1][2]["msgtype"] == "m.image"
    assert fake.sent[-1][2]["url"] == "mxc://example.com/abc"
    assert fake.uploads[-1][3] is False

    # 9. 出站图片（加密房间走 file 字段并加密上传）
    client._encrypted_rooms.add("!room:example.com")
    result = await client.send_message(
        {
            "message_info": {"group_info": {"group_id": "!room:example.com", "group_name": "测试群"}},
            "raw_message": [
                {
                    "type": "image",
                    "data": "mxc://example.com/src",
                    "binary_data_base64": base64.b64encode(b"img-bytes").decode("ascii"),
                }
            ],
        }
    )
    assert result["success"] is True
    assert fake.uploads[-1][3] is True
    assert fake.sent[-1][2]["file"]["url"] == "mxc://example.com/abc"
    assert "url" not in fake.sent[-1][2]

    # 10. 私聊出站：命中已有 DM 房间
    fake.rooms["!dm:example.com"] = dm_room
    result = await client.send_message(
        {
            "message_info": {"user_info": {"user_id": "@alice:example.com", "user_nickname": "Alice"}},
            "raw_message": [{"type": "text", "data": "私聊回复"}],
        }
    )
    assert result["success"] is True
    assert fake.sent[-1][0] == "!dm:example.com"

    # 11. 转发消息拍平
    flattened = client._flatten_forward(
        [
            {"user_nickname": "Alice", "content": [{"type": "text", "data": "第一句"}]},
            {"user_nickname": "Bob", "content": [{"type": "text", "data": "第二句"}]},
        ]
    )
    assert flattened == "Alice: 第一句\nBob: 第二句"

    # 12. 房间白名单
    client._config.behavior.allowed_rooms = ["!room:example.com"]
    assert client._is_room_allowed("!room:example.com") is True
    assert client._is_room_allowed("!other:example.com") is False

    print("ALL CHECKS PASSED")


def main() -> None:
    """入口。"""

    _install_mocks()
    module = _load_plugin()
    asyncio.run(_run_checks(module))


if __name__ == "__main__":
    main()
