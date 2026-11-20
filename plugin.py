"""Matrix 适配器插件。

通过 Matrix Client-Server API 接入任意 Matrix 服务器：用户名密码登录、
端到端加密（vodozemac）、文本/图片/文件/回复消息的双向路由。

设计要点（来自实际 E2EE 排障经验）：
1. device_id 必须持久化且稳定，加密库按 device_id 隔离，换设备不能复用旧库；
2. 房间是否加密不能只依赖加密机内存表，需自己从 state 事件累积并持久化；
3. 部分服务器（如 tuwunel 2.0）返回的房间号不带 :server，发送前要归一化；
4. 一次性密钥（OTK）交给 matrix-nio 自动管理，不做大规模循环 claim。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

import asyncio
import base64
import logging
import mimetypes
import os
import secrets
import time

from maibot_sdk import Field, MaiBotPlugin, MessageGateway, PluginConfigBase

try:
    from nio import (
        AsyncClient,
        AsyncClientConfig,
        DownloadError,
        JoinError,
        KeysClaimError,
        KeysQueryError,
        KeysUploadError,
        LoginError,
        MatrixRoom,
        MegolmEvent,
        ReactionEvent,
        RedactionEvent,
        RoomCreateError,
        RoomEncryptedMedia,
        RoomEncryptionEvent,
        RoomMessageEmote,
        RoomMessageMedia,
        RoomMessageNotice,
        RoomMessageText,
        RoomPreset,
        RoomSendError,
        SyncError,
        UploadError,
    )
    from nio.crypto.attachments import decrypt_attachment

    _NIO_IMPORT_ERROR: Optional[BaseException] = None
except ImportError as exc:  # pragma: no cover - 依赖缺失时给出明确提示
    _NIO_IMPORT_ERROR = exc


GATEWAY_NAME = "matrix_gateway"
PLATFORM_NAME = "matrix"
PROTOCOL_NAME = "matrix-cs-api"

# 零宽字符与不换行空格，部分服务器会在房间号里混入这些字符
_INVISIBLE_CHARS = (chr(0x200B), chr(0x200C), chr(0x200D), chr(0xFEFF), chr(0x00A0))


class MatrixPluginSectionConfig(PluginConfigBase):
    """插件基础配置。"""

    __ui_label__ = "插件"
    __ui_icon__ = "package"
    __ui_order__ = 0

    enabled: bool = Field(default=False, description="是否启用 Matrix 适配器")
    config_version: str = Field(default="0.1.0", description="配置版本")


class MatrixConnectionConfig(PluginConfigBase):
    """Matrix 连接配置。"""

    __ui_label__ = "连接"
    __ui_icon__ = "server"
    __ui_order__ = 1

    homeserver: str = Field(
        default="https://matrix.org",
        description="Matrix 服务器地址，例如 https://matrix.example.com（任意标准 CS API 服务器）",
    )
    user_id: str = Field(
        default="@maibot:matrix.org",
        description="机器人用户 ID：可填完整 ID（@maibot:example.com），也可只填用户名（maibot），由服务器补齐",
    )
    password: str = Field(default="", description="登录密码，用于换取访问令牌")
    device_id: str = Field(
        default="",
        description="设备 ID；留空时自动生成并持久化。请勿与手机等其它客户端共用同一设备 ID",
    )
    device_name: str = Field(default="MaiBot", description="设备显示名称")
    enable_e2ee: bool = Field(
        default=True,
        description="启用端到端加密（需要 matrix-nio[e2e] 与 vodozemac）",
    )
    store_path: str = Field(
        default="",
        description="加密库根目录；留空时使用插件数据目录下的 crypto_store/<device_id>",
    )
    request_timeout: int = Field(default=60, description="单次 HTTP 请求超时（秒）")


class MatrixBehaviorConfig(PluginConfigBase):
    """Matrix 行为配置。"""

    __ui_label__ = "行为"
    __ui_icon__ = "settings"
    __ui_order__ = 2

    auto_join_invites: bool = Field(default=True, description="收到邀请时自动加入房间")
    allowed_rooms: List[str] = Field(
        default_factory=list,
        description="允许接入的房间 ID 列表；留空表示全部房间",
    )
    sync_timeout_ms: int = Field(default=30000, description="sync 长轮询超时（毫秒）")
    max_media_bytes: int = Field(default=20971520, description="单条媒体消息大小上限（字节）")
    ignore_unverified_devices: bool = Field(
        default=True,
        description="加密房间中忽略未验证设备；关闭后可能因设备未验证而无法发送",
    )
    reply_enabled: bool = Field(default=True, description="把 Matrix 回复关系映射为 MaiBot 的 reply 组件")
    send_read_receipts: bool = Field(default=False, description="收到消息后发送已读回执")
    room_name_refresh_seconds: int = Field(default=300, description="房间名称缓存刷新间隔（秒）")
    mention_keywords: List[str] = Field(
        default_factory=list,
        description="额外的 @ 触发关键词；留空时使用机器人显示名与本地部分",
    )


class MatrixAdapterConfig(PluginConfigBase):
    """Matrix 适配器完整配置。"""

    plugin: MatrixPluginSectionConfig = Field(default_factory=MatrixPluginSectionConfig)
    connection: MatrixConnectionConfig = Field(default_factory=MatrixConnectionConfig)
    behavior: MatrixBehaviorConfig = Field(default_factory=MatrixBehaviorConfig)


def _sanitize_path_component(value: str) -> str:
    """把设备 ID 等值规范化为可安全用作目录名的片段。"""

    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value.strip())
    return cleaned or "default"


def _strip_invisible(value: str) -> str:
    """清掉房间号里可能混入的零宽字符与不换行空格。"""

    cleaned = value
    for char in _INVISIBLE_CHARS:
        cleaned = cleaned.replace(char, "")
    return cleaned.strip()


def _guess_image_mime(payload: bytes) -> str:
    """根据文件头猜测图片 MIME 类型。"""

    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if payload.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if payload.startswith(b"GIF8"):
        return "image/gif"
    if payload[:4] == b"RIFF" and payload[8:12] == b"WEBP":
        return "image/webp"
    return "image/png"


def _install_windows_store_patch() -> None:
    """修复 nio 在 Windows 上的存储文件名问题。

    nio 的 DefaultStore 用 f"{user_id}_{device_id}" 拼数据库与信任库文件名，
    而 user_id 含 "@" 与 ":"，Windows 不允许 ":"，会导致：
    - SQLite 实际把 ":" 后的部分写成 NTFS 数据流
    - 信任库 atomicwrites 的 MoveFileExW 报 WinError 123
    这里替换 DefaultStore.__post_init__，用安全化后的文件名重建数据库与信任库。
    """

    if os.name != "nt":
        return
    try:
        from nio.store.database import DefaultStore
        from nio.store.file_trustdb import KeyStore
    except ImportError:
        return
    if getattr(DefaultStore.__post_init__, "__name__", "") == "_patched_post_init":
        return

    def _safe(value: str) -> str:
        return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)

    def _patched_post_init(self: Any) -> None:
        self.database_name = self.database_name or f"{_safe(self.user_id)}_{_safe(self.device_id)}.db"
        self.database_path = os.path.join(self.store_path, self.database_name)
        self.database = self._create_database()
        self.database.connect()
        store_version = self._get_store_version()
        if store_version == 1:
            self.upgrade_to_v2()
        with self.database.bind_ctx(self.models):
            self.database.create_tables(self.models)
        for suffix, attribute in (
            (".trusted_devices", "trust_db"),
            (".blacklisted_devices", "blacklist_db"),
            (".ignored_devices", "ignore_db"),
        ):
            filename = os.path.join(self.store_path, f"{_safe(self.user_id)}_{_safe(self.device_id)}{suffix}")
            setattr(self, attribute, KeyStore(filename))

    DefaultStore.__post_init__ = _patched_post_init


class MatrixClient:
    """封装 Matrix 客户端生命周期、同步循环与消息收发。"""

    def __init__(
        self,
        *,
        config: MatrixAdapterConfig,
        data_dir: Path,
        logger: logging.Logger,
        inbound_callback: Callable[[Dict[str, Any]], Awaitable[bool]],
    ) -> None:
        """初始化 Matrix 客户端封装。

        Args:
            config: 插件配置。
            data_dir: 插件持久数据目录。
            logger: 插件日志器。
            inbound_callback: 入站消息回调，返回 Host 是否接受。
        """

        self._config = config
        self._data_dir = data_dir
        self._logger = logger
        self._inbound_callback = inbound_callback
        self._client: Optional[AsyncClient] = None
        self._sync_task: Optional[asyncio.Task[None]] = None
        self._running = False
        self._ready = False
        self._user_id = ""
        self._device_id = ""
        self._scope = ""
        self._encrypted_rooms: Set[str] = set()
        self._direct_rooms: Set[str] = set()
        self._room_name_cache: Dict[str, Tuple[str, float]] = {}
        self._mention_keywords: List[str] = []

    @property
    def user_id(self) -> str:
        """返回当前登录的 Matrix 用户 ID。"""

        return self._user_id

    @property
    def scope(self) -> str:
        """返回当前连接的路由作用域（homeserver 主机名）。"""

        return self._scope

    @property
    def ready(self) -> bool:
        """返回适配器是否已就绪。"""

        return self._ready

    async def start(self) -> None:
        """登录并启动同步循环。

        Raises:
            RuntimeError: 依赖缺失、配置非法或登录失败时抛出。
        """

        if _NIO_IMPORT_ERROR is not None:
            raise RuntimeError(
                f"matrix-nio 未安装（{_NIO_IMPORT_ERROR}）；请安装 matrix-nio[e2e] 与 vodozemac"
            )
        _install_windows_store_patch()

        connection = self._config.connection
        homeserver = connection.homeserver.strip().rstrip("/")
        if not homeserver:
            raise ValueError("Matrix homeserver 不能为空")
        user_id = connection.user_id.strip()
        if not user_id:
            raise ValueError("Matrix 用户 ID 不能为空（可填完整 ID，也可只填用户名）")
        if user_id.startswith("@") and ":" not in user_id:
            raise ValueError("Matrix 用户 ID 缺少服务器名：请写成 @user:server，或只填用户名由服务器补齐")
        password = connection.password
        if not password:
            raise ValueError("Matrix 登录密码不能为空")

        self._scope = self._build_scope(homeserver)
        device_id = self._load_or_create_device_id(connection.device_id)
        store_path = self._resolve_store_path(connection.store_path, device_id)
        try:
            client_config = AsyncClientConfig(
                encryption_enabled=bool(connection.enable_e2ee),
                store_sync_tokens=True,
                request_timeout=float(connection.request_timeout),
            )
        except ImportWarning as exc:
            raise RuntimeError(
                "端到端加密依赖缺失（vodozemac），请安装 matrix-nio[e2e]"
            ) from exc
        client = AsyncClient(
            homeserver,
            user_id,
            device_id=device_id,
            store_path=str(store_path),
            config=client_config,
        )
        self._client = client
        try:
            login_response = await client.login(
                password=password,
                device_name=connection.device_name or "MaiBot",
            )
            if isinstance(login_response, LoginError):
                raise RuntimeError(f"Matrix 登录失败: {login_response.message}")
            client.user_id = login_response.user_id
            client.device_id = login_response.device_id
            client.access_token = login_response.access_token
            self._user_id = login_response.user_id
            self._device_id = login_response.device_id
            self._persist_device_id(login_response.device_id)

            if connection.enable_e2ee:
                client.load_store()
                if client.olm is None:
                    raise RuntimeError(
                        "端到端加密库初始化失败：请确认已安装 matrix-nio[e2e] 与 vodozemac"
                    )
                # 加密库恢复的房间加密标记，作为重启后判定加密房间的第一来源
                self._encrypted_rooms = set(client.encrypted_rooms)

            # 首次全量同步，确保房间状态、成员与加密标记完整
            first_sync = await client.sync(timeout=0, full_state=True)
            if isinstance(first_sync, SyncError):
                raise RuntimeError(f"Matrix 首次同步失败: {first_sync.message}")
            await self._maintain_crypto()
            await self._dispatch_sync(first_sync)
            await self._refresh_direct_rooms()
            self._refresh_mention_keywords()

            self._running = True
            self._sync_task = asyncio.create_task(self._sync_loop(), name="matrix-sync-loop")
            self._ready = True
            self._logger.info(
                "Matrix 适配器已连接: user=%s device=%s homeserver=%s e2ee=%s",
                self._user_id,
                self._device_id,
                homeserver,
                bool(connection.enable_e2ee),
            )
        except Exception:
            await self._close_client()
            raise

    async def stop(self) -> None:
        """停止同步循环并关闭客户端（保留加密库与登录状态）。"""

        self._running = False
        self._ready = False
        task = self._sync_task
        self._sync_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # pragma: no cover - 退出路径的兜底日志
                self._logger.debug("Matrix 同步任务退出异常: %s", exc)
        await self._close_client()

    async def _close_client(self) -> None:
        """关闭底层 HTTP 会话。"""

        client = self._client
        self._client = None
        if client is None:
            return
        try:
            await client.close()
        except Exception as exc:  # pragma: no cover - 关闭失败不影响退出
            self._logger.debug("关闭 Matrix 客户端失败: %s", exc)

    def _build_scope(self, homeserver: str) -> str:
        """从 homeserver 地址构造路由作用域。"""

        parsed = urlsplit(homeserver)
        host = parsed.hostname or homeserver
        if parsed.port:
            return f"{host}:{parsed.port}"
        return host

    def _load_or_create_device_id(self, configured: str) -> str:
        """读取或生成稳定的设备 ID。

        设备 ID 与加密库一一对应：同一账号在两处使用同一设备 ID 会让两份
        加密库互相覆盖，因此这里必须持久化，不能每次启动随机生成。
        """

        normalized = configured.strip()
        if normalized:
            return normalized
        path = self._data_dir / "device_id.txt"
        if path.is_file():
            stored = path.read_text(encoding="utf-8").strip()
            if stored:
                return stored
        generated = "MAIBOT" + secrets.token_hex(4).upper()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(generated + "\n", encoding="utf-8")
        return generated

    def _persist_device_id(self, device_id: str) -> None:
        """把服务器确认的设备 ID 写回本地，保证下次登录复用同一设备。"""

        normalized = device_id.strip()
        if not normalized:
            return
        path = self._data_dir / "device_id.txt"
        if path.is_file() and path.read_text(encoding="utf-8").strip() == normalized:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(normalized + "\n", encoding="utf-8")

    def _resolve_store_path(self, configured: str, device_id: str) -> Path:
        """解析加密库目录，并按设备 ID 隔离。"""

        if configured.strip():
            base = Path(configured.strip())
            if not base.is_absolute():
                base = self._data_dir / base
        else:
            base = self._data_dir / "crypto_store"
        path = base / _sanitize_path_component(device_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _refresh_mention_keywords(self) -> None:
        """刷新 @ 触发关键词：配置项 + 机器人显示名 + 本地部分。"""

        keywords: List[str] = []
        for item in self._config.behavior.mention_keywords:
            normalized = str(item or "").strip()
            if normalized and normalized not in keywords:
                keywords.append(normalized)
        localpart = self._user_id.split(":", 1)[0].lstrip("@")
        if localpart and localpart not in keywords:
            keywords.append(localpart)
        self._mention_keywords = keywords


    async def _sync_loop(self) -> None:
        """持续同步 Matrix 事件，异常时指数退避重试。"""

        backoff = 1.0
        while self._running:
            client = self._client
            if client is None:
                break
            try:
                response = await client.sync(timeout=int(self._config.behavior.sync_timeout_ms))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._logger.warning("Matrix sync 异常: %s", exc)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            if isinstance(response, SyncError):
                self._logger.warning("Matrix sync 返回错误: %s", response.message)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            backoff = 1.0
            try:
                await self._maintain_crypto()
                await self._dispatch_sync(response)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._logger.error("处理 Matrix sync 结果失败: %s", exc, exc_info=True)

    async def _maintain_crypto(self) -> None:
        """维护设备密钥与一次性密钥（OTK）。

        这里只做单轮上传/查询/认领，不做大规模循环 claim：部分服务器
        （如 tuwunel 2.0）在大量 claim 后会把 OTK 数据写坏。
        """

        client = self._client
        if client is None or client.olm is None:
            return
        if client.should_upload_keys:
            result = await client.keys_upload()
            if isinstance(result, KeysUploadError):
                self._logger.warning("上传 Matrix 设备密钥失败: %s", result.message)
        if client.should_query_keys:
            result = await client.keys_query()
            if isinstance(result, KeysQueryError):
                self._logger.warning("查询 Matrix 设备密钥失败: %s", result.message)
        if client.should_claim_keys:
            users = client.get_users_for_key_claiming()
            if users:
                result = await client.keys_claim(users)
                if isinstance(result, KeysClaimError):
                    self._logger.warning("认领 Matrix 一次性密钥失败: %s", result.message)
        await client.send_to_device_messages()

    async def _dispatch_sync(self, response: Any) -> None:
        """分发一次 sync 结果中的房间事件与邀请。"""

        client = self._client
        if client is None:
            return
        rooms = getattr(response, "rooms", None)
        if rooms is None:
            return
        for room_id, join_info in rooms.join.items():
            if not self._is_room_allowed(room_id):
                continue
            room = client.rooms.get(room_id)
            if room is None:
                continue
            for event in join_info.timeline.events:
                await self._handle_timeline_event(room, event)
        for room_id in rooms.invite:
            await self._handle_invite(room_id)

    async def _handle_invite(self, room_id: str) -> None:
        """处理房间邀请。"""

        if not self._config.behavior.auto_join_invites:
            return
        client = self._client
        if client is None:
            return
        result = await client.join(room_id)
        if isinstance(result, JoinError):
            self._logger.warning("加入 Matrix 房间失败 %s: %s", room_id, result.message)
            return
        self._logger.info("已加入 Matrix 房间: %s", room_id)

    async def _handle_timeline_event(self, room: MatrixRoom, event: Any) -> None:
        """处理单条时间线事件。"""

        if isinstance(event, RoomEncryptionEvent):
            # 自己累积加密标记，避免重启后依赖可能为空的加密机房间表
            self._encrypted_rooms.add(room.room_id)
            return
        if isinstance(event, MegolmEvent):
            client = self._client
            request_room_key = getattr(client, "request_room_key", None)
            if callable(request_room_key):
                try:
                    # 向其它设备请求缺失的房间密钥；已请求过时 nio 会抛异常，忽略即可
                    await request_room_key(event)
                except Exception as exc:
                    self._logger.debug("请求 Matrix 房间密钥失败: %s", exc)
            self._logger.warning(
                "收到无法解密的 Matrix 加密消息（已尝试请求密钥）: room=%s event=%s",
                room.room_id,
                getattr(event, "event_id", ""),
            )
            return
        if isinstance(event, (ReactionEvent, RedactionEvent)):
            return
        if not isinstance(
            event,
            (RoomMessageText, RoomMessageNotice, RoomMessageEmote, RoomMessageMedia, RoomEncryptedMedia),
        ):
            return
        if str(getattr(event, "sender", "")) == self._user_id:
            return
        message = await self._build_inbound_message(room, event)
        if message is None:
            return
        accepted = await self._inbound_callback(message)
        if not accepted:
            self._logger.warning("Host 未接收 Matrix 入站消息: %s", message.get("message_id"))
            return
        if self._config.behavior.send_read_receipts:
            await self._send_read_receipt(room.room_id, str(message.get("message_id") or ""))


    async def _build_inbound_message(self, room: MatrixRoom, event: Any) -> Optional[Dict[str, Any]]:
        """把 Matrix 事件转换为 MaiBot 标准消息字典。"""

        source = getattr(event, "source", None)
        content: Dict[str, Any] = source.get("content", {}) if isinstance(source, dict) else {}
        sender = str(getattr(event, "sender", "") or "")
        event_id = str(getattr(event, "event_id", "") or "")
        if not sender or not event_id:
            return None

        is_dm = self._is_dm_room(room)
        nickname = self._user_display_name(room, sender)
        raw_message: List[Dict[str, Any]] = []
        is_picture = False

        reply_to = self._extract_reply_target(content)
        if reply_to and self._config.behavior.reply_enabled:
            raw_message.append({"type": "reply", "data": {"target_message_id": reply_to}})

        if isinstance(event, (RoomMessageMedia, RoomEncryptedMedia)):
            media = await self._download_media(event)
            mime = self._extract_mime(content, event)
            media_url = str(getattr(event, "url", "") or "")
            body = str(getattr(event, "body", "") or "")
            if media is None:
                raw_message.append({"type": "text", "data": f"[媒体消息] {body}".strip()})
            elif mime.startswith("image/"):
                raw_message.append(
                    {
                        "type": "image",
                        "data": media_url,
                        "binary_data_base64": base64.b64encode(media).decode("ascii"),
                    }
                )
                is_picture = True
            elif mime.startswith("audio/"):
                raw_message.append(
                    {
                        "type": "voice",
                        "data": media_url,
                        "binary_data_base64": base64.b64encode(media).decode("ascii"),
                    }
                )
            else:
                raw_message.append(
                    {
                        "type": "file",
                        "data": {
                            "name": body or "file",
                            "size": len(media),
                            "url": media_url,
                            "mime_type": mime,
                            "base64": base64.b64encode(media).decode("ascii"),
                        },
                    }
                )
        else:
            body = str(getattr(event, "body", "") or "")
            if not body.strip():
                return None
            if isinstance(event, RoomMessageEmote):
                body = f"* {nickname} {body}"
            raw_message.append({"type": "text", "data": body})

        mentioned = self._is_mentioned(content, raw_message)
        message_info: Dict[str, Any] = {
            "user_info": {"user_id": sender, "user_nickname": nickname},
            "additional_config": {
                "matrix_room_id": room.room_id,
                "matrix_event_id": event_id,
                "matrix_encrypted": bool(room.encrypted) or self._room_is_encrypted(room.room_id),
            },
        }
        if not is_dm:
            message_info["group_info"] = {
                "group_id": room.room_id,
                "group_name": self._room_display_name(room),
            }

        server_timestamp = getattr(event, "server_timestamp", None)
        timestamp = str(int(server_timestamp) / 1000) if server_timestamp else str(time.time())
        return {
            "message_id": event_id,
            "platform": PLATFORM_NAME,
            "account_id": self._user_id,
            "scope": self._scope,
            "timestamp": timestamp,
            "message_info": message_info,
            "raw_message": raw_message,
            "is_mentioned": mentioned,
            "is_at": mentioned,
            "is_picture": is_picture,
            "reply_to": reply_to,
        }

    async def _download_media(self, event: Any) -> Optional[bytes]:
        """下载并（必要时）解密媒体内容。"""

        client = self._client
        if client is None:
            return None
        url = str(getattr(event, "url", "") or "")
        if not url.startswith("mxc://"):
            return None
        response = await client.download(mxc=url)
        if isinstance(response, DownloadError):
            self._logger.warning("下载 Matrix 媒体失败 %s: %s", url, response.message)
            return None
        body = getattr(response, "body", b"")
        if not isinstance(body, bytes):
            return None
        if len(body) > int(self._config.behavior.max_media_bytes):
            self._logger.warning("Matrix 媒体超过大小上限，已跳过: %s (%d bytes)", url, len(body))
            return None

        key = getattr(event, "key", None)
        iv = getattr(event, "iv", None)
        hashes = getattr(event, "hashes", None)
        if isinstance(key, dict) and isinstance(iv, str) and isinstance(hashes, dict):
            key_b64 = str(key.get("k") or "")
            hash_b64 = str(hashes.get("sha256") or "")
            if key_b64 and hash_b64:
                try:
                    body = decrypt_attachment(body, key_b64, hash_b64, iv)
                except Exception as exc:
                    self._logger.warning("解密 Matrix 媒体失败 %s: %s", url, exc)
                    return None
        return body


    def _extract_mime(self, content: Dict[str, Any], event: Any) -> str:
        """从事件内容中提取 MIME 类型。"""

        info = content.get("info")
        if isinstance(info, dict):
            mime = str(info.get("mimetype") or "").strip()
            if mime:
                return mime
        mime = str(getattr(event, "mimetype", "") or "").strip()
        if mime:
            return mime
        filename = str(getattr(event, "body", "") or "")
        guessed, _ = mimetypes.guess_type(filename)
        return guessed or "application/octet-stream"

    def _extract_reply_target(self, content: Dict[str, Any]) -> Optional[str]:
        """提取回复目标事件 ID。"""

        relates = content.get("m.relates_to")
        if not isinstance(relates, dict):
            return None
        in_reply = relates.get("m.in_reply_to")
        if not isinstance(in_reply, dict):
            return None
        target = str(in_reply.get("event_id") or "").strip()
        return target or None

    def _is_mentioned(self, content: Dict[str, Any], raw_message: List[Dict[str, Any]]) -> bool:
        """判断消息是否 @ 了机器人。"""

        mentions = content.get("m.mentions")
        if isinstance(mentions, dict):
            user_ids = mentions.get("user_ids")
            if isinstance(user_ids, list) and self._user_id in [str(uid) for uid in user_ids]:
                return True
        text = "".join(
            str(item.get("data") or "")
            for item in raw_message
            if item.get("type") == "text" and isinstance(item.get("data"), str)
        )
        if not text:
            return False
        for keyword in self._mention_keywords:
            if keyword and keyword in text:
                return True
        return False

    def _is_dm_room(self, room: MatrixRoom) -> bool:
        """判断房间是否为私聊（DM）。"""

        if room.room_id in self._direct_rooms:
            return True
        return room.member_count == 2 and self._user_id in room.users

    def _room_display_name(self, room: MatrixRoom) -> str:
        """返回房间显示名（带缓存）。"""

        cached = self._room_name_cache.get(room.room_id)
        now = time.monotonic()
        ttl = max(int(self._config.behavior.room_name_refresh_seconds), 0)
        if cached is not None and now - cached[1] < ttl:
            return cached[0]
        name = str(room.display_name or "").strip() or room.room_id
        self._room_name_cache[room.room_id] = (name, now)
        return name

    def _user_display_name(self, room: MatrixRoom, user_id: str) -> str:
        """返回房间内用户的显示名。"""

        user = room.users.get(user_id)
        if user is not None:
            name = str(getattr(user, "display_name", "") or "").strip()
            if name:
                return name
        return user_id

    def _is_room_allowed(self, room_id: str) -> bool:
        """判断房间是否在允许列表中。"""

        allowed = [str(item).strip() for item in self._config.behavior.allowed_rooms if str(item).strip()]
        if not allowed:
            return True
        normalized = self._normalize_room_id(room_id)
        return normalized in allowed or room_id in allowed

    def _normalize_room_id(self, raw: str) -> str:
        """归一化房间号。

        部分服务器（如 tuwunel 2.0）的 /joined_rooms 返回 !opaque 而不带
        :server，直接用完整号发送会被拒绝；这里按 !opaque 前缀对回本地房间表。
        """

        cleaned = _strip_invisible(str(raw or ""))
        if not cleaned:
            return ""
        client = self._client
        if client is None:
            return cleaned
        if cleaned in client.rooms:
            return cleaned
        if cleaned.startswith("!") and ":" not in cleaned:
            for room_id in client.rooms:
                if room_id.split(":", 1)[0] == cleaned:
                    return room_id
        return cleaned

    async def _refresh_direct_rooms(self) -> None:
        """读取 m.direct 账号数据，缓存私聊房间。"""

        client = self._client
        if client is None:
            return
        try:
            response = await client.list_direct_rooms()
        except Exception as exc:
            self._logger.debug("读取 Matrix m.direct 失败: %s", exc)
            return
        rooms = getattr(response, "rooms", None)
        if not isinstance(rooms, dict):
            return
        direct_rooms: Set[str] = set()
        for room_ids in rooms.values():
            if isinstance(room_ids, list):
                direct_rooms.update(str(room_id) for room_id in room_ids)
        self._direct_rooms = direct_rooms

    async def _send_read_receipt(self, room_id: str, event_id: str) -> None:
        """发送已读回执。"""

        client = self._client
        if client is None or not event_id:
            return
        try:
            await client.room_read_markers(room_id, fully_read_event=event_id, read_event=event_id)
        except Exception as exc:
            self._logger.debug("发送 Matrix 已读回执失败: %s", exc)

    def _room_is_encrypted(self, room_id: str) -> bool:
        """判断房间是否启用端到端加密。"""

        if room_id in self._encrypted_rooms:
            return True
        client = self._client
        if client is None:
            return False
        room = client.rooms.get(room_id)
        return bool(room.encrypted) if room is not None else False


    async def send_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """把 MaiBot 消息发送到 Matrix。

        Args:
            message: Host 传入的标准消息字典。

        Returns:
            Dict[str, Any]: 至少包含 success 字段的发送结果。
        """

        client = self._client
        if client is None or not self._ready:
            return {"success": False, "error": "Matrix 适配器尚未就绪"}

        room_id = await self._resolve_target_room(message)
        components = message.get("raw_message")
        if not isinstance(components, list):
            components = []

        reply_to: Optional[str] = None
        text_parts: List[str] = []
        media_components: List[Dict[str, Any]] = []
        for component in components:
            if not isinstance(component, dict):
                continue
            component_type = str(component.get("type") or "").strip()
            data = component.get("data")
            if component_type == "text":
                text_parts.append(str(data or ""))
            elif component_type == "reply":
                if isinstance(data, dict):
                    reply_to = str(data.get("target_message_id") or "").strip() or None
            elif component_type in {"image", "emoji", "file", "voice"}:
                media_components.append(component)
            elif component_type == "at":
                if isinstance(data, dict):
                    target = str(data.get("target_user_id") or "").strip()
                    nickname = str(data.get("target_user_nickname") or "").strip()
                    if target:
                        text_parts.append(f"@{nickname or target}")
            elif component_type == "forward":
                forwarded = self._flatten_forward(data)
                if forwarded:
                    text_parts.append(forwarded)

        text = "".join(text_parts).strip()
        encrypted = self._room_is_encrypted(room_id)
        last_event_id = ""
        for component in media_components:
            event_id = await self._send_media_component(
                room_id,
                component,
                encrypted,
                reply_to if not last_event_id else None,
            )
            if event_id:
                last_event_id = event_id
        if text:
            event_id = await self._send_text(
                room_id,
                text,
                encrypted,
                reply_to if not last_event_id else None,
            )
            if event_id:
                last_event_id = event_id
        if not last_event_id:
            return {"success": False, "error": "没有可发送的消息内容"}
        return {"success": True, "external_message_id": last_event_id}

    async def _resolve_target_room(self, message: Dict[str, Any]) -> str:
        """从消息字典解析目标房间。"""

        message_info = message.get("message_info")
        if isinstance(message_info, dict):
            group_info = message_info.get("group_info")
            if isinstance(group_info, dict):
                group_id = str(group_info.get("group_id") or "").strip()
                if group_id:
                    return self._normalize_room_id(group_id)
            user_info = message_info.get("user_info")
            if isinstance(user_info, dict):
                user_id = str(user_info.get("user_id") or "").strip()
                if user_id and user_id != self._user_id:
                    return await self._ensure_dm_room(user_id)
        raise ValueError("消息缺少目标房间或用户，无法确定 Matrix 发送目标")

    async def _ensure_dm_room(self, user_id: str) -> str:
        """查找或创建与指定用户的私聊房间。"""

        client = self._client
        if client is None:
            raise RuntimeError("Matrix 客户端未初始化")
        for room in client.rooms.values():
            if room.member_count == 2 and self._user_id in room.users and user_id in room.users:
                return room.room_id
        response = await client.room_create(
            is_direct=True,
            invite=[user_id],
            preset=RoomPreset.trusted_private_chat,
        )
        if isinstance(response, RoomCreateError):
            raise RuntimeError(f"创建 Matrix 私聊房间失败: {response.message}")
        self._logger.info("已创建 Matrix 私聊房间: %s -> %s", user_id, response.room_id)
        return response.room_id


    async def _send_text(
        self,
        room_id: str,
        text: str,
        encrypted: bool,
        reply_to: Optional[str],
    ) -> Optional[str]:
        """发送文本消息。"""

        client = self._client
        if client is None:
            return None
        content: Dict[str, Any] = {"msgtype": "m.text", "body": text}
        if reply_to:
            content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}
        if encrypted and client.olm is None:
            raise RuntimeError("目标房间已加密，但端到端加密库未启用")
        response = await client.room_send(
            room_id,
            "m.room.message",
            content,
            ignore_unverified_devices=bool(self._config.behavior.ignore_unverified_devices),
        )
        if isinstance(response, RoomSendError):
            raise RuntimeError(f"发送 Matrix 消息失败: {response.message}")
        return str(response.event_id or "")

    async def _send_media_component(
        self,
        room_id: str,
        component: Dict[str, Any],
        encrypted: bool,
        reply_to: Optional[str],
    ) -> Optional[str]:
        """上传并发送媒体组件。"""

        client = self._client
        if client is None:
            return None
        component_type = str(component.get("type") or "")
        data = component.get("data")
        raw_base64 = ""
        filename = ""
        mime = ""
        if component_type == "file" and isinstance(data, dict):
            raw_base64 = str(data.get("base64") or "")
            filename = str(data.get("name") or "file")
            mime = str(data.get("mime_type") or "")
        else:
            raw_base64 = str(component.get("binary_data_base64") or "")
            filename = str(data or "") if isinstance(data, str) else ""
            mime = ""
        if not raw_base64:
            return None
        try:
            payload = base64.b64decode(raw_base64)
        except Exception as exc:
            raise RuntimeError(f"媒体 Base64 解码失败: {exc}") from exc
        if len(payload) > int(self._config.behavior.max_media_bytes):
            raise RuntimeError(f"媒体超过大小上限: {len(payload)} bytes")
        if not mime:
            if component_type in {"image", "emoji"}:
                mime = _guess_image_mime(payload)
            elif component_type == "voice":
                mime = "audio/ogg"
            else:
                mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        if not filename:
            filename = "media" + (mimetypes.guess_extension(mime) or ".bin")
        if encrypted and client.olm is None:
            raise RuntimeError("目标房间已加密，但端到端加密库未启用")

        upload_response, decryption_info = await client.upload(
            payload,
            content_type=mime,
            filename=filename,
            encrypt=encrypted,
        )
        if isinstance(upload_response, UploadError):
            raise RuntimeError(f"上传 Matrix 媒体失败: {upload_response.message}")
        mxc_uri = str(upload_response.content_uri or "")
        if not mxc_uri:
            raise RuntimeError("上传 Matrix 媒体失败: 未返回 content_uri")

        if mime.startswith("image/"):
            msgtype = "m.image"
        elif mime.startswith("audio/"):
            msgtype = "m.audio"
        elif mime.startswith("video/"):
            msgtype = "m.video"
        else:
            msgtype = "m.file"
        content: Dict[str, Any] = {
            "msgtype": msgtype,
            "body": filename,
            "info": {"mimetype": mime, "size": len(payload)},
        }
        if decryption_info:
            content["file"] = {"url": mxc_uri, **decryption_info}
        else:
            content["url"] = mxc_uri
        if reply_to:
            content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}
        response = await client.room_send(
            room_id,
            "m.room.message",
            content,
            ignore_unverified_devices=bool(self._config.behavior.ignore_unverified_devices),
        )
        if isinstance(response, RoomSendError):
            raise RuntimeError(f"发送 Matrix 媒体消息失败: {response.message}")
        return str(response.event_id or "")

    def _flatten_forward(self, data: Any) -> str:
        """把转发消息节点拍平成文本（Matrix 无原生合并转发）。"""

        if not isinstance(data, list):
            return ""
        lines: List[str] = []
        for node in data:
            if not isinstance(node, dict):
                continue
            nickname = str(node.get("user_nickname") or node.get("user_id") or "未知用户")
            parts: List[str] = []
            for item in node.get("content") or []:
                if isinstance(item, dict) and str(item.get("type")) == "text":
                    parts.append(str(item.get("data") or ""))
            if parts:
                lines.append(f"{nickname}: {''.join(parts)}")
        return "\n".join(lines)


class MatrixAdapterPlugin(MaiBotPlugin):
    """Matrix 适配器插件。"""

    config_model = MatrixAdapterConfig

    def __init__(self) -> None:
        """初始化插件状态。"""

        super().__init__()
        self._client: Optional[MatrixClient] = None
        self._ready = False

    async def on_load(self) -> None:
        """加载插件并启动 Matrix 连接。"""

        config = self.config
        if not config.plugin.enabled:
            self.ctx.logger.info("Matrix 适配器未启用")
            return
        if _NIO_IMPORT_ERROR is not None:
            self.ctx.logger.error(
                "matrix-nio 未安装，Matrix 适配器无法启动: %s；请安装 matrix-nio[e2e] 与 vodozemac",
                _NIO_IMPORT_ERROR,
            )
            return

        client = MatrixClient(
            config=config,
            data_dir=self.ctx.paths.data_dir,
            logger=self.ctx.logger,
            inbound_callback=self._handle_inbound,
        )
        try:
            await client.start()
        except Exception as exc:
            self.ctx.logger.error("Matrix 适配器启动失败: %s", exc, exc_info=True)
            await client.stop()
            return

        self._client = client
        self._ready = True
        await self.ctx.gateway.update_state(
            gateway_name=GATEWAY_NAME,
            ready=True,
            platform=PLATFORM_NAME,
            account_id=client.user_id,
            scope=client.scope,
            metadata={
                "protocol": PROTOCOL_NAME,
                "homeserver": config.connection.homeserver,
                "e2ee": bool(config.connection.enable_e2ee),
            },
        )
        self.ctx.logger.info("Matrix 网关已就绪: %s", client.user_id)

    async def on_unload(self) -> None:
        """卸载插件并断开 Matrix 连接。"""

        client = self._client
        self._client = None
        self._ready = False
        if client is not None:
            await client.stop()
        try:
            await self.ctx.gateway.update_state(gateway_name=GATEWAY_NAME, ready=False)
        except Exception as exc:
            self.ctx.logger.debug("上报 Matrix 网关离线失败: %s", exc)

    async def on_config_update(self, scope: str, config_data: dict[str, Any], version: str) -> None:
        """配置热更新：重建 Matrix 连接。"""

        del scope, config_data, version
        self.ctx.logger.info("Matrix 配置已更新，正在重建连接")
        await self.on_unload()
        await self.on_load()

    async def _handle_inbound(self, message: Dict[str, Any]) -> bool:
        """把入站消息注入 Host。"""

        message_id = str(message.get("message_id") or "")
        return await self.ctx.gateway.route_message(
            gateway_name=GATEWAY_NAME,
            message=message,
            external_message_id=message_id,
            dedupe_key=message_id,
        )

    @MessageGateway(
        route_type="duplex",
        name=GATEWAY_NAME,
        description="Matrix 双向消息网关（Client-Server API）",
        platform=PLATFORM_NAME,
        protocol=PROTOCOL_NAME,
    )
    async def send_to_platform(
        self,
        message: Dict[str, Any],
        route: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """出站：把 Host 消息发送到 Matrix。"""

        del route, metadata, kwargs
        client = self._client
        if client is None or not self._ready:
            return {"success": False, "error": "Matrix 适配器尚未就绪"}
        try:
            return await client.send_message(message)
        except Exception as exc:
            self.ctx.logger.error("Matrix 出站发送失败: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}


# 模块使用了 from __future__ import annotations，pydantic 需要显式重建嵌套配置模型，
# 否则在构造配置时会报 "is not fully defined"。显式传入模块命名空间，
# 保证 List 等 typing 名字能被解析。
_config_namespace = globals()
for _config_class in (
    MatrixPluginSectionConfig,
    MatrixConnectionConfig,
    MatrixBehaviorConfig,
    MatrixAdapterConfig,
):
    if hasattr(_config_class, "model_rebuild"):
        _config_class.model_rebuild(_types_namespace=_config_namespace)


def create_plugin() -> MatrixAdapterPlugin:
    """创建 Matrix 适配器插件实例。"""

    return MatrixAdapterPlugin()
