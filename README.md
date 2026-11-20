# Matrix 适配器（MaiBot 插件）

通过 Matrix Client-Server API 把 MaiBot 接入任意 Matrix 服务器，支持用户名密码登录、
端到端加密（E2EE）与双向消息路由。

## 功能

- 用户名密码登录，自动换取访问令牌；设备 ID 持久化，重启复用同一设备
- 端到端加密：基于 matrix-nio + vodozemac，支持加密房间收发与加密媒体
- 入站：文本、图片、文件、语音、回复关系、@ 提及、房间邀请自动加入
- 出站：文本、图片、文件、回复、@ 提及、转发消息拍平为文本
- 群聊/私聊自动区分：普通房间映射为群聊，DM 房间映射为私聊，私聊缺房间时自动创建
- 房间白名单、媒体大小上限、已读回执、房间名缓存等可配置项

## 安装位置

插件目录位于 `D:\MaiBot\plugins\maibot-matrix-adapter`（MaiBot 的第三方插件根目录）。

- 若 MaiBot 实例根目录就是 `D:\MaiBot`（设置了 `MAIBOT_INSTANCE_DIR=D:\MaiBot`），插件会被自动发现。
- 若实例根目录是 `MaiBot-1.3.15`，请在 `MaiBot-1.3.15\plugins\` 下创建指向本目录的 junction：

```bat
mklink /J "D:\MaiBot\MaiBot-1.3.15\plugins\maibot-matrix-adapter" "D:\MaiBot\plugins\maibot-matrix-adapter"
```

## 依赖

插件在 `_manifest.json` 中声明了以下 Python 包，MaiBot 会按依赖管线安装：

- `matrix-nio>=0.26.0`
- `vodozemac>=0.9.0`（E2EE 必需）
- `peewee>=3.14`、`cachetools>=5.3`、`atomicwrites>=1.4`（matrix-nio 的 e2e 依赖）

手动安装等价命令：

```bash
pip install "matrix-nio[e2e]>=0.26.0"
```

## 配置

在插件配置页填写：

| 配置项 | 说明 |
| --- | --- |
| `connection.homeserver` | Matrix 服务器地址，如 `https://matrix.example.com` |
| `connection.user_id` | 机器人用户 ID：可填完整 ID（`@maibot:example.com`），也可只填用户名（`maibot`），由服务器补齐 |
| `connection.password` | 登录密码 |
| `connection.device_id` | 留空自动生成并持久化；**不要与手机等其它客户端共用** |
| `connection.enable_e2ee` | 是否启用端到端加密，默认开启 |
| `behavior.allowed_rooms` | 允许接入的房间 ID 列表，留空表示全部 |
| `behavior.auto_join_invites` | 收到邀请自动加入，默认开启 |
| `behavior.ignore_unverified_devices` | 加密房间忽略未验证设备，默认开启 |

## E2EE 说明

- 加密库保存在插件数据目录 `crypto_store/<device_id>/`，按设备隔离；换设备不会复用旧库。
- 房间是否加密由插件自己从 state 事件累积（并持久化），不依赖重启后可能为空的加密机房间表。
- 加密房间的媒体会先解密再交给 MaiBot；出站媒体在加密房间会自动加密上传。
- 未验证设备默认忽略（`ignore_unverified_devices=true`），否则可能因设备未验证而无法发送。

## 排错

按以下顺序定位 E2EE 问题：

1. 日志里有没有「收到 to-device」——没有说明发送方没有分发密钥。
2. 出现 `m.room_key.withheld` / `code=m.no_olm`——Olm 通道建不起来。
3. 认领一把 OTK 自己验签，签名对不上说明密钥数据坏了。
4. 校验 device keys 自签名，检查有没有多余或非法的签名条目。
5. 确认同一账号没有在两处共用同一个令牌（共用令牌 = 共用设备 = 两份加密库互相覆盖）。

其他常见问题：

- 房间号不带 `:server`（部分服务器如 tuwunel 2.0）：插件会自动按 `!opaque` 前缀对回本地房间表。
- 大量循环 claim OTK 可能写坏服务端数据：插件只做单轮认领，不做循环。
- 服务器关闭注册或要求邀请：属于服务器策略，插件会把错误如实写入日志。
- 收到无法解密的加密消息：插件会自动调用 `request_room_key` 向其它设备请求密钥，过一会儿会重新解密。
- Windows 存储路径：nio 默认用 `{user_id}_{device_id}` 拼数据库文件名，而 user_id 含 `:`（Windows 非法）；插件启动时会打补丁改用安全文件名，否则加密发送会报 `WinError 123`。
- 429 限流：nio 会按服务器 `Retry-After` 自动等待重试，日志里出现 `Got 429 response` 属于正常退避。

## 限制

- Matrix 没有严格的群聊/私聊二分：插件用 `m.direct` 与两人房间判定私聊。
- 合并转发没有原生支持，出站时拍平为文本。
- 表情回应（reaction）与撤回事件当前不注入 MaiBot。
