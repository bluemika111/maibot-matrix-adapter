# Changelog

## 0.1.0

- 初始版本：Matrix 双向消息网关（`@MessageGateway(route_type="duplex")`）
- 用户名密码登录，设备 ID 持久化，加密库按设备隔离
- 端到端加密：加密房间收发、加密媒体上传/下载解密
- 入站映射：文本、图片、文件、语音、回复、@ 提及、邀请自动加入
- 出站映射：文本、图片、文件、回复、@ 提及、转发拍平
- 群聊/私聊区分与私聊房间自动创建
- 房间号归一化（兼容不带 `:server` 的服务器）
- Windows 存储路径补丁（nio 默认数据库名含 `:` 会触发 WinError 123）
- 无法解密的加密消息自动 `request_room_key` 补取密钥
- pydantic 嵌套配置模型显式 `model_rebuild()`
