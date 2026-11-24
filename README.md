# shou瓜田 后端

shou瓜田主站后端基于 Django 5.2 与 Python 3.11+（当前于 Python 3.12 环境验证）实现，负责社区帖子、评论、媒体上传、硬币、校友墙、教育邮箱验证以及 FIDO2 / WebAuthn 安全中心接口。

高权限账号任免、实名材料审核、密码 Hash 查看、临时代登录与硬件凭证签发等敏感功能，由独立部署的特权管理站负责，并通过专用的受限数据库账号访问共享数据表。

## 本地开发与启动

依赖清单以 [pyproject.toml](pyproject.toml) 和 [uv.lock](uv.lock) 为准，[requirement.txt](requirement.txt) 为锁文件的导出版本。

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirement.txt
Copy-Item config.yaml.example config.yaml
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py createcachetable dev_cache
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:18000
```

- 运行模式由 `SHOUGT_MODE` 控制：`dev`（SQLite、数据库缓存和控制台邮件）、`dev-mysql` 或 `prod`（PostgreSQL + Redis + SMTP）。独立特权管理站支持 SQLite 和 PostgreSQL，不支持 `dev-mysql`。
- 依赖变更后执行以下命令同步更新 `requirement.txt`：

```powershell
uv export --locked --no-hashes --no-emit-project --format requirements-txt --output-file requirement.txt
```

### 本地持久化预览模式

需要长期保留测试账号、安全密钥与审计日志进行交互调试时，可先运行 [scripts/prepare_local_preview.py](scripts/prepare_local_preview.py)（需要预设本地管理员可再配合 [scripts/prepare_local_admin.py](scripts/prepare_local_admin.py)）生成 `.local-preview/forum.sqlite3`，再显式开启环境变量启动：

```powershell
$env:SHOUGT_MODE = "dev"
$env:SHOUGT_LOCAL_PREVIEW = "1"
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:18000 --noreload --settings=gt.local_preview_settings
```

`gt.local_preview_settings` 仅在显式设置 `SHOUGT_LOCAL_PREVIEW=1` 时加载，并为 SQLite 启用 WAL 与 `IMMEDIATE` 事务模式。本地预览的固定邮箱验证码 `123456` 与 `.local-preview/fido-local-pins.json` 仅在回环环境下生效，正式环境完全禁用。

## 认证、角色与安全边界

### 教育邮箱与实名认证

- 默认支持 `edu.cn`、`edu`、`ac.uk` 后缀的教育邮箱；验证码绑定邮箱和用途，且限期、限次、单次有效。
- 域名分组规则：`st.shou.edu.cn` 归类为「上海海洋大学 · 学生」，`shou.edu.cn` 及其子域归类为「上海海洋大学 · 教师」，其他教育邮箱归类为「外校人士」。
- 学号按「院校缩写-邮箱前缀」生成（可通过 `education_institution_aliases` 配置域名例外，最长 128 字符）。
- 进阶实名认证不在日常安全中心作为“申请管理员”功能开放，而是仅在新任管理员首次登录（或经授权准备特权任命的账号）自动弹出的安全配置引导中使用：成员须使用外置 FIDO2 安全密钥签署挑战信息，并在 24 小时内使用已验证的教育邮箱发送完整正文至 `renzheng@shouguatian.com`。系统仅采用可信收件端校验后传回的 `From` 发件人称呼（例如 `示例用户<example001@st.shou.edu.cn>` 会解析出实名 `示例用户`、学号 `shou-example001`），不信任前端自填姓名；经超级管理员核对后写入账号。

### 安全密钥、角色分工与临时特权

- **硬件密钥与多因素认证**：每个账号最多绑定 3 把有效外置安全密钥（与通行密钥共用 20 个凭据上限）。管理账号要求不可备份、带可信硬件证明的外置 FIDO2 安全密钥；特权及超级管理角色（`super_admin`、`admin_admin`、`superadmin_admin`、`global_reader`）登录还必须搭配第二把不同公钥的安全密钥、密码 / TOTP / 邮箱验证码之一，或经服务端核验的 FIPS 140 L2+ / 同等级硬件凭证。
- **新任管理首次配置门禁（Onboarding）**：授予管理岗位或完成特权制卡后会自动开启 `admin_onboarding_required` 并刷新账号版本（立即作废旧会话）。在完成 FIDO2 外置安全密钥绑定、教育邮箱实名与进阶认证及最终密钥确认前，新任管理员虽保留管理身份与主角色徽章（有身份），但不具备任何实际管理权限（无权限 — 所有 `/admin/`、Django Admin、管理水印与特权管理端接口均拒绝访问；普通社区浏览不受影响），登录时自动弹出三步配置引导完成认证。
- **角色权限与临时证书**：
  - 主站 `admin_user` 仅能重置普通账号密码（管理账号密码仅限 `super_admin` 重置）；`/admin/user/` 仅允许修改 `no_review`（老学究）、配额、硬币和封禁状态，角色任命、信息修改与密码 Hash 查看统一在特权管理站完成。
  - 新增 `super_admin`、`admin_admin`、`superadmin_admin`、`global_reader` 须完成实体智能卡（PIV）或本机 Windows TPM 2.0 制卡签发（严禁任何 `.p12` 软证书）。未持有长期 CA 卡的超级管理员可签发有效期少于 37 天的短期临时最终证书，但临时特权账号或短期持卡者不能继续签发下游证书。
  - `global_reader` 与测试签名 CA 证书在全系统（主站 API、Django Admin 与管理站）强制只读。
- **匿名角色与内容可见性**：
  - 账号主角色直接联动 `/security/privacy/` 的实名展示设置，管理徽章仅挂载于主角色；`is_private=True` 的匿名角色严格隐藏背后用户信息，退出共享角色或特定可见组后立即失去访问权限。
  - 后台管理查询（`UserAdminViewset` 与 `ImageViewset`）支持按数字 ID（如 `1`、`#1`）、用户名、实名与学号检索；非 `admin_image` 管理员仅可检索个人上传图片。
- **临时代登录与 Django Admin**：
  - 临时代登录仅能由特权管理站 `super_admin` 签发 2 分钟一次性票据，进入目标账号最长 15 分钟的受限会话，严禁访问 `/admin/`、`/django-admin/`、`/security/`、`/user/setting/` 及修改角色。
  - Django Admin 禁止密码登录，只能通过安全中心换票进入且保持账号表只读。
- **动态管理水印**：管理区域附带零宽会话标识，画面背景与无损截图嵌入实名明水印、动态空间 / 频域 / LSB v2 Ed25519 RS 签名载荷与微块 `M3` 载荷，由主站前端 `npm run build:watermark` 统一编译并同步静态资源。

## 可信邮件接收接口

收件基础设施需先行校验 DKIM / SPF / DMARC 与发件人对齐，再把解码后的纯文本正文投递给主站（不可直接使用来信自填的 `Authentication-Results` 或任意 `From` 头）：

```json
{
  "recipient": "renzheng@shouguatian.com",
  "authenticated_sender": "example001@st.shou.edu.cn",
  "from_header": "示例用户<example001@st.shou.edu.cn>",
  "dmarc_pass": true,
  "received_at": "2026-11-05T12:00:00+08:00",
  "message_id": "message-id-from-receiving-mta",
  "body": "完整纯文本邮件正文，包含 SHOU-VERIFY: 行"
}
```

- **本机受信任 MTA**：`python manage.py ingest_verified_mail --event event.json`（或经 stdin 传入）。
- **远程接口**：`POST /security/mail-ingest/`（经同源代理 `/api/security/mail-ingest/`），附带 `X-Shou-Mail-Time`（Unix 秒数，误差限 5 分钟内）与 `X-Shou-Mail-Signature`（`HMAC-SHA256(secret, ascii(timestamp) + "." + raw_body)`）。

## 生产配置与旧数据库升级

正式部署请由 `config.yaml.example` 生成 `config.yaml` 并配置环境变量。主站必须启用 HTTPS 且准确设置 WebAuthn `RP ID` 与 `Origin`（切勿把特权管理站子域名加入主站 WebAuthn Origin 白名单）。

| 环境变量 | 用途说明 |
| --- | --- |
| `SHOUGT_SECRET_KEY` | 主站核心签名密钥（生产必填，各实例保持一致） |
| `SHOUGT_TOTP_ENCRYPTION_KEY` | Fernet 密钥（未配置时由主站密钥派生，轮换前须迁移现有 TOTP 密文） |
| `SHOUGT_MAIL_INGEST_SECRET` | 可信收件适配器 HMAC 密钥（未配置则关闭远程收件接口） |
| `SHOUGT_WATERMARK_SIGNING_KEY` | 32 字节随机 Base64 Ed25519 签名密钥（建议独立设置） |
| `SHOUGT_SMTP_PASSWORD` | 外发邮件 SMTP 密码 |
| `SHOUGT_DB_NAME / USER / PASSWORD / HOST / PORT` | PostgreSQL 连接参数（默认端口 `15432`） |
| `SHOUGT_REDIS_URL` | 缓存与 Celery 地址（默认 `redis://127.0.0.1:16379/4`） |
| `SHOUGT_SQLITE_PATH` | 自定义本地 SQLite 文件路径 |

### 升级旧版数据库

对缺少初始迁移记录的历史数据库升级前，请先完整备份并在副本演练：

```powershell
# 1. 只读比对 27 张核心业务表结构
.\.venv\Scripts\python.exe manage.py adopt_legacy_migrations
# 2. 确认结构匹配后补记初始迁移并执行升级
.\.venv\Scripts\python.exe manage.py adopt_legacy_migrations --apply
.\.venv\Scripts\python.exe manage.py migrate
```

- 原 Django 超级用户会迁移为 `super_admin`；旧文件管理员对应拆分为 `admin_file` 与 `admin_image`；旧空投功能已下线，历史数据表保留。

## 检查、测试与延伸文档

```powershell
$env:SHOUGT_MODE = "dev"
.\.venv\Scripts\python.exe manage.py check --settings=gt.test_settings
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run --settings=gt.test_settings
.\.venv\Scripts\python.exe manage.py test
```

- 安全审计与红蓝演练详情见 [SECURITY-AUDIT.md](SECURITY-AUDIT.md)。
- 首尔部署节点与 OneDrive 媒体接入评估见 [ONEDRIVE-STORAGE-ASSESSMENT.md](ONEDRIVE-STORAGE-ASSESSMENT.md)。
- 本项目继续保留原 GPLv3 开源协议。
