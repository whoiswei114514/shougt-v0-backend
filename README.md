# shou瓜田后端

Django 5.2 / Python 3.11+，本次在 Python 3.12 环境验证。论坛、教育邮箱认证与主站 FIDO2 服务位于本项目；独立特权管理应用位于相邻的 `shougt-sa`，通过自己的后端和专用数据库账号访问数据库。

## 在 VS Code 中开发

打开上一级 `shougt.code-workspace`。后端解释器已指向项目 `.venv`，通过“任务 → 运行任务”选择 Django 检查、安全回归测试或开发服务。前端项目提供构建、开发任务。不要把开发或测试设置用于生产。

新机器可使用：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirement.txt
Copy-Item config.yaml.example config.yaml
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py createcachetable dev_cache
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:18000
```

配置变量是 `SHOUGT_MODE`（`dev` / `dev-mysql` / `prod`），不是旧文档的 `GT_MODE`。`dev` 使用 SQLite、数据库缓存和控制台邮件。独立管理应用支持 SQLite 和 PostgreSQL，不支持 `dev-mysql`。

依赖以 `pyproject.toml` 和 `uv.lock` 为准。`requirement.txt` 是锁文件的导出，`requirement-new.txt` 仅保留兼容入口。更新依赖后用 `uv export --locked --no-hashes --no-emit-project --format requirements-txt --output-file requirement.txt` 重新导出。

## 本机持久化预览

运行 `scripts/prepare_local_preview.py` 准备缺少的数据，再显式设置 `SHOUGT_LOCAL_PREVIEW=1`，使用 `gt.local_preview_settings` 在 `127.0.0.1:18000` 启动。账号、邮箱挑战和真实 FIDO2 公钥凭据保存在 `.local-preview/forum.sqlite3`，重复准备或重启均不重置；SQLite 使用 WAL 和 IMMEDIATE 事务避免并发安全页/审计写入冲突。验证码暂为 `123456`，仅 localhost 的回环请求生效；邮件写入本地文件，昵称审核采用带测试标识的本地结果，禁止连接外部服务。

本机账号配置与授权记录保存在忽略的 `.local-preview/` 中。`scripts/prepare_local_admin.py` 只允许修改预览库，保留既有密码和真实 FIDO2 凭据；测试资料不代表完成真实材料审核。若明确授权使用现有 PIV CA 槽，临时许可必须精确绑定账号、公开证书指纹、测试姓名和到期时间。CA 的 CN 不作为个人姓名，普通客户端证书仍核对 CN。

`.local-preview/fido-local-pins.json` 按账号、凭据和公钥指纹允许既有密钥 30 天，正式模式不加载此许可，也不把它标记为已核验硬件证明或 FIPS 认证。主站登录与管理操作仍需实际 FIDO2 签名，超级管理登录还需密码 / TOTP / 邮箱验证码之一。PIV 的整站 TLS 验证由相邻独立应用负责，浏览器和驱动状态见其 README。

## 认证与权限

- 教育邮箱默认为 `edu.cn`、`edu`、`ac.uk` 后缀，严格检查域名边界。`st.shou.edu.cn` 是海大学生，`shou.edu.cn` 及其他子域是海大教师，其余教育域是外校人士。邮箱验证码限时、限次数、绑定用途且一次有效。
- 普通用户支持密码及通行密钥。管理员默认要求带可信硬件证明、用户验证且不能备份同步的外置 FIDO2 密钥；`no_review` 不属于管理岗位。
- 管理员及被提名的候选人需要在安全中心签署随机串、邮箱、派生学号与时间戳，并在 24 小时内从已验证教育邮箱发送完整认证邮件至 `renzheng@shouguatian.com`。实名取可信收件系统提供的 From 发件人称呼，不使用前端填写的姓名。例如 `魏子力<2531231@st.shou.edu.cn>` 生成实名“魏子力”、学号 `shou-2531231`，超级管理员核对材料后将两项一并写入账号。
- `super_admin`、`admin_admin`、`superadmin_admin` 要求外置安全密钥和登录时的密码 / TOTP / 邮箱验证码之一，或服务器验证的 FIPS 140 L2+ / 同等级硬件。型号名称、客户端 attachment 声明不能获得硬件信任或 FIPS 豁免。
- 站点需配置官方证明根、AAGUID、有效期及审核来源。`fido_attestation_trust` 默认空，未配置时管理员密钥注册会拒绝。认证元数据变更会在每次验证时重新检查；成功断言将更新独立管理站读取的证明状态。
- 安全中心返回本次登录凭据的已核验等级；FIPS 140-2/3 L2–L4 或经审核的同等级凭据显示金色。`certifications` 可补充 CC 等证书的 `standard`、`level`、`reference`，用于显示具体等级；它不会自动提高权限或把 CC 等级换算成 FIPS 等级。本机临时许可与凭据名称不会取得金色认证。
- 管理认证始终显示在账号注册主角色上，与实名公开状态分开；其他个人或匿名角色不继承管理员标记。`/security/privacy/` 的 `show_real_name` 直接控制主角色 `show_user_info`，与角色设置同步。主角色关联不可自行更换、匿名化、共享或删除，可正常修改名称与头像。迁移 `0007` 为旧账号保留最早仍可用的独立公开角色；没有合适角色时新建主角色，保留旧隐私选择。
- 普通用户管理员只能设置 `no_review`。其他任命全部在独立管理应用；两种特权任命角色与其他管理岗位互斥，可与 `no_review` 并存。`superadmin_admin` 按需求可任免其他超级管理员。
- 用户列表“创建用户”由 `admin_user` 直接调用 `/admin/user/`，不要求或发送验证码。新账号为普通权限，邮箱与实名保持未认证，用户可登录后自行验证教育邮箱。密码校验后哈希保存，学校/身份按邮箱归类，学号由院校缩写与邮箱前缀生成；禁止注入权限、认证状态或自定义学号，创建操作记入审计。
- `admin_user` 只能重置普通账号密码；管理账号密码仅允许超级管理员重置，防止借用临时非密钥许可接管其他管理岗位。
- 原代登录入口已移除；只有独立管理站的 `super_admin` 可发起 15 分钟代登录。会话与原超管会话绑定，审计记录双方账号，禁止修改目标安全设置或进入管理功能。
- 帖子置顶使用 `POST /admin/post/<id>/pin/`，请求为 `{"pinned": true}` 或 `{"pinned": false}`，仅 `admin_forum` 及继承该权限的角色可用。操作幂等，记录变更前后状态，不改变审核状态、可见范围和编辑时间；已删除帖子只能取消置顶。评论置顶仍由发帖角色操作一级评论。
- Django admin 只能从安全中心进入，禁止密码入口。账号/权限页只读且不展示密码 hash；对应修改和 hash/salt 查看在独立管理站完成。

“仅自己可见”按发帖角色的全部成员授权；成员可在当前角色下阅读和回复。退组即失去访问权。媒体库存权限拆分为 `admin_file` 和 `admin_image`；视频播放令牌也遵循可见帖子、上传者与媒体管理员权限。已发给浏览器的内容及已有公共对象存储链接不能被追溯收回，生产存储与 CDN 的私有读取策略需与站点一致。

主站管理页与 Django admin 为显示的文本附加零宽会话标记，复制局部文本也会带标记；输入框值保持原样。背景叠加实名明水印、空间暗水印和频域水印。Django 静态脚本由主站前端 `scripts/build-admin-watermark.mjs` 生成，修改公共水印实现后应重新生成并收集静态资源。

## 旧数据库升级

**先备份，并在备份副本演练。** 新代码会作废旧登录令牌，现有管理员要重新完成邮箱、可信密钥和进阶认证。

1. 原项目缺少可跟踪的迁移文件；本次补入了原结构的初始迁移。对于已有业务表但没有这些迁移记录的旧库，先执行 `python manage.py adopt_legacy_migrations`。命令只读核对 27 个业务表的字段、主键与外键，并列出待补记记录。它不替代对字段类型、索引及部署历史的人工比对。
2. 确认旧库确实来自对应原始版本，再执行 `python manage.py adopt_legacy_migrations --apply`，然后 `python manage.py migrate`。结构不匹配会停止。不要直接以全局 `--fake` 忽略未知差异；仅用 `--fake-initial` 可能先遇到已应用的 Django admin 依赖历史不一致。
3. 已有初始迁移记录且与本项目一致的数据库直接 `migrate`。新数据库也直接 `migrate`。
4. 旧 Django 超级用户迁移为 `super_admin`；旧文件管理员保留文件及媒体管理权限。旧学校标签归为外校，之后按验证教育邮箱重新分组；历史实名仍保留但不视为已经认证。
5. 空投功能的模型、路由、页面已退役；旧 `gt_file_drop` 与关联表保留为历史数据，不主动删除。旧实例完全下线后，由数据库管理者决定归档期限。
6. 首位及旧超管认证接续见相邻 `shougt-sa/README.md`。已有新体系管理登录或首次初始化记录后，初始化通道永久关闭。

## 生产配置

复制并填写 `config.yaml.example`。本次没有连接真实邮件系统或生产数据库，也没有部署域名。

| 环境变量 | 用途 |
| --- | --- |
| `SHOUGT_SECRET_KEY` | 主站签名密钥；生产必填，所有主站实例一致 |
| `SHOUGT_TOTP_ENCRYPTION_KEY` | Fernet 密钥，建议独立保存；缺省由主站密钥派生，轮换前必须迁移现有 TOTP 数据 |
| `SHOUGT_MAIL_INGEST_SECRET` | 可信收件系统 HMAC 密钥；未配置时远程收件接口关闭 |
| `SHOUGT_SMTP_PASSWORD` | SMTP 凭据 |
| `SHOUGT_DB_NAME / USER / PASSWORD / HOST / PORT` | PostgreSQL 连接，默认端口 15432 |
| `SHOUGT_REDIS_URL` | 缓存 / Celery，默认 `redis://127.0.0.1:16379/4` |
| `SHOUGT_SQLITE_PATH` | 本地 SQLite 路径 |

生产主站必须 HTTPS；精确配置 WebAuthn RP ID 和 Origin。凭据绑定 RP，不能把 localhost 上注册的测试凭据迁到生产域名。独立管理子域不要加入主站 WebAuthn Origin 白名单，其操作统一回到主站完成 FIDO2。

主站前端通过同源 `/api/` 调用后端，代理应移除该前缀；Django 静态资源需由 `collectstatic` 后配置到 `/static/`。生产主站另需合适的 WSGI/ASGI 服务、HTTPS、缓存和后台任务进程。上传签名已改用本站配置的桶和区域；请同时配置前端媒体 CDN、可信回调及私有读取策略。

## 可信邮件接收

收件基础设施应验证 DKIM/SPF/DMARC 和对齐的真实发件人，把接收时间、信封收件人、已认证发件地址以及解码后的纯文本正文传给主站。**不能把来信自带的 `Authentication-Results` 或任意 `From` 头当成认证结果。** 拒绝多发件地址、对齐失败及无法确认真实发件人的邮件。

认证邮件的 `from_header` 必须来自收件系统实际验证、与已认证地址对应的原始 From 字段，拒绝无称呼、多发件人、分组地址、换行注入和地址不匹配；支持 RFC 2047 编码姓名。浏览器提交内容或来信自行声明的认证结果不能充当可信事件。`authenticated_sender` 也兼容包含称呼的唯一完整邮箱表示，但必须由可信适配器提供。姓名只在收件后写入申请，不改变已签署的挑战正文；管理员审核后才更新账号。

学号为“院校缩写-邮箱前缀”，默认取 `edu.cn` / `edu` / `ac.uk` 之前的院校域标签，忽略院系子域；`education_institution_aliases` 可按最长域名匹配配置例外。注册或换绑邮箱时也生成学号。最大长度扩大至 128，保留完整邮箱前缀。迁移 `0006_email_sender_identity` 添加发件人称呼来源和派生学号字段；已有申请若缺少收件称呼，须重新导入仍有效的原始邮件或重新申请，不能凭旧手填姓名审核。

事件格式：

```json
{
  "recipient": "renzheng@shouguatian.com",
  "authenticated_sender": "2531231@st.shou.edu.cn",
  "from_header": "魏子力<2531231@st.shou.edu.cn>",
  "dmarc_pass": true,
  "received_at": "2026-11-05T12:00:00+08:00",
  "message_id": "message-id-from-receiving-mta",
  "body": "完整纯文本邮件正文，包含 SHOU-VERIFY: 行"
}
```

受信任本地 MTA 可写入只对服务账号可读的 JSON，然后执行 `python manage.py ingest_verified_mail --event event.json`，或经 stdin 管道输入。命令不会发送邮件，只接收已经由收件系统认证的事件。

远程适配器使用 `POST /security/mail-ingest/`（同源代理外部路径 `/api/security/mail-ingest/`）；请求为 UTF-8 JSON。头 `X-Shou-Mail-Time` 为当前 Unix 秒数，`X-Shou-Mail-Signature` 为 `HMAC-SHA256(secret, ascii(timestamp) + b'.' + raw_request_body).hexdigest()`，允许时间差 5 分钟。收到邮件的时间来自可信 MTA，必须在签名后的 24 小时内；重放事件被拒绝。接口应仅对可信收件适配器开放，密钥不要进入浏览器或邮件正文。

## 验证

本地审计及红队回归见 `SECURITY-AUDIT.md`。认证限流依据连接来源 `REMOTE_ADDR`，不信任客户端提供的 `X-Forwarded-For`；部署代理应在可信入口规范化来源地址。共享角色邀请要求接收方允许加入或明确将邀请人列为信任用户；把别人加入自己的信任列表不会获得查看对方实名的权限。普通转账和举报回执同样遵循实名隐私。

深层嵌套的 JSON 和令牌解析失败统一返回 400 / 401，不泄露异常堆栈；JSON 对象、批量上传数组及原有表单解析行为保留。

图片上传按用户与 MD5 去重，新对象使用随机存储键；发帖只能引用本人图片或保留该帖已有图片。升级时运行迁移 `gt_file.0003_image_ownership`，它仅调整索引和约束，保留原有图片 ID、对象键和所属用户。上传大小必须为正数，不接受 SVG 图片元数据。硬币变动对当前余额加锁并原子写入，转账按统一顺序锁定双方余额。

```powershell
.\.venv\Scripts\python.exe manage.py check --settings=gt.test_settings
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run --settings=gt.test_settings
.\.venv\Scripts\python.exe manage.py test --settings=gt.test_settings
```

测试用真实本地 ES256 签名与生成的测试 PKI，不代表实体密钥型号、真实 PIV 中间件或生产 PostgreSQL/SMTP 已通过验收。浏览器联合测试从前端项目运行 `npm run test:e2e`；它创建隔离 SQLite/测试证书，并在 15173、18000、18443 启动测试服务，结束后清理进程。

原项目 GPLv3 许可证保留。独立管理应用的实现边界和来源记录见 `shougt-sa/PROVENANCE.md`。
