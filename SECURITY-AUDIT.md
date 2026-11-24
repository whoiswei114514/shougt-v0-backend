# 本地安全审计与红蓝对抗报告

最后更新：2026-11-24（Asia/Shanghai）。

## 审计范围与说明

本报告汇总针对主站后端（Django API 与权限架构）、主站前端（Vue 3 / Vite / WebPIV / DOM 净化）以及独立特权管理站（mTLS / FIDO2 审批 / 硬件制卡 / 水印溯源）的静态代码审查与本地隔离环境实战红蓝对抗结果。

- **验证范围边界**：实战对抗在本地回环高端口、测试 SQLite 与生成测试 CA 下进行，未连接真实生产数据库、SMTP 基础设施或在线第三方漏洞库执行线上渗透扫描。
- **生产上线前置要求**：正式部署仍需人工核验生产 CA / subCA / CRL 分发、PostgreSQL 最小权限配置、可信代理转发头（`REMOTE_ADDR`）、对象存储私有读取策略与实际硬件凭证链。

## 已复现并修复的安全问题

| 类别 | 发现的问题与风险 | 落地的修复措施 |
| --- | --- | --- |
| **会话范围与代登录越权** | `AuthSession.scope` 校验不够收紧或异常令牌绕过时，`reauth` / `onboarding` 会话或代登录状态可能越权访问敏感设置 | 限定 `scope` 白名单（仅 `full`、`enrollment`、`impersonation`）；严禁 `impersonation` 访问 `/admin/`、`/django-admin/`、`/security/`、`/user/setting/`（含隐私设置）及 `/role/` 写接口；`impersonation-exchange` 核验双方会话与启用状态；代登录标签页隔离在 `sessionStorage`，不污染管理员主会话。 |
| **管理权限、只读与临时特权越界** | 普通管理员（`admin_user` / `admin_admin`）、只读读者或临时特权账号可能操作高权限目标或签发下游证书 | 禁止 `admin_user` 重置管理账号密码；`protect_user` 同时检查有效及过期特权角色；`global_reader` 与测试签发 CA 凭证全线强制只读；新增 `can_sign_issuance_requests()`，阻止持短期证书或临时特权者继续签署下游证书；3 分钟查看窗口（`browse_access`）严格排除 `password_hash`、`impersonate`、`inspect_watermark` 与一切写入／制卡动作，并在登出、撤权或特权到期时立即失效。 |
| **匿名角色去识别与 IDOR** | 匿名／共享角色、孤立内容、举报表与图片检索可能泄露底层实名、学号或他人私有媒体 | `RoleSerializer`、`PostAdminViewset`、`CommentViewset` 与举报接口统一带入请求上下文与可见性边界（隐藏对象与不存在对象统一返回 404，`is_private=True` 严格隐藏 `user_info`）；图片去重与 `ImageUserIdSearchFilter` 按普通用户作用域严格隔离；信任名单采取单向校验。 |
| **前端 XSS 与跨窗口安全** | 富文本、Markdown、KaTeX / Mermaid 渲染、URL 票据或 `postMessage` 存在注入或会话泄露面 | 文章、评论与编辑器统一通过 DOMPurify 白名单过滤，移除 `SimpleRichText.vue` 的 `v-html` 与无保护外链；彻底删除浏览器 `.p12` 导出与 WebCrypto 私钥缓存代码；页面初始化最早期提取并清除 `#ticket=`；对 `/security/approve` 及本地助手（`127.0.0.1:10000–65535`）校验精确 Origin 与加密挑战。 |
| **高并发竞争条件** | 多线程并发下 SQLite 默认 `DEFERRED` 事务与非原子赞数／挑战消费触发 `database is locked` 或重放风险 | SQLite 统一开启 `timeout=30` 与 `IMMEDIATE` 事务模式；WebAuthn `claim_challenge` 改为原子条件更新；硬币转账、发帖配额及帖子／评论点赞全程使用 `select_for_update()` 与 `F()` 原子更新，并发下票据与单次操作严格只能成功一次。 |
| **边界溢出与账号锁死（DoS）** | 极大浮点数（`1e308` 累加为 `inf`）、超 64 位整数、Unicode `.isdigit()` 与 JSON `NaN` 导致 HTTP 500 甚至账号无法登录 | 限制硬币单次变更幅度与 `isfinite` 总余额上限；全栈统一限制 signed 64-bit SQLite 整数上界、严格以 `isascii()` 判别数字 ID 并拒收 `NaN`/`Infinity`；前端管理视图补齐匿名及已删除作者空值保护。 |

## 测试与对抗验证记录（2026-11-24）

以下全部检查均在最终修改落地且所有预览服务关闭后独立完成：

| 验证维度 | 执行内容与范围 | 结果 |
| --- | --- | --- |
| **主站后端单元测试** | `SHOUGT_MODE=dev` 下运行 `manage.py test`（认证、权限、隐私红队、管理站整合、安全密钥与并发回归） | **260 项全部通过（OK）** |
| **独立特权管理站测试** | `unittest discover -s tests -v`（mTLS、CRL、委派 CA、3 分钟查看窗口、整数 / JSON 边界、本地桥接、TPM/PIV、水印取证） | **115 项全部通过（OK）** |
| **主站前端构建与单测** | `npx vue-tsc --noEmit`、`npm run build`、`node --test tests/webpiv.test.mjs` | 类型检查与打包通过；WebPIV / 安全测试 **21/21 通过** |
| **实机红蓝对抗（隔离服务）** | 启动 `15173` / `18000` / `18443` 真实服务与桥接，运行 HTTP、mTLS 与真实 Chromium Playwright 测试 | HTTP 探针（水平 IDOR 246 项、垂直提权 362 项、溢位/异常 126 项、多线程并发 9 类）全通过；mTLS 探针 37/37 通过；Playwright E2E 28 passed, 1 skipped（独立高可信配置用例）, 0 failed + DOM XSS / 跨窗口专题 3/3 通过 |

## 本地复现命令

1. **主站后端完整检查与测试**：

```powershell
$env:SHOUGT_MODE = "dev"
.\.venv\Scripts\python.exe manage.py check --settings=gt.test_settings
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run --settings=gt.test_settings
.\.venv\Scripts\python.exe manage.py test
```

2. **独立特权管理站测试**：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

3. **前后端联调端到端测试**（在前端项目目录运行）：

```powershell
npm ci
npm run test:e2e
# 单独运行高可信密钥展示用例
$env:SHOUGT_UI_CERTIFIED_KEY = "1"
npm run test:e2e -- --grep "certified key shows gold"
Remove-Item Env:SHOUGT_UI_CERTIFIED_KEY
```

## 上线前人工验收要点

- 核查生产环境 Python 与 npm 第三方依赖的现行安全通告。
- 在真实环境中验收 PostgreSQL `SERIALIZABLE` 事务、Redis / Celery、真实 MTA 签收转发、存储私有读取策略及 HTTPS / WebAuthn RP 配置。
- 使用物理安全密钥、实体 PIV 智能卡与读卡器、系统 minidriver 及正式 CA / subCA / CRL 验证端到端 mTLS 握手与吊销阻断效果。
- 若业务需要防范具备管理卡的恶意操作员，需另行引入设备原厂专属可信硬件证明体系；当前方案仍依赖受控工作站及现场 CA 操作员规程。
