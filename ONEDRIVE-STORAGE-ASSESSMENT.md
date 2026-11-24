# OneDrive 媒体存储可行性评估

评估日期：2026-11-16（针对首尔部署节点与现有 shou瓜田媒体接口）。  
以下结合代码现状与 Microsoft 官方文档给出工程评估；因尚未取得目标租户并在首尔节点完成实测，具体网络延迟、吞吐和账单费用需以试点压测为准。

## 结论摘要

**OneDrive 适合用于冷备份、归档和少量低频附件下载，不适合直接挂载为主媒体目录来承载帖子热图或视频直接点播。** 当前阶段建议继续由现有对象存储与 CDN 服务公开图片及视频，并通过独立存储适配器小范围试点 OneDrive [S1–S6]。

| 业务场景 | 建议结论 | 需配套的工程实现 |
| --- | --- | --- |
| **备份与冷归档** | **适合试点** | 异步后台同步、SHA-256 校验、保留本地或独立副本及恢复演练 |
| **低频文件下载** | **条件可行** | 每次读取先过应用鉴权、受控私有缓存、并发限流与故障退避 |
| **头像与帖子热图** | **暂不迁移** | 频繁小文件首字节延迟高、缺少原生 CDN 与实时缩略图处理 |
| **视频源文件归档** | **条件可行** | Graph 大文件分片上传会话、后台校验完成后再标记可用 |
| **视频直接点播** | **不作为主方案** | `Range` / Seek 响应与回源带宽不稳，应保留转码与独立 CDN 播放 |

## 为什么不能直接修改本地挂载路径

当前媒体链路并非统一写入本地 `MEDIA_ROOT`，而是按业务拆分在不同对象存储接口中：

- 图片通过 [gt_file/views.py](gt_file/views.py) 的 `sign_upload` 签发直传数据。
- 普通文件依赖 `doge_api.get_upload_data`（`File.storage` 当前仅有 `dogecloud` 选项）。
- 视频依赖多吉云 `VodUploadInfo/did`、上传完成回调与播放令牌。

直接挂载远端磁盘既无法接管直传签名流程，也会把远端限流和网络抖动拖进业务请求线程。规范接入方式是先引入统一存储适配器并登记 `provider / drive_id / item_id / etag / size / sha256 / state`，将发起上传、完成确认、鉴权读取和异常重试解耦，同时维持既有 URL 与撤权语义。

## 区域归属与访问权限边界

- **服务器在首尔不等于数据在首尔**：Microsoft 365 / OneDrive 实际数据驻留区域应在目标租户管理中心的 Data Location 核实，且个人版账号不提供企业级地区保证 [S4]。
- **不要把 Graph `/content` 预授权链接直接发给前端或日志**：该接口返回短期有效的预签名下载地址，持有地址即可免 `Authorization` 下载，无法撤回且几分钟内可能过期 [S1]。
- **私有访问必须服务端鉴权**：每次下载须检查资源所属权、帖子可见范围与账号封禁状态，再由服务端代理或受控私有缓存输出；缓存命中同样要鉴权，严禁直接拼接用户传入的 URL 或路径。OAuth 令牌和 rclone 配置仅存于服务器受控配置目录，不得进入前端或仓库。

## 上传、点播与限流控制

- **可恢复分片上传**：调用 Graph Upload Session 须按顺序上传，单片小于 60 MiB 且大小为 320 KiB 的整数倍，上传完毕核对远端文件尺寸与校验后再设为可用 [S2]。
- **Range 转发要求**：`Range` 请求须转发至实际预签名下载地址，且上游可能忽略分片要求返回 `200`；代理层需正确处理 `200 / 206 / 416`、`Content-Range` 与连接中断，不要把下载链接寿命当成视频授权寿命 [S1]。
- **应对 429 / 503 限流**：SharePoint / OneDrive for Business 遇到高并发会返回限流状态码 [S3]。务必遵循 `Retry-After` 等待，搭配全局并发上限、退避重试与热资源缓存。

## 若使用 rclone / VFS 挂载

- 仅供应用进程使用小权限账号和专用子目录执行**只读挂载**，禁止通过 Web 服务器静态目录直接公开挂载盘，并保持 rclone 额外的 HTTP / RC 控制接口关闭 [S5, S6]。
- 文件写入仍应先落盘本地队列，确认上传并校验通过后再移除本地暂存，避免把 FUSE 返回成功当作远端持久化完成。
- 使用 `--vfs-cache-mode full` 时需监控本地 SSD 剩余容量与令牌刷新：`--vfs-cache-max-size` 只是清理目标而非硬配额，正被打开的文件仍可能占满磁盘 [S5]。

## 试点验收标准

1. 在目标首尔主机对比现有对象存储、Graph 代理与 VFS 挂载，在冷／热缓存及 1 / 5 / 10 并发下测量首字节时间（p50 / p95）、吞吐、出站流量、429 比例及缓存占用。
2. 覆盖视频首播、随机拖动 Seek、重复 `Range` 与中途取消，以及令牌过期、远端变更、缓存写满与断网恢复测试，确认试点期间原资源始终可回滚。

## 官方参考资料（2026-11-16 核验）

- **S1** Graph 下载与 Range：`https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0`
- **S2** Graph 可恢复上传：`https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession?view=graph-rest-1.0`
- **S3** SharePoint Online 限流说明：`https://learn.microsoft.com/en-us/sharepoint/dev/general-development/how-to-avoid-getting-throttled-or-blocked-in-sharepoint-online`
- **S4** Microsoft 365 数据位置：`https://learn.microsoft.com/en-us/microsoft-365/enterprise/o365-data-locations?view=o365-worldwide`
- **S5** rclone mount / VFS：`https://rclone.org/commands/rclone_mount/`
- **S6** rclone OneDrive 后端：`https://rclone.org/onedrive/`
