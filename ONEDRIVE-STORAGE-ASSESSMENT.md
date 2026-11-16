# OneDrive 媒体存储评估

核验日期：2026-11-16。评估对象为部署在首尔的 shou瓜田服务器，尚未获得目标 OneDrive 租户和首尔服务器的实际测试访问，因此没有实测延迟、吞吐量或费用结论。以下建议结合当前代码和官方文档。

## 结论

可以把 OneDrive 接入归档、备份和低频文件读取，并用 rclone/FUSE 挂载。当前阶段建议保留现有图片/视频服务，用独立适配器小范围验证 OneDrive。把 OneDrive 直接挂成主媒体目录不能兼容现有上传和播放流程，也会把远端限流、令牌和缓存故障引入用户请求链路。[S1–S6]

| 用途 | 建议 | 本项目需要处理的事项 |
| --- | --- | --- |
| 备份和冷归档 | 适合试点 | 后台复制、完整性校验、保留本地/独立副本与恢复验证 |
| 少量、低频下载 | 条件可行 | 每次应用鉴权、私有缓存、下载限流和错误恢复 |
| 头像和帖子热图 | 暂保留现有对象存储/CDN | 大量小请求、首字节时间、缩略图、缓存失效和匿名访问 |
| 视频源文件归档 | 条件可行 | 大文件上传会话、后台任务、校验完成才标为可用 |
| 视频直接点播 | 不作为当前主方案 | Range、seek、冷缓存和持续带宽；另行实现转码/切片/CDN |

这些是针对本项目的工程判断，不代表 Microsoft 给出的带宽承诺。

## 不能只改挂载路径

当前图片由 `gt_file/views.py` 的 `sign_upload` 签发 OSS 上传数据，普通文件使用 `doge_api.get_upload_data`，视频使用多吉云 `VodUploadInfo/did`、完成回调及播放令牌。`File.storage` 只有 `dogecloud` 选项。现有业务不是统一写入本地 `MEDIA_ROOT`，挂载一个目录不会把这些接口自动替换。

接入需要统一存储适配器和迁移：记录 `provider/drive_id/item_id/etag/size/sha256/state`，上传开始、完成复核、授权读取、删除及后台重试分离。视频源文件存储与转码/播放服务分别实现。已有资源 URL 和撤销语义必须保留或经过显式迁移。

## 首尔与权限边界

服务器位于首尔不等于 OneDrive 数据也位于首尔。Microsoft 365 的实际服务数据区域应在目标租户管理中心 Data Location 中确认；地区承诺受服务、租户和许可影响，不能套用到未经确认的个人版账号。官方区域表包含韩国，但不足以推导本项目的网络路径或延迟。[S4]

Microsoft Graph 的 `/content` 返回临时预授权下载地址，取得该地址的人无需另带 Authorization 即可下载，地址可能数分钟内过期。不能把它当作可永久保存或可即时撤回的私有资源 URL，也不能写入公开日志、帖子或分析系统。[S1]

私有文件应先检查应用里的资源归属、帖子可见性、封禁/撤销和当前身份，再由服务端代理或受控缓存返回。缓存命中同样要鉴权，避免匿名访问、跨账号复用和撤权后继续读取。禁止把任意用户传入的 URL/磁盘路径映射成下载目标；只接受数据库登记的资源 ID。访问令牌、刷新令牌和 rclone 配置保存在服务器受控配置目录，不进入前端或 Git。

## 上传、播放与限流

Graph 大文件使用可恢复上传会话：分片顺序提交，单次请求小于 60 MiB，按文档要求使用 320 KiB 的整数倍分片；完成后核验远端大小、版本和应用校验值，再把资源状态改为可用。[S2]

Range 必须发往实际下载地址而不是 Graph `/content`。官方说明上游可能忽略 Range 并返回完整 200；代理须正确处理 200/206/416、Content-Range、取消请求和上游过期，不能把完整内容伪装为局部分片。不要将下载 URL 的寿命当作视频会话寿命。[S1]

SharePoint/OneDrive for Business 可能返回 429 或 503。按 `Retry-After` 等待，配合全局并发上限、退避和后台队列；不遵守可能加重限流乃至封锁。公开热门内容会放大请求量，因此需要缓存和明确的降级路径。[S3]

## 若试用挂载

rclone 提供 OneDrive 后端和 VFS 缓存。先使用专用测试目录、小权限服务账号、只读挂载及本地 SSD 缓存，仅供应用进程读取，避免直接由 Web 静态目录公开整个盘。不要开启 rclone 的额外 HTTP/RC 服务。写入先保留在本地暂存区，用任务队列上传并校验，不把 FUSE 写入返回当成业务已持久化成功。[S5,S6]

`--vfs-cache-mode full` 有利于随机读取，但增加本地容量和首次下载成本；设置缓存目录、清理目标和空闲空间告警。`--vfs-cache-max-size` 是清理控制，正在打开的文件等情况仍需额外磁盘余量，不能作为严格磁盘配额。监测令牌刷新、挂载存活、空间耗尽和远端变更；缓存故障时返回可重试错误，不能回退为未鉴权直链。[S5]

本轮只做评估，没有创建 OAuth 应用、授权 OneDrive、挂载磁盘、迁移媒体或启动端口服务。

## 验收计划

用自有合成图片、文件和视频，在目标首尔服务器对比现有存储、Graph 代理和只读挂载。分别记录冷/热缓存、1/5/10 并发时的 p50/p95 首字节、总耗时、吞吐量、错误率、429/503、缓存空间和服务器出站流量；测视频首播、随机 seek、重复 Range 和取消请求。

另外验证授权过期、令牌刷新失败、撤权、删除、远端版本改变、缓存满、断网后恢复以及服务重启。试点期间保留原资源和可回滚映射，先从低频附件或归档开始；达成产品约定的延迟/错误率/恢复目标后再决定是否扩展。容量、许可和流量费用以实际账号方案与测量值核算。

## 官方资料

- S1 Graph 下载与 Range：`https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0`
- S2 Graph 可恢复上传：`https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession?view=graph-rest-1.0`
- S3 SharePoint Online 限流：`https://learn.microsoft.com/en-us/sharepoint/dev/general-development/how-to-avoid-getting-throttled-or-blocked-in-sharepoint-online`
- S4 Microsoft 365 数据位置：`https://learn.microsoft.com/en-us/microsoft-365/enterprise/o365-data-locations?view=o365-worldwide`
- S5 rclone mount/VFS：`https://rclone.org/commands/rclone_mount/`
- S6 rclone OneDrive：`https://rclone.org/onedrive/`
