# 两级分发：骨干发布 → 当地 mesh 下载（文件 + 流）

本文说明 mesh 作为 CDN 式分发系统时的两级拓扑，以及仓库内的验证方式。
目标：**内容先发布到骨干节点（origin），消费方通过当地 mesh 下载**；文件与流都走这条路径。

## 拓扑

```
  publisher ──PUT──▶ 骨干节点 (gateway A / origin, M3 CAS)
                            │  Range GET（拉取并校验）
                            ▼
                    当地 mesh 节点 (gateway B, 本地缓存)
                            │  playlist + Range/206
                            ▼
                    当地客户端（文件下载 / 流播放）
```

- **骨干节点**：权威数据源。发布 = 文件切 chunk → M3 V2 manifest（逐块 SHA-256 + 对象 digest）
  存入骨干的不可变 CAS；经 S3 网关（SigV4）PUT，并以 Range/206 对外服务。
- **当地 mesh 节点**：从骨干拉取对象并缓存到本地 CAS（= 边缘缓存），对当地客户端提供
  HLS playlist（`GET /:bucket/:object/playlist.m3u8`）与按 segment 的 Range/206。
- **当地客户端**：文件 = 整对象 Range 下载（或经 `mesh_sync_engine` 增量/断点续传）；
  流 = 先取 playlist，再逐 segment Range 拉取（标准 HLS 播放器可对接）。

## 已有实现（`事实`）

| 职责 | 实现 |
|---|---|
| 不可变寻址/存储 | `m3_chunk_store` + `m3_object_manifest` V2（CID=SHA-256） |
| 骨干发布 | `m3_gateway_main` PUT（SigV4）+ `mesh_stream_media_main publish` |
| 骨干服务 | 网关 GET / Range/206 + `playlist.m3u8` 路由（P14/P15） |
| 当地拉取/缓存 | 网关 GET→PUT 缓存；亦可经 `mesh_stream_multisource`（P2/P10）或 `mesh_sync_engine`（P3） |
| 当地服务 | 同网关（playlist + Range/206），对象级 CAS 缓存 + `m3_repair`/`m3_gc` |
| 就近发现 | `mesh_stream_discovery`（P6/P11）、service record |
| 多节点 mesh | `run_m3_gateway_mesh_smoke.ps1`、`run_m3_raft_cluster.ps1` |
| 软件发布 | `release pack` 多文件清单 + 版本 + 路径→对象映射（P17）；
  `release.txt` 列表路由（P21） |
| release 文件下载 | `GET /:bucket/:object/<path>` 按清单路径解析并 Range 服务（P23）；
  C 侧 `release pull` SigV4 下载（P22） |
| release 入口点 | `GET /:bucket/:object?listing=1` 直接下载清单；
  `?redirect=<segment>` 302 重定向（如 release.txt）；无查询时返回原始清单字节（P30） |
| release 发布/拉取 | `release publish` 一键打包 + SigV4 PUT 发布到骨干（P24）；
  `release pull` 按名从网关取清单后下载（P25） |
| release 深层路径 | `--paths` 三元组指定释放内路径（`lib/x64/…`）；
  pull 自动建子目录；网关端点支持多层路径（P26） |
| release 两级镜像 | `release mirror <name> --from <骨干> --to <当地>`：
  从骨干网关拉取并发布到当地边缘网关（P27） |
| live 跨网关切换 | 确定性 live 会话：两个网关服务相同节目片段；
  `mesh_stream_live_client_main` 主网关失效后切换到备用，字节一致（P29） |

## 验证

`mesh/scripts/run_mesh_two_tier_smoke.ps1`（两个真实网关进程）：
1. 客户端 publish（manifest + 4 段 HLS playlist）
2. 骨干网关 A：签名 PUT 发布对象
3. 当地 mesh 网关 B：从 A 拉取整对象 → 校验字节 → 缓存（PUT 到本地）
4. 当地客户端从 B：
   - 流：`playlist.m3u8` + 4 段 `Range bytes=…` → 全部 206 + 字节一致
   - 文件：整对象下载 → 字节一致
5. exit 0

## 已完成的可选增强（验证状态）

- **发布清单 / 下载端点 / live-over-HTTP / C 侧拉取器 / 深层路径 /
  两级镜像 / live 跨网关切换**：P17–P29 均已实现并有 smoke 覆盖。
