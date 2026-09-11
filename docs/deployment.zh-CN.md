# 部署指南

## 挂载目录

| 容器路径 | 内容 | 必需 |
|---|---|---|
| `/app/data` | 业务/审计/指标数据库、ACME 账户密钥 | **是** |
| `/app/certs` | 证书与私钥 | **是** |
| `/app/logs` | 应用日志、Caddy 日志、按规则访问日志 | 推荐 |
| `/app/waf` | CRS 规则、IP2Region xdb、Coraza 审计日志 | 推荐 |
| `/app/config` | Caddyfile（仅高级定制） | 可选 |

> 不挂载 `/app/waf` 时，容器重建会将 CRS 回退到镜像捆绑版本；系统自动将更新后的规则树快照持久化到数据卷并在启动时对账恢复。数据库是配置的唯一真实来源。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `JWT_SECRET` | 自动生成 | JWT 签名密钥；生产建议显式设置 |
| `LOG_FILE` | 空 | 应用日志同时写入此文件 |
| `NODE_NAME` | `node-1` | 集群注册的默认节点名 |
| `APP_VERSION` | 构建时注入 | 显示版本号 |
| `TZ` | 数据库 `timezone` | 进程时区 |

## 端口

| 端口 | 用途 |
|---|---|
| `8000` | 管理面板与 REST API |
| `80 / 443` | HTTP/HTTPS 代理流量 |
| `2019` | Caddy Admin API（仅回环） |
| 自定义 | TCP 规则监听端口 |

> Linux 推荐 `--network host`。macOS/Windows 用 `-p 8000:8000 -p 80:80 -p 443:443 -p 443:443/udp`（UDP 为 HTTP/3 必需）。

## 生产参数

**文件描述符**是唯一必需项（已内置在 compose 中）：

```bash
--ulimit nofile=1048576:1048576
```

内核级调优（sysctl）均为可选——默认值已生产就绪，完整指南见 [生产调优](production-tuning.zh-CN.md)。

## 品牌定制

`data/branding.json``data/branding.json`（启动时载入内存；文件修改即时生效——mtime 变化检测自动重载）：

```json
{ "app_name": "Lazy Balancer", "footer_text": "Copyright © 2026 XiaoBao.", "landing_text": "", "version": "" }
```

| 字段 | 说明 | 空值行为 |
|---|---|---|
| `app_name` | 产品名（侧栏/登录页/拦截页） | 回退 `Lazy Balancer` |
| `footer_text` | 页脚文案 | 回退默认页脚（含 GitHub 链接） |
| `landing_text` | 空域名命中网关时的提示页文案 | 回退 `Lazy Balancer V2 is running!` |
| `version` | 覆盖构建版本号显示 | 回退构建版本 |

## 配置备份

- **导出**：系统信息 → 配置备份（完整 JSON，含凭证与证书）
- **导入**：校验失败零写入；v2 备份需 ≥ v2.1.2 导出
- **v1 迁移**：选择 nginx 版备份自动转换

## 四道合法性关卡

每次配置写入经过：前端校验 → 后端字段校验 → caddy CLI 校验 → 事务内应用。非法值 400 拒绝、零落库。
