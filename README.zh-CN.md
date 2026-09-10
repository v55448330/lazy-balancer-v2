# Lazy Balancer V2

[English](README.en.md) | 简体中文

基于 **Caddy v2.11 + caddy-l4** 的可视化负载均衡管理平台（Go + Vue 3 单容器交付），内置完整 WAF 安全防护。

## 功能特性

- 🔄 **负载均衡** — HTTP/HTTPS/TCP/UDP 四层代理，支持轮询/加权/IP 哈希/最少连接/Cookie 会话粘性
- 🛡️ **WAF 安全防护** — OWASP CRS 规则集 + 自定义规则 + IP 访问控制 + 地域拦截 + 限流
- 📜 **证书管理** — ACME 自动签发（Let's Encrypt / ZeroSSL），DNS-01 / HTTP-01 挑战，自动续签
- 📊 **监控仪表盘** — 实时流量 / 连接数 / 上游健康 / 安全事件总览
- 🔗 **集群管理** — 主从节点配置同步，TOFU 安全基线，故障切换
- 🤖 **MCP 工具链** — 127 个 AI 可调用运维工具，支持 API Key 认证

## 快速开始

```bash
docker run -d \
  --name lazy-balancer \
  -p 80:80 -p 443:443 -p 8000:8000 \
  -v ./data:/app/data \
  -v ./certs:/app/certs \
  -v ./logs:/app/logs \
  v55448330/lazy-balancer-v2:latest
```

打开 `http://localhost:8000` 进入管理面板。

## 交流群

<div align="center">

**LazyBalancer 交流群**

群号：**303410331**

<img src="docs/qq-group-qr.webp" alt="LazyBalancer QQ 交流群" width="280">

扫一扫二维码，加入群聊

</div>

## 文档

- [生产部署指南](docs/production-tuning.zh-CN.md)
- [Docker Compose 编排](docker-compose.yml)
- [API 文档](http://localhost:8000/docs)（部署后可用）
- [OpenAPI 规范](http://localhost:8000/api/v1/openapi.yaml)（部署后可用）

## 技术栈

| 层 | 技术 |
|---|---|
| 代理引擎 | Caddy v2.11.4 + caddy-l4 v0.1.2 |
| WAF | Coraza v3.7 + OWASP CRS v4.29 |
| 后端 | Go 1.26 + Gin + SQLite |
| 前端 | Vue 3 + TypeScript + Element Plus + Vite |
| 交付 | Docker 多架构（amd64/arm64） |

## License

[MIT](LICENSE)
