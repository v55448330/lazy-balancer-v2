# Lazy Balancer V2 - 运维指南

> **已归档**：本文为历史设计文档，不代表当前实现（当前：首次访问初始化管理员、集群角色存于数据库、凭证在页面配置）。


**文档版本**: 1.0
**更新日期**: 2026-04-17
**目的**: 部署、配置、故障排查，支持日常运维操作

---

## 1. 快速开始

### 1.1 Docker Compose 部署

```bash
# 克隆项目
git clone https://github.com/your-repo/lazy-balancer-v2.git
cd lazy-balancer-v2

# 启动服务
docker compose up -d

# 查看状态
docker compose ps

# 查看日志
docker compose logs -f
```

### 1.2 访问服务

- **Web UI**: http://localhost (或 http://localhost:80)
- **API**: http://localhost:8000
- **Caddy Admin**: http://localhost:2019

### 1.3 默认凭据

- 用户名: `admin`
- 密码: `admin123`

---

## 2. Docker Compose 配置

### 2.1 基本配置

```yaml
# docker-compose.yml
version: '3.8'

services:
  lazy-balancer:
    build: .
    container_name: lazy-balancer
    ports:
      - "80:80"      # HTTP
      - "443:443"    # HTTPS
      - "8000:8000"  # API
      - "2019:2019"  # Caddy Admin
    volumes:
      - ./data:/app/data
    environment:
      - ADMIN_USER=admin
      - ADMIN_PASSWORD=admin123
      - NODE_NAME=master
      - NODE_MODE=master
    restart: unless-stopped
```

### 2.2 多节点配置

**Master 节点**:
```yaml
environment:
  - NODE_MODE=master
  - NODE_NAME=master
```

**Slave 节点**:
```yaml
environment:
  - NODE_MODE=slave
  - MASTER_URL=http://10.0.0.1:8000
```

### 2.3 DNS Provider 配置 (可选)

```yaml
environment:
  # DNSPod
  - DNSPOD_ID=your_id
  - DNSPOD_TOKEN=your_token
```

---

## 3. 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| ADMIN_USER | admin | 初始管理员用户名 |
| ADMIN_PASSWORD | admin123 | 初始管理员密码 |
| NODE_NAME | master | 节点名称 |
| NODE_MODE | master | master/slave |
| MASTER_URL | - | Slave 模式下的 Master 地址 |
| DNSPOD_ID | - | DNSPod API ID |
| DNSPOD_TOKEN | - | DNSPod API Token |

---

## 4. 数据目录

```
data/
├── lazy-balancer.db    # SQLite 数据库
├── config/            # 配置文件（可选）
└── caddy/             # Caddy 证书存储
```

### 4.1 备份数据库

```bash
# 停止服务
docker compose down

# 备份
cp -r data/data data/data.bak.$(date +%Y%m%d)

# 启动服务
docker compose up -d
```

### 4.2 重置数据库

```bash
# 停止服务
docker compose down

# 删除数据目录
rm -rf data

# 启动服务（会重新初始化）
docker compose up -d
```

---

## 5. 日志

### 5.1 应用日志

```bash
# 实时日志
docker compose logs -f

# 最近 100 行
docker compose logs --tail 100

# 最近 1 小时
docker compose logs --since 1h
```

### 5.2 日志级别

默认日志级别: `info`

**调试模式**:
```yaml
environment:
  - LOG_LEVEL=debug
```

### 5.3 Caddy 日志

Caddy 日志位于容器内的 `/root/.config/caddy/`

```bash
# 查看 Caddy 日志
docker compose exec lazy-balancer cat /root/.config/caddy/caddy.log
```

---

## 6. 健康检查

### 6.1 API 健康检查

```bash
curl http://localhost:8000/health
# 返回: {"status": "ok"}
```

### 6.2 Caddy Admin 健康检查

```bash
curl http://localhost:2019/config/
# 返回 Caddy 配置 JSON
```

### 6.3 规则配置健康检查

```bash
# 获取规则详情
curl http://localhost:8000/api/rules/lb_abc123xyz12 \
  -H "Authorization: Bearer <token>"

# 获取规则 Caddy 配置
curl http://localhost:8000/api/rules/lb_abc123xyz12/caddy-config \
  -H "Authorization: Bearer <token>"
```

---

## 7. 故障排查

### 7.1 容器无法启动

**检查日志**:
```bash
docker compose logs lazy-balancer
```

**常见原因**:
- 端口被占用 (80, 443, 8000, 2019)
- 数据目录权限问题
- Docker 网络问题

**解决方案**:
```bash
# 检查端口占用
lsof -i :80

# 修复数据目录权限
chmod 755 data
```

### 7.2 API 返回 404

**检查服务是否运行**:
```bash
docker compose ps
```

**检查 Gin 是否启动**:
```bash
curl http://localhost:8000/health
```

### 7.3 规则创建失败 (400/500)

**检查 Caddy 配置**:
```bash
curl http://localhost:2019/config/
```

**检查端口冲突**:
```bash
# 查看现有规则
curl http://localhost:8000/api/rules \
  -H "Authorization: Bearer <token>"
```

### 7.4 Caddy 配置应用失败

**验证配置**:
```bash
curl -X POST http://localhost:2019/load?validate=true \
  -H "Content-Type: application/json" \
  -d @config.json
```

**手动重新加载**:
```bash
curl -X POST http://localhost:8000/api/config/reload \
  -H "Authorization: Bearer <token>"
```

### 7.5 数据库损坏

**备份并重建**:
```bash
# 停止服务
docker compose down

# 备份现有数据
mv data data.broken

# 启动新服务（会重新初始化）
docker compose up -d

# 手动恢复数据（如有备份）
```

---

## 8. 性能优化

### 8.1 数据库优化

SQLite 使用 WAL 模式，已启用外键约束。

**定期 VACUUM** (可选):
```bash
docker compose exec lazy-balancer sqlite3 /app/data/lazy-balancer.db "VACUUM;"
```

### 8.2 Caddy 性能

Caddy 默认配置适合中小规模负载。

**调整worker数量** (高级):
```bash
# 修改 docker-compose.yml
environment:
  - CADDY_WORKERS=2
```

---

## 9. 安全

### 9.1 修改默认密码

登录后访问 **设置 → 用户管理** 修改密码。

### 9.2 API Key 管理

使用 API Key 进行机器间通信:

1. 访问 **设置 → API Keys**
2. 创建新 Key
3. 使用 `X-API-Key` header

```bash
curl http://localhost:8000/api/rules \
  -H "X-API-Key: lb_key_xxxxxxxxxxxx_abcd1234"
```

### 9.3 防火墙配置

```bash
# 只开放必要端口
firewall-cmd --add-port=80/tcp --permanent
firewall-cmd --add-port=443/tcp --permanent
firewall-cmd --add-port=8000/tcp --permanent
firewall-cmd --reload
```

---

## 10. 升级

### 10.1 Docker Compose 升级

```bash
# 拉取新镜像
docker compose pull

# 重建容器
docker compose up -d --build

# 验证
docker compose ps
curl http://localhost:8000/health
```

### 10.2 数据迁移

升级前备份数据:
```bash
cp -r data data.backup.$(date +%Y%m%d)
```

---

## 11. 常用命令

| 命令 | 说明 |
|------|------|
| `docker compose up -d` | 启动服务 |
| `docker compose down` | 停止服务 |
| `docker compose down -v` | 停止并删除数据 |
| `docker compose restart` | 重启服务 |
| `docker compose logs -f` | 查看日志 |
| `docker compose build --no-cache` | 强制重建 |
| `docker compose exec lazy-balancer sh` | 进入容器 |

---

## 12. 目录结构

```
lazy-balancer-v2/
├── cmd/server/main.go          # 后端入口
├── internal/                   # 业务逻辑
│   ├── config/
│   ├── db/
│   ├── handlers/
│   ├── middleware/
│   ├── models/
│   └── services/
├── web/                        # 前端源码
│   └── src/
├── ui/                         # 前端构建产物
├── data/                       # 数据目录
├── docs/                       # 文档
├── docker-compose.yml
├── Dockerfile
├── Makefile
└── AGENTS.md                   # 项目知识库
```

---

## 13. 相关文档

- [系统概述](./1-overview.md)
- [详细架构](./2-architecture.md)
- [API 参考](./3-api.md)
- [配置规则规范](./4-config-rules.md)