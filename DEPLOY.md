# Trojan-Go 部署方案说明

本项目提供三种部署脚本，适用于不同场景。

## 脚本概览

| 脚本 | 部署方式 | 交互方式 | 目标用户 | 代码来源 |
|------|----------|----------|----------|----------|
| `install.sh` | 原生二进制 + systemd | 交互式 | 运维人员 | GitHub Release |
| `install-docker.sh` | Docker-Compose | 交互式 | 运维人员 | 远程镜像 |
| `install-ai.sh` | 原生/Docker | 命令行参数 | AI Agent / CI-CD | 源码编译 |

---

## 1. install.sh（直接部署）

### 功能特性

- 从 GitHub 拉取最新 release 包
- 自动检测系统架构（amd64/arm64）
- 自动安装缺失依赖
- 交互式配置向导
- 注册 systemd 服务
- 支持备份与回滚

### 使用方法

```bash
# 安装
sudo bash install.sh

# 卸载
sudo bash install.sh --uninstall
```

### 安装流程

```
环境预检 → 获取最新版本 → 下载安装包 → 配置初始化 → 注册systemd → 启动服务
```

### 安装路径

| 文件类型 | 路径 |
|----------|------|
| 二进制文件 | `/usr/local/bin/trojan-go` |
| CLI 管理工具 | `/usr/local/bin/trojan` |
| 配置文件 | `/etc/trojan-go/config.json` |
| 路由规则 | `/usr/share/trojan-go/` |
| systemd 服务 | `/etc/systemd/system/trojan-go.service` |

### 服务管理

```bash
systemctl start trojan-go     # 启动
systemctl stop trojan-go      # 停止
systemctl restart trojan-go   # 重启
systemctl status trojan-go    # 查看状态
journalctl -u trojan-go -f    # 查看日志
```

---

## 2. install-docker.sh（Docker-Compose 部署）

### 功能特性

- 自动检查/安装 Docker 环境
- 自动检查/安装 Docker Compose
- 交互式配置向导
- 远程镜像部署
- 健康检查配置
- 日志轮转配置

### 使用方法

```bash
# 安装
sudo bash install-docker.sh

# 卸载
sudo bash install-docker.sh --uninstall
```

### 安装流程

```
环境预检 → 检查Docker → 检查Compose → 初始化项目 → 配置向导 → 生成compose → 启动服务
```

### 项目目录结构

```
/opt/trojan-go/
├── docker-compose.yml    # Compose 配置文件
├── config.json           # Trojan-Go 配置
├── certs/                # TLS 证书目录
│   ├── fullchain.crt
│   └── private.key
├── data/                 # 数据卷
└── geodata/              # 路由规则文件
```

### 服务管理

```bash
cd /opt/trojan-go

docker compose up -d       # 启动
docker compose down        # 停止
docker compose restart     # 重启
docker compose ps          # 查看状态
docker logs -f trojan-go   # 查看日志

# 更新镜像
docker compose pull && docker compose up -d
```

---

## 3. install-ai.sh（AI Agent 自动化部署）

### 功能特性

- **零交互**：所有参数通过命令行传入
- **源码编译**：从 GitHub 拉取指定分支源码编译
- **双模式**：支持 native 和 docker 部署
- **JSON 输出**：结果以 JSON 格式输出，便于 Agent 解析
- **幂等性**：重复执行安全
- **快速失败**：参数校验前置，错误立即退出

### 使用方法

```bash
# Native 部署 main 分支
sudo bash install-ai.sh --mode native --password mypass --branch main

# Docker 部署 dev 分支，启用 WS + Hysteria2
sudo bash install-ai.sh --mode docker --password mypass --branch dev --ws --hy2

# 指定端口和域名
sudo bash install-ai.sh --mode native --password mypass --port 8443 --domain example.com

# 仅生成配置
sudo bash install-ai.sh --mode native --password mypass --config-only

# 安装后不启动
sudo bash install-ai.sh --mode native --password mypass --no-start

# Dry run（仅打印操作）
sudo bash install-ai.sh --mode native --password mypass --dry-run

# 卸载
sudo bash install-ai.sh --uninstall
```

### 命令行参数

#### 必填参数

| 参数 | 简写 | 说明 |
|------|------|------|
| `--mode` | `-m` | 部署模式：`native` 或 `docker` |
| `--password` | `-P` | 连接密码 |

#### 可选参数

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `--branch` | `-b` | `main` | Git 分支名 |
| `--host` | `-H` | `0.0.0.0` | 监听地址 |
| `--port` | `-p` | `443` | Trojan 端口 |
| `--domain` | `-d` | - | 域名（用于 TLS SNI） |
| `--ws` | - | `false` | 启用 WebSocket |
| `--ws-path` | - | `/trojan-go` | WebSocket 路径 |
| `--hy2` | - | `false` | 启用 Hysteria2 |
| `--hy2-port` | - | `8443` | Hysteria2 端口 |
| `--cert` | `-c` | - | TLS 证书路径 |
| `--key` | `-k` | - | TLS 私钥路径 |
| `--install-dir` | - | 自动 | 安装目录 |
| `--config-only` | - | `false` | 仅生成配置 |
| `--no-start` | - | `false` | 安装后不启动 |
| `--dry-run` | - | `false` | 仅打印操作 |
| `--verbose` | `-v` | `false` | 详细输出 |
| `--uninstall` | - | `false` | 卸载 |
| `--help` | `-h` | - | 帮助信息 |

### 输出格式

脚本执行成功后输出 JSON 格式结果：

```json
{
    "success": true,
    "mode": "native",
    "branch": "dev",
    "version": "a1b2c3d",
    "status": "running",
    "config": "/etc/trojan-go/config.json",
    "port": 443,
    "ws": true,
    "hy2": true,
    "password": "mypass"
}
```

#### 状态说明

| status | 说明 |
|--------|------|
| `running` | 服务已启动运行 |
| `installed` | 已安装但未启动（--no-start） |
| `config_only` | 仅生成配置（--config-only） |
| `failed` | 服务启动失败 |

### AI Agent 调用示例

```bash
# 基础部署
bash install-ai.sh \
  --mode native \
  --password "test_password" \
  --branch main

# 完整配置部署
bash install-ai.sh \
  --mode docker \
  --password "secure_pass" \
  --branch develop \
  --port 443 \
  --domain "jp.example.com" \
  --ws \
  --hy2 \
  --verbose

# 解析返回结果
result=$(bash install-ai.sh --mode native --password pass --branch main)
status=$(echo "$result" | jq -r '.status')
if [[ "$status" == "running" ]]; then
    echo "部署成功"
fi
```

---

## 配置文件说明

### 配置文件路径

| 部署模式 | 配置文件路径 |
|----------|--------------|
| install.sh | `/etc/trojan-go/config.json` |
| install-docker.sh | `/opt/trojan-go/config.json` |
| install-ai.sh (native) | `/etc/trojan-go/config.json` |
| install-ai.sh (docker) | `/opt/trojan-go/config.json` |

### 配置项说明

```json
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": ["your_password"],
    "ssl": {
        "cert": "/path/to/fullchain.crt",
        "key": "/path/to/private.key",
        "sni": "your-domain.com"
    },
    "websocket": {
        "enabled": false,
        "path": "/trojan-go",
        "hostname": "your-domain.com"
    },
    "router": {
        "enabled": true,
        "block": ["geoip:private"],
        "geoip": "/usr/share/trojan-go/geoip.dat",
        "geosite": "/usr/share/trojan-go/geosite.dat"
    },
    "hysteria2": {
        "enabled": false,
        "port": 8443,
        "up_mbps": 100,
        "down_mbps": 500,
        "masquerade_url": "https://www.bilibili.com",
        "auth_api": "http://127.0.0.1:8080/admin/api/hysteria/auth"
    }
}
```

---

## 系统要求

### 操作系统

- Linux (systemd 发行版)
- 支持：Ubuntu 18.04+, CentOS 7+, Debian 9+, Alpine 3.14+

### 架构

- x86_64 (amd64)
- aarch64 (arm64)

### 依赖

| 脚本 | 必需依赖 | 可选依赖 |
|------|----------|----------|
| install.sh | curl, tar, unzip, jq, systemctl | openssl |
| install-docker.sh | curl | docker, docker-compose |
| install-ai.sh | git, make, go (>=1.20), systemctl | docker (docker模式) |

---

## 常见问题

### 1. 端口被占用

```bash
# 查看端口占用
ss -tlnp | grep 443

# 修改端口
# 编辑配置文件后重启服务
```

### 2. 证书配置

```bash
# 使用 Let's Encrypt 申请证书
certbot certonly --standalone -d your-domain.com

# 证书路径
# /etc/letsencrypt/live/your-domain.com/fullchain.pem
# /etc/letsencrypt/live/your-domain.com/privkey.pem
```

### 3. 防火墙配置

```bash
# 开放端口
ufw allow 443/tcp
ufw allow 8443/udp

# 或 iptables
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp --dport 8443 -j ACCEPT
```

### 4. 卸载后重新安装

```bash
# 完全卸载
sudo bash install.sh --uninstall

# 删除配置（可选）
sudo rm -rf /etc/trojan-go

# 重新安装
sudo bash install.sh
```

---

## 更新日志

| 版本 | 日期 | 说明 |
|------|------|------|
| v1.0.0 | 2026-07-25 | 初始版本，支持三种部署方式 |
