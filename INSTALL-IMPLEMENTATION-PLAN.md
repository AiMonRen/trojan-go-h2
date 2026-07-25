# Trojan-Go 节点部署脚本实现方案

> **版本**: v2.0
> **日期**: 2026-07-25
> **基于**: 节点部署脚本文档 v1.0

---

## 1. 设计目标

基于现有 `install.sh` 重构，实现：
- 非交互式部署，通过 `config.conf` 配置
- 支持主节点（--master）和从节点（--worker）两种模式
- 主节点自动生成加密 Secret 供从节点使用
- 与现有 `nodesync` 模块集成，实现节点间通信

---

## 2. 文件结构

```
trojan-go-h2/
├── install.sh          # 部署主脚本
├── config.conf         # 配置文件模板
└── INSTALL-IMPLEMENTATION-PLAN.md  # 本文档
```

---

## 3. 编译产物分析

### 3.1 二进制文件清单

根据 `Makefile` 和 `cmd/` 目录分析，项目编译后生成 **2 个可执行二进制文件**：

| 二进制文件 | 源码入口 | 功能说明 |
|-----------|----------|----------|
| `trojan-go` | `cmd/trojan-go/main.go` | 核心服务主进程，支持多种服务模式 |
| `trojan` | `cmd/trojan/main.go` | CLI 管理控制台（交互式菜单） |

### 3.2 trojan-go 服务模式

`trojan-go` 二进制支持 **4 种服务模式**，通过命令行参数切换：

| 模式 | 启动命令 | 监听端口 | 功能说明 |
|------|----------|----------|----------|
| **默认代理模式** | `trojan-go -config config.yaml` | 443 | 传统 Trojan 代理服务器 |
| **Admin 服务** | `trojan-go admin-service -config admin.yaml` | 8081 | 管理面板 API、用户管理、订阅 |
| **Gateway 服务** | `trojan-go gateway-service -config gateway.yaml` | 443 | TLS 终止、流量路由、反向代理 |
| **Control 服务** | `trojan-go control-service -config control.yaml` | 8082 | 节点同步、心跳监控、HY2 认证 |

### 3.3 trojan CLI 功能

`trojan` 二进制提供交互式管理菜单：

| 菜单 | 功能 |
|------|------|
| 服务运维与部署 | 启动/停止/重启服务、原子升级、申请 SSL 证书、一键部署 |
| 用户管理 | 查看/添加/删除用户 |
| 节点管理 | 查看/添加/修改/删除节点、查看同步 URL |
| 配置与安全管理 | 显示配置、切换 WebSocket、修改管理员密码 |

### 3.4 主节点 vs 从节点二进制使用

#### 主节点（Master）

| 服务 | 二进制 | 配置文件 | 说明 |
|------|--------|----------|------|
| Gateway 服务 | `trojan-go` | `gateway.yaml` | TLS 终止，对外提供代理入口 |
| Admin 服务 | `trojan-go` | `admin.yaml` | 管理面板，用户/节点管理 |
| Control 服务 | `trojan-go` | `control.yaml` | 接收从节点同步请求 |
| CLI 管理 | `trojan` | - | 本地管理操作 |

#### 从节点（Worker）

| 服务 | 二进制 | 配置文件 | 说明 |
|------|--------|----------|------|
| Gateway 服务 | `trojan-go` | `gateway.yaml` | TLS 终止，对外提供代理入口 |
| Control 服务 | `trojan-go` | `control-worker.yaml` | 向主节点同步用户数据 |
| CLI 管理 | `trojan` | - | 本地管理操作 |

---

## 4. 部署目录结构

### 4.1 统一部署目录

```
/opt/trojan-go/
├── bin/                        # 二进制文件目录
│   ├── trojan-go               # 核心服务主进程
│   └── trojan                  # CLI 管理控制台
├── config/                     # 配置文件目录
│   ├── config.conf             # 部署脚本配置文件
│   ├── gateway.yaml            # Gateway 服务配置
│   ├── admin.yaml              # Admin 服务配置（仅主节点）
│   ├── control.yaml            # Control 服务配置（仅主节点）
│   └── control-worker.yaml     # Worker Control 配置（仅从节点）
├── certs/                      # SSL 证书目录
│   ├── fullchain.crt
│   └── private.key
├── data/                       # 数据目录
│   └── trojan-go.db            # SQLite 数据库（从节点）
├── logs/                       # 日志目录
└── secret.key                  # 节点认证密钥（权限 0600）
```

### 4.2 systemd 服务文件

```
/etc/systemd/system/
├── trojan-go-gateway.service   # Gateway 服务
├── trojan-go-admin.service     # Admin 服务（仅主节点）
└── trojan-go-control.service   # Control 服务
```

---

## 5. 配置文件设计 (config.conf)

```ini
# ============================================================
# Trojan-Go 节点部署配置文件
# ============================================================

# 主节点域名（必须）
# - 主节点模式：填写本节点域名
# - 从节点模式：填写主节点域名
master=your.master.com

# 从节点域名
# - 主节点模式：固定填写 no
# - 从节点模式：填写本节点域名
worker=your.worker.com

# 节点认证密钥
# - 主节点模式：固定填写 no（部署后自动生成）
# - 从节点模式：填写主节点生成的密钥字符串
secret=no

# 管理员邮箱（用于 SSL 证书申请）
email=admin@example.com

# ============================================================
# 高级配置（可选）
# ============================================================

# Trojan 监听端口（默认 443 TCP）
trojan_port=443

# WebSocket 启用（true/false，默认 false）
ws_enabled=false

# WebSocket 路径（默认 /trojan-go）
ws_path=/trojan-go

# Hysteria2 启用（true/false，默认 true）
hy2_enabled=true

# Hysteria2 端口（默认 443 UDP，与 TCP 443 不冲突）
hy2_port=443

# Hysteria2 伪装 URL
hy2_masquerade=https://www.bilibili.com

# 数据库类型（默认 mysql）
db_type=mysql

# MySQL 部署模式（docker/local，默认 docker）
# - docker: 自动部署 Docker MySQL 容器
# - local: 使用已存在的 MySQL 实例
mysql_deploy=docker

# Docker MySQL 配置（仅 mysql_deploy=docker 时有效）
mysql_docker_name=trojan-mysql
mysql_docker_root_password=AutoGenerate
mysql_docker_port=3306
mysql_host=127.0.0.1
mysql_port=3306
mysql_user=trojan
mysql_password=AutoGenerate
mysql_dbname=trojan_go

# 节点同步间隔（秒，默认 60）
sync_interval=60
```

---

## 6. 脚本架构设计

### 6.1 整体流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                        install.sh                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 参数解析 (--config, --master, --worker, --secret)           │
│           │                                                     │
│           ▼                                                     │
│  2. 加载配置文件 (config.conf)                                  │
│           │                                                     │
│           ▼                                                     │
│  3. 环境预检 (系统/架构/依赖/权限)                              │
│           │                                                     │
│           ▼                                                     │
│  4. 配置校验 (根据模式校验参数)                                 │
│           │                                                     │
│           ▼                                                     │
│  5. 下载/检测二进制文件 (trojan-go, trojan)                     │
│           │                                                     │
│           ▼                                                     │
│  6. 创建统一部署目录 (/opt/trojan-go/)                          │
│           │                                                     │
│           ▼                                                     │
│  7. 根据模式执行部署                                            │
│     ┌─────┴─────┐                                               │
│     ▼           ▼                                               │
│  --master    --worker                                           │
│     │           │                                               │
│     ▼           ▼                                               │
│  生成 Secret  使用 Secret                                       │
│  部署主服务   部署从服务                                        │
│     │           │                                               │
│     └─────┬─────┘                                               │
│           ▼                                                     │
│  8. 配置 systemd 并启动                                         │
│           │                                                     │
│           ▼                                                     │
│  9. 输出结果                                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 函数清单

| 函数名 | 功能 |
|--------|------|
| `main()` | 主入口，协调各步骤 |
| `parse_args()` | 解析命令行参数 |
| `load_config()` | 加载配置文件 |
| `preflight_check()` | 环境预检 |
| `validate_master_config()` | 主节点配置校验 |
| `validate_worker_config()` | 从节点配置校验 |
| `detect_or_download_binaries()` | 检测/下载二进制文件 |
| `create_deploy_directory()` | 创建统一部署目录 |
| `generate_secret()` | 生成节点认证密钥 |
| `deploy_master()` | 主节点部署流程 |
| `deploy_worker()` | 从节点部署流程 |
| `generate_service_configs()` | 生成各服务 YAML 配置 |
| `setup_systemd()` | 配置 systemd 服务 |
| `print_result()` | 输出部署结果 |
| `show_secret()` | 显示主节点 Secret（--secret 模式） |

---

## 7. 核心逻辑实现

### 7.1 参数解析

```bash
parse_args() {
    # 支持的参数：
    #   --config=<path>   配置文件路径（必填）
    #   --master          主节点模式
    #   --worker          从节点模式
    #   --secret          显示主节点 Secret（仅主节点部署后使用）
    #   --local-binaries  使用本地二进制文件（跳过下载）
    
    # 错误码：
    #   1 - 配置文件路径不存在
    #   2 - 未指定部署模式（--master/--worker）
    #   3 - 同时指定了 --master 和 --worker
    #   7 - 二进制文件不存在或损坏
}
```

### 7.2 二进制文件检测与部署

```bash
# 检测本地二进制文件
detect_local_binaries() {
    local bin_dir="${1:-/opt/trojan-go/bin}"
    
    # 检查必需的二进制文件
    local required_bins=("trojan-go" "trojan")
    local missing_bins=()
    
    for bin in "${required_bins[@]}"; do
        if [[ ! -x "${bin_dir}/${bin}" ]]; then
            missing_bins+=("$bin")
        fi
    done
    
    if [[ ${#missing_bins[@]} -gt 0 ]]; then
        return 1  # 缺少二进制文件
    fi
    
    return 0  # 所有二进制文件就绪
}

# 下载或复制二进制文件到部署目录
deploy_binaries() {
    local deploy_dir="${1:-/opt/trojan-go/bin}"
    
    mkdir -p "$deploy_dir"
    
    # 如果指定了 --local-binaries，从当前目录复制
    if [[ "$USE_LOCAL_BINARIES" == "true" ]]; then
        cp -f trojan-go trojan "$deploy_dir/" 2>/dev/null || {
            error "本地二进制文件不存在，请确保 trojan-go 和 trojan 在当前目录"
            return 1
        }
    else
        # 从 GitHub Release 下载
        download_from_github_release
    fi
    
    # 设置可执行权限
    chmod +x "${deploy_dir}/trojan-go" "${deploy_dir}/trojan"
    
    # 验证二进制文件
    if ! "${deploy_dir}/trojan-go" -version &>/dev/null; then
        error "trojan-go 二进制文件验证失败"
        return 1
    fi
    
    info "二进制文件已部署到 ${deploy_dir}"
}
```

### 7.3 配置校验规则

#### 主节点模式 (--master)

| 配置项 | 校验规则 |
|--------|----------|
| `master` | 非空，有效域名格式 |
| `worker` | 必须为 `no` |
| `secret` | 必须为 `no` |
| `email` | 有效邮箱格式 |

#### 从节点模式 (--worker)

| 配置项 | 校验规则 |
|--------|----------|
| `master` | 非空，有效域名格式 |
| `worker` | 非空，不能为 `no` |
| `secret` | 非空，不能为 `no` |
| `email` | 有效邮箱格式 |

### 7.4 Secret 生成逻辑

```bash
generate_secret() {
    # 使用 /dev/urandom 生成 32 字节随机数据
    # 编码为十六进制字符串（64 字符）
    # 格式: TG-<64位十六进制>
    
    local random_bytes
    random_bytes=$(head -c 32 /dev/urandom | xxd -p -c 64)
    echo "TG-${random_bytes}"
}
```

### 7.5 主节点服务配置生成

#### 7.5.1 Gateway 服务配置 (gateway.yaml)

```yaml
run_type: server
local_addr: 0.0.0.0
local_port: 443

ssl:
  cert: /opt/trojan-go/certs/fullchain.crt
  key: /opt/trojan-go/certs/private.key
  sni: <master域名>

backends:
  admin:
    address: 127.0.0.1:8081
    paths:
      - /admin
      - /sub
  control:
    address: 127.0.0.1:8082
    paths:
      - /control/v1/*
  data_plane:
    address: 127.0.0.1:14443

router:
  enabled: true
  geoip: /opt/trojan-go/geodata/geoip.dat
  geosite: /opt/trojan-go/geodata/geosite.dat
  block:
    - geoip:private
```

#### 7.5.2 Admin 服务配置 (admin.yaml)

```yaml
run_type: server
local_addr: 127.0.0.1
local_port: 8081

database:
  type: <db_type>
  # MySQL 配置
  host: <mysql_host>
  port: <mysql_port>
  user: <mysql_user>
  password: <mysql_password>
  dbname: <mysql_dbname>

admin:
  username: admin
  password: <自动生成>

subscription:
  path: /sub
```

#### 7.5.3 Control 服务配置 (control.yaml)

```yaml
run_type: server
local_addr: 127.0.0.1
local_port: 8082

admin_address: 127.0.0.1:8081

node_sync:
  enabled: true
  path: /control/v1/nodes/sync

heartbeat:
  enabled: true
  path: /control/v1/nodes/heartbeat
  interval: 60

hysteria2:
  auth_api: http://127.0.0.1:8082/control/v1/hysteria/auth
```

### 7.6 从节点服务配置生成

#### 7.6.1 Gateway 服务配置 (gateway.yaml)

```yaml
run_type: server
local_addr: 0.0.0.0
local_port: 443

ssl:
  cert: /opt/trojan-go/certs/fullchain.crt
  key: /opt/trojan-go/certs/private.key
  sni: <worker域名>

backends:
  control:
    address: 127.0.0.1:8082
    paths:
      - /control/v1/*
  data_plane:
    address: 127.0.0.1:14443

router:
  enabled: true
  geoip: /opt/trojan-go/geodata/geoip.dat
  geosite: /opt/trojan-go/geodata/geosite.dat
  block:
    - geoip:private

admin_disabled: true
```

#### 7.6.2 Worker Control 配置 (control-worker.yaml)

```yaml
run_type: server
local_addr: 127.0.0.1
local_port: 8082

worker:
  enabled: true
  master_url: https://<master域名>/control/v1/nodes/sync
  secret: <secret>

database:
  type: sqlite
  path: /opt/trojan-go/data/trojan-go.db
```

---

## 8. --secret 参数功能

部署主节点后，可通过以下命令获取 Secret：

```bash
bash install.sh --config=/path/to/config.conf --secret
```

**输出示例**：
```
══════════════════════════════════════════════════════════════
           主节点认证密钥 / Master Node Secret
══════════════════════════════════════════════════════════════

  Secret: TG-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

  请妥善保存此密钥，从节点部署时需要配置此密钥
  Please save this secret, worker nodes need it to connect

══════════════════════════════════════════════════════════════
```

---

## 9. 使用示例

### 9.1 主节点部署（使用本地编译的二进制文件）

```bash
# 1. 确保二进制文件在当前目录
ls -la trojan-go trojan

# 2. 创建配置文件
cat > /opt/trojan-go/config.conf << 'EOF'
master=your.domain.com
worker=no
secret=no
email=admin@example.com
hy2_enabled=true
hy2_port=443
db_type=mysql
mysql_deploy=docker
mysql_docker_root_password=AutoGenerate
mysql_password=AutoGenerate
EOF

# 3. 执行部署（使用本地二进制）
sudo bash install.sh --config=/opt/trojan-go/config.conf --master --local-binaries

# 4. 获取 Secret（用于从节点配置）
sudo bash install.sh --config=/opt/trojan-go/config.conf --secret
```

### 9.2 主节点部署（自动下载二进制文件）

```bash
# 1. 创建配置文件
cat > /opt/trojan-go/config.conf << 'EOF'
master=your.domain.com
worker=no
secret=no
email=admin@example.com
hy2_enabled=true
hy2_port=443
db_type=mysql
mysql_deploy=docker
mysql_docker_root_password=AutoGenerate
mysql_password=AutoGenerate
EOF

# 2. 执行部署（自动从 GitHub Release 下载）
sudo bash install.sh --config=/opt/trojan-go/config.conf --master

# 3. 获取 Secret（用于从节点配置）
sudo bash install.sh --config=/opt/trojan-go/config.conf --secret
```

### 9.3 从节点部署

```bash
# 1. 创建配置文件（使用主节点返回的 Secret）
cat > /opt/trojan-go/config.conf << 'EOF'
master=your.domain.com
worker=your.domain.com
secret=TG-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
email=admin@example.com
hy2_enabled=true
hy2_port=443
db_type=mysql
mysql_deploy=docker
mysql_docker_root_password=AutoGenerate
mysql_password=AutoGenerate
EOF

# 2. 执行部署
sudo bash install.sh --config=/opt/trojan-go/config.conf --worker --local-binaries
```

---

## 10. 错误处理

### 10.1 错误码定义

| 错误码 | 含义 | 处理方式 |
|--------|------|----------|
| 1 | 配置文件路径不存在 | 检查路径是否正确 |
| 2 | 未指定部署模式 | 添加 --master 或 --worker |
| 3 | 同时指定了 --master 和 --worker | 仅指定一个模式 |
| 4 | 配置项缺失或不合法 | 检查配置文件 |
| 5 | 主节点模式下配置了非法的 worker/secret 值 | 修改配置为 no |
| 6 | 从节点模式下 worker 或 secret 为空 | 填写有效值 |
| 7 | 二进制文件不存在或损坏 | 检查二进制文件或重新下载 |

### 10.2 错误处理示例

```bash
# 配置文件不存在
$ bash install.sh --config=/nonexistent.conf --master
[✗ ERROR] 配置文件不存在: /nonexistent.conf (错误码: 1)

# 未指定部署模式
$ bash install.sh --config=/opt/config.conf
[✗ ERROR] 请指定部署模式 --master 或 --worker (错误码: 2)

# 同时指定两个模式
$ bash install.sh --config=/opt/config.conf --master --worker
[✗ ERROR] 不能同时指定 --master 和 --worker (错误码: 3)

# 二进制文件缺失
$ bash install.sh --config=/opt/config.conf --master --local-binaries
[✗ ERROR] 本地二进制文件不存在: trojan-go, trojan (错误码: 7)
```

---

## 11. 安全考虑

### 11.1 文件权限

| 文件 | 权限 | 所有者 |
|------|------|--------|
| `config.conf` | 0600 | root |
| `/opt/trojan-go/bin/trojan-go` | 0755 | root |
| `/opt/trojan-go/bin/trojan` | 0755 | root |
| `/opt/trojan-go/certs/private.key` | 0600 | root |
| `/opt/trojan-go/secret.key` | 0600 | root |
| `/opt/trojan-go/config/*.yaml` | 0600 | root |

### 11.2 Secret 存储

- 主节点 Secret 存储于 `/opt/trojan-go/secret.key`
- 从节点 Secret 通过安全渠道（SSH/配置管理）分发
- 禁止在日志中输出 Secret

---

## 12. Docker MySQL 自动部署

### 12.1 功能说明

当 `mysql_deploy=docker` 时，install.sh 会自动部署 MySQL Docker 容器，无需手动安装和配置 MySQL。

### 12.2 Docker MySQL 部署流程

```bash
deploy_mysql_docker() {
    # 1. 检查 Docker 是否安装
    if ! command -v docker &>/dev/null; then
        info "Docker 未安装，正在安装..."
        curl -fsSL https://get.docker.com | sh
        systemctl enable docker
        systemctl start docker
    fi
    
    # 2. 检查容器是否已存在
    if docker ps -a --format '{{.Names}}' | grep -q "^${mysql_docker_name}$"; then
        warn "MySQL 容器已存在: ${mysql_docker_name}"
        if docker ps --format '{{.Names}}' | grep -q "^${mysql_docker_name}$"; then
            info "MySQL 容器正在运行"
            return 0
        else
            info "启动已存在的 MySQL 容器..."
            docker start "${mysql_docker_name}"
            return 0
        fi
    fi
    
    # 3. 生成随机密码（如果设置为 AutoGenerate）
    if [[ "$mysql_docker_root_password" == "AutoGenerate" ]]; then
        mysql_docker_root_password=$(openssl rand -base64 24)
    fi
    if [[ "$mysql_password" == "AutoGenerate" ]]; then
        mysql_password=$(openssl rand -base64 24)
    fi
    
    # 4. 创建数据目录
    mkdir -p /opt/trojan-go/mysql/data
    
    # 5. 启动 MySQL 容器
    docker run -d \
        --name "${mysql_docker_name}" \
        --restart unless-stopped \
        -e MYSQL_ROOT_PASSWORD="${mysql_docker_root_password}" \
        -e MYSQL_DATABASE="${mysql_dbname}" \
        -e MYSQL_USER="${mysql_user}" \
        -e MYSQL_PASSWORD="${mysql_password}" \
        -v /opt/trojan-go/mysql/data:/var/lib/mysql \
        -v /opt/trojan-go/mysql/init:/docker-entrypoint-initdb.d:ro \
        -p 127.0.0.1:${mysql_port}:3306 \
        mysql:8.0 \
        --character-set-server=utf8mb4 \
        --collation-server=utf8mb4_unicode_ci \
        --default-authentication-plugin=mysql_native_password
    
    # 6. 等待 MySQL 就绪
    info "等待 MySQL 启动..."
    local max_wait=60
    local waited=0
    while ! docker exec "${mysql_docker_name}" mysqladmin ping --silent 2>/dev/null; do
        sleep 2
        waited=$((waited + 2))
        if [[ $waited -ge $max_wait ]]; then
            error "MySQL 启动超时"
            return 1
        fi
    done
    
    info "MySQL Docker 部署完成"
    
    # 7. 保存密码到安全文件
    cat > /opt/trojan-go/mysql/.credentials << EOF
MYSQL_ROOT_PASSWORD=${mysql_docker_root_password}
MYSQL_USER=${mysql_user}
MYSQL_PASSWORD=${mysql_password}
MYSQL_DATABASE=${mysql_dbname}
EOF
    chmod 600 /opt/trojan-go/mysql/.credentials
}
```

### 12.3 MySQL 初始化脚本

```sql
-- /opt/trojan-go/mysql/init/01-schema.sql
CREATE DATABASE IF NOT EXISTS trojan_go CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE trojan_go;

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    quota BIGINT DEFAULT -1,
    download BIGINT DEFAULT 0,
    upload BIGINT DEFAULT 0,
    expiry_time BIGINT DEFAULT -1,
    status INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 节点表
CREATE TABLE IF NOT EXISTS nodes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    address VARCHAR(255) NOT NULL,
    port INT NOT NULL,
    sni VARCHAR(255),
    traffic_rate FLOAT DEFAULT 1.0,
    ws_enabled BOOLEAN DEFAULT FALSE,
    ws_path VARCHAR(255) DEFAULT '/trojan-go',
    secret VARCHAR(255),
    status INT DEFAULT 1,
    last_heartbeat TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 同步回执表
CREATE TABLE IF NOT EXISTS node_sync_receipts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    node_id INT NOT NULL,
    sync_id VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_node_id (node_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- 流量同步回执表
CREATE TABLE IF NOT EXISTS data_plane_sync_receipts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sync_id VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;
```

### 12.4 部署目录结构（含 MySQL）

```
/opt/trojan-go/
├── bin/                        # 二进制文件
│   ├── trojan-go
│   └── trojan
├── config/                     # 配置文件
│   ├── config.conf
│   ├── gateway.yaml
│   ├── admin.yaml
│   ├── control.yaml
│   └── control-worker.yaml
├── certs/                      # SSL 证书
│   ├── fullchain.crt
│   └── private.key
├── data/                       # 应用数据
├── mysql/                      # MySQL 数据持久化
│   ├── data/                   # 数据库文件
│   ├── init/                   # 初始化脚本
│   │   └── 01-schema.sql
│   └── .credentials            # 凭据文件（权限 600）
├── logs/                       # 日志目录
└── secret.key                  # 节点认证密钥
```

### 12.5 MySQL 部署验证

```bash
verify_mysql_deployment() {
    # 检查容器状态
    if ! docker ps --format '{{.Names}}' | grep -q "^${mysql_docker_name}$"; then
        error "MySQL 容器未运行"
        return 1
    fi
    
    # 测试连接
    if docker exec "${mysql_docker_name}" mysql -u"${mysql_user}" -p"${mysql_password}" \
        -e "SELECT 1" "${mysql_dbname}" &>/dev/null; then
        info "MySQL 连接测试通过"
        return 0
    else
        error "MySQL 连接测试失败"
        return 1
    fi
}
```

### 12.6 常用 MySQL 管理命令

```bash
# 查看 MySQL 容器状态
docker ps | grep trojan-mysql

# 查看 MySQL 日志
docker logs trojan-mysql --tail 50

# 进入 MySQL Shell
docker exec -it trojan-mysql mysql -uroot -p

# 备份数据库
docker exec trojan-mysqldump -uroot -p"${MYSQL_ROOT_PASSWORD}" trojan_go > backup.sql

# 恢复数据库
docker exec -i trojan-mysql mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" trojan_go < backup.sql

# 重启 MySQL
docker restart trojan-mysql
```

---

## 13. 与现有代码集成

### 13.1 集成的模块

| 模块 | 用途 |
|------|------|
| `internal/nodesync` | 节点同步管理 |
| `internal/secretfile` | Secret 文件安全读写 |
| `internal/database` | 用户数据缓存 |
| `internal/webserver` | 控制面 API (Gateway/Admin/Control) |

### 13.2 同步端点

- 主节点：`/control/v1/nodes/sync`（接收从节点同步）
- 心跳：`/control/v1/nodes/heartbeat`
- 认证头：`X-Node-Secret: <secret>`

### 13.3 systemd 服务配置示例

#### 主节点 Gateway 服务

```ini
# /etc/systemd/system/trojan-go-gateway.service
[Unit]
Description=Trojan-Go Gateway Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/trojan-go/bin/trojan-go gateway-service -config /opt/trojan-go/config/gateway.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

#### 主节点 Admin 服务

```ini
# /etc/systemd/system/trojan-go-admin.service
[Unit]
Description=Trojan-Go Admin Service
After=network.target trojan-go-gateway.service

[Service]
Type=simple
ExecStart=/opt/trojan-go/bin/trojan-go admin-service -config /opt/trojan-go/config/admin.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

#### 主节点 Control 服务

```ini
# /etc/systemd/system/trojan-go-control.service
[Unit]
Description=Trojan-Go Control Service
After=network.target trojan-go-admin.service

[Service]
Type=simple
ExecStart=/opt/trojan-go/bin/trojan-go control-service -config /opt/trojan-go/config/control.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

#### 从节点 Gateway 服务

```ini
# /etc/systemd/system/trojan-go-gateway.service
[Unit]
Description=Trojan-Go Gateway Service (Worker)
After=network.target

[Service]
Type=simple
ExecStart=/opt/trojan-go/bin/trojan-go gateway-service -config /opt/trojan-go/config/gateway.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

#### 从节点 Worker Control 服务

```ini
# /etc/systemd/system/trojan-go-control.service
[Unit]
Description=Trojan-Go Worker Control Service
After=network.target trojan-go-gateway.service

[Service]
Type=simple
ExecStart=/opt/trojan-go/bin/trojan-go control-service -worker -config /opt/trojan-go/config/control-worker.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

---

## 14. 实施步骤

1. **Phase 1**: 创建配置文件和参数解析
2. **Phase 2**: 实现环境预检和配置校验
3. **Phase 3**: 实现二进制文件检测与部署逻辑
4. **Phase 4**: 实现 Docker MySQL 自动部署功能
5. **Phase 5**: 实现主节点部署逻辑（3个服务）
6. **Phase 6**: 实现从节点部署逻辑（2个服务）
7. **Phase 7**: 实现 Secret 生成和显示功能
8. **Phase 8**: 添加错误处理和日志
9. **Phase 9**: 测试验证

---

## 15. 待确认事项

- [ ] Secret 格式最终确认（当前方案：TG-<64位十六进制>）
- [x] 是否支持 Docker 模式部署（已添加 Docker MySQL 部署）
- [ ] 是否保留交互式配置向导作为 fallback
- [x] MySQL 初始化是否由脚本自动完成（已实现）
- [ ] 二进制文件是否支持多架构（amd64/arm64）
- [ ] Hysteria2 是否需要单独的二进制或容器
