# Trojan-Go 服务部署文档

> **版本**: v1.0  
> **日期**: 2026-07-25  
> **适用范围**: 日本主节点 + 新加坡从节点的 Trojan-Go 服务部署  
> **参考文档**: 
> - [当前业务架构端口与使用逻辑说明](file:///Users/wangwenjin/Downloads/workbuddy/clawcode/outputs/当前业务架构端口与使用逻辑说明-2026-07-22.md)
> - [日本-新加坡Trojan-Hysteria2部署流程与执行记录基底](file:///Users/wangwenjin/Downloads/workbuddy/clawcode/outputs/日本-新加坡Trojan-Hysteria2部署流程与执行记录基底-2026-07-22.md)
> - [统一Gateway网关与Trojan-Go服务化架构技术报告](file:///Users/wangwenjin/Downloads/workbuddy/clawcode/outputs/统一Gateway网关与Trojan-Go服务化架构技术报告-2026-07-23.md)

---

## 目录

1. [部署架构概述](#1-部署架构概述)
2. [环境准备要求](#2-环境准备要求)
3. [部署步骤](#3-部署步骤)
4. [Docker Compose 配置详解](#4-docker-compose-配置详解)
5. [启动与验证流程](#5-启动与验证流程)
6. [注意事项](#6-注意事项)

---

## 1. 部署架构概述

### 1.1 架构设计

本部署采用 **日本主节点 + 新加坡从节点** 的双节点架构：

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              客户端                                     │
│                    (FiClash / Mihomo / Clash Meta)                     │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
          ▼                       ▼                       ▼
   TCP/443 (Trojan)      UDP/443 (Hysteria2)     TCP/9443 (中继)
          │                       │                       │
          ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         日本主节点 (jp.liteops.top)                      │
│                            124.156.213.217                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    gateway-service (TCP/443)                     │   │
│  │                         TLS 终止 + 分流                          │   │
│  └───────────┬────────────────────────────────────┬────────────────┘   │
│              │                                    │                     │
│    ┌─────────▼─────────┐              ┌───────────▼───────────┐        │
│    │  admin-service    │              │  trojan-data-plane   │        │
│    │  (127.0.0.1:8081) │              │  (127.0.0.1:14443)   │        │
│    │  后台/API/订阅     │              │  Trojan 认证/代理    │        │
│    └─────────┬─────────┘              └───────────────────────┘        │
│              │                                                          │
│    ┌─────────▼─────────┐                                               │
│    │  control-service  │                                               │
│    │  (127.0.0.1:8082) │                                               │
│    │  Worker同步/HY2认证│                                               │
│    └───────────────────┘                                               │
│                                                                         │
│  ┌───────────────────┐    ┌───────────────────────────────────────┐   │
│  │  hysteria (UDP/443)│    │  HAProxy (TCP/9443 → 新加坡TCP/443)  │   │
│  └───────────────────┘    └───────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘                                       │
                                  │ TCP 中继
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       新加坡从节点 (xjp.liteops.top)                     │
│                           43.160.204.91                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    gateway-service (TCP/443)                     │   │
│  └───────────┬───────────────────────────────────────┬────────────┘   │
│              │                                       │                 │
│    ┌─────────▼─────────┐                   ┌─────────▼────────────┐   │
│    │  control-service  │                   │  trojan-data-plane   │   │
│    │  (127.0.0.1:8082) │                   │  (127.0.0.1:14443)   │   │
│    └───────────────────┘                   └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 节点功能定位

#### 日本主节点 (jp.liteops.top)

| 功能 | 说明 |
|------|------|
| **用户与订阅管理** | 主面板、用户管理、流量统计 |
| **Trojan 主入口** | TCP/443 公网代理入口 |
| **Hysteria2 入口** | UDP/443 QUIC 加速代理 |
| **HAProxy 中继** | TCP/9443 → 新加坡 TCP/443 透明转发 |
| **Worker 控制面** | 从节点同步、心跳监控 |
| **MySQL 数据库** | 主数据库，存储用户/节点/配置数据 |

#### 新加坡从节点 (xjp.liteops.top)

| 功能 | 说明 |
|------|------|
| **Trojan 从入口** | TCP/443 代理出口（模拟美国出口） |
| **节点同步** | 从主节点同步用户数据到本地缓存 |
| **HAProxy 中继目标** | 接收日本转发的 TCP/9443 流量 |

### 1.3 网络路径说明

#### 路径 A：日本直连

```
客户端 ──Trojan TLS/TCP 443──▶ 日本 jp.liteops.top (Gateway)
                                    │
                                    ▼
                              trojan-data-plane (认证/代理)
                                    │
                                    ▼
                                 目标网站
```

#### 路径 B：用户 → 日本 → 新加坡（TCP 中继）

```
客户端 ──Trojan TLS/TCP 9443──▶ 日本 HAProxy
                                     │
                                     │ 原样 TCP 字节流
                                     ▼
                               新加坡 xjp.liteops.top:443 (Gateway)
                                     │
                                     ▼
                               trojan-data-plane (认证/代理)
                                     │
                                     ▼
                                  目标网站（新加坡出口）
```

> **重要说明**: HAProxy 为四层透明 TCP 转发，不终止 TLS。客户端 SNI 必须设置为 `xjp.liteops.top`，TLS 证书校验在新加坡完成。

#### 路径 C：Hysteria2 QUIC

```
客户端 ──Hysteria2/UDP 443──▶ 日本 hysteria
                                  │
                                  ▼
                            HTTP Auth API (127.0.0.1:8082)
                                  │
                                  ▼
                               目标网站
```

---

## 2. 环境准备要求

### 2.1 服务器配置要求

#### 日本主节点

| 项目 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 1 核 | 2 核 |
| 内存 | 1 GB | 2 GB |
| 磁盘 | 20 GB | 40 GB |
| 系统 | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| 公网 IP | 124.156.213.217 | - |
| 域名 | jp.liteops.top | - |

#### 新加坡从节点

| 项目 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 1 核 | 2 核 |
| 内存 | 512 MB | 1 GB |
| 磁盘 | 20 GB | 30 GB |
| 系统 | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| 公网 IP | 43.160.204.91 | - |
| 域名 | xjp.liteops.top | - |

### 2.2 Docker 及 Docker Compose 版本要求

| 组件 | 最低版本 | 推荐版本 |
|------|----------|----------|
| Docker | 20.10.0 | 24.0+ |
| Docker Compose | 2.0.0 | 2.20+ |

安装命令：

```bash
# 安装 Docker
curl -fsSL https://get.docker.com | sh

# 安装 Docker Compose (v2 plugin)
apt-get install -y docker-compose-plugin

# 验证安装
docker --version
docker compose version
```

### 2.3 网络端口开放策略

#### 日本主节点安全组

| 端口 | 协议 | 来源 | 用途 |
|------|------|------|------|
| 22 | TCP | 管理 IP 白名单 | SSH 管理 |
| 80 | TCP | 0.0.0.0/0 | ACME HTTP-01 证书申请 |
| 443 | TCP | 0.0.0.0/0 | Trojan + HTTPS 面板/订阅 |
| 443 | UDP | 0.0.0.0/0 | Hysteria2 / QUIC |
| 9443 | TCP | 0.0.0.0/0 | HAProxy 日本→新加坡中继 |
| 8080-8082 | TCP | **禁止公网** | 本机回环 |
| 14443 | TCP | **禁止公网** | 本机回环 |

#### 新加坡从节点安全组

| 端口 | 协议 | 来源 | 用途 |
|------|------|------|------|
| 22 | TCP | 管理 IP 白名单 | SSH 管理 |
| 80 | TCP | 0.0.0.0/0 | ACME HTTP-01 证书申请 |
| 443 | TCP | 0.0.0.0/0 | Trojan 代理入口 |
| 443 | UDP | 0.0.0.0/0 | Hysteria2（可选） |
| 8080-8082 | TCP | **禁止公网** | 本机回环 |
| 14443 | TCP | **禁止公网** | 本机回环 |

### 2.4 域名与证书配置

| 项目 | 值 |
|------|-----|
| 日本域名 | jp.liteops.top |
| 新加坡域名 | xjp.liteops.top |
| 证书注册邮箱 | xwiops@163.com |
| 证书颁发机构 | Let's Encrypt (ACME HTTP-01) |
| 证书路径 (日本) | `/etc/trojan-go/tls/jp.liteops.top/` |
| 证书路径 (新加坡) | `/etc/trojan-go/tls/xjp.liteops.top/` |

> **重要**: 不要自己签发证书，必须使用 Let's Encrypt 申请公有 CA 证书。

### 2.5 域名 DNS 配置

| 域名 | 记录类型 | 记录值 | 说明 |
|------|----------|--------|------|
| jp.liteops.top | A | 124.156.213.217 | 日本主节点 |
| xjp.liteops.top | A | 43.160.204.91 | 新加坡从节点 |

---

## 3. 部署步骤

### 3.1 前置条件检查与准备工作

#### 步骤 1: 登录服务器并更新系统

```bash
# 登录日本主节点
ssh tokyo

# 更新系统
sudo apt-get update && sudo apt-get upgrade -y

# 安装必要工具
sudo apt-get install -y curl wget git jq certbot
```

```bash
# 登录新加坡从节点
ssh sg

# 更新系统
sudo apt-get update && sudo apt-get upgrade -y

# 安装必要工具
sudo apt-get install -y curl wget git jq certbot
```

#### 步骤 2: 安装 Docker 环境

```bash
# 安装 Docker
curl -fsSL https://get.docker.com | sh

# 启动 Docker 服务
sudo systemctl start docker
sudo systemctl enable docker

# 安装 Docker Compose
sudo apt-get install -y docker-compose-plugin

# 验证安装
docker --version
docker compose version
```

#### 步骤 3: 创建项目目录

```bash
# 日本主节点
sudo mkdir -p /opt/trojan-go-jp/{config,certs,data,geodata,logs}
cd /opt/trojan-go-jp

# 新加坡从节点
sudo mkdir -p /opt/trojan-go-sg/{config,certs,data,geodata,logs}
cd /opt/trojan-go-sg
```

#### 步骤 4: 验证域名解析

```bash
# 日本主节点
dig +short jp.liteops.top
# 预期输出: 124.156.213.217

# 新加坡从节点
dig +short xjp.liteops.top
# 预期输出: 43.160.204.91
```

#### 步骤 5: 验证端口可用性

```bash
# 日本主节点
sudo ss -tlnp | grep -E '(443|8080|8082|14443|9443)'
# 预期: 无输出（端口空闲）

# 新加坡从节点
sudo ss -tlnp | grep -E '(443|8080|8082|14443)'
# 预期: 无输出（端口空闲）
```

### 3.2 MySQL 数据库容器部署

> **说明**: MySQL 数据库仅在日本主节点部署，作为第一个启动的容器。

#### 步骤 1: 创建 MySQL 初始化脚本

```bash
# 日本主节点
cat > /opt/trojan-go-jp/init-db.sql << 'EOF'
-- 初始化数据库
CREATE DATABASE IF NOT EXISTS trojan_go CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 创建用户表
USE trojan_go;

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

-- 创建节点表
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

-- 创建同步回执表
CREATE TABLE IF NOT EXISTS node_sync_receipts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    node_id INT NOT NULL,
    sync_id VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_node_id (node_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- 创建流量同步回执表
CREATE TABLE IF NOT EXISTS data_plane_sync_receipts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sync_id VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;
EOF
```

#### 步骤 2: 部署 MySQL 容器

```bash
# 启动 MySQL 容器
sudo docker run -d \
  --name trojan-mysql \
  --restart unless-stopped \
  -e MYSQL_ROOT_PASSWORD=your_secure_root_password \
  -e MYSQL_DATABASE=trojan_go \
  -e MYSQL_CHARSET=utf8mb4 \
  -e MYSQL_COLLATION=utf8mb4_unicode_ci \
  -v /opt/trojan-go-jp/mysql/data:/var/lib/mysql \
  -v /opt/trojan-go-jp/init-db.sql:/docker-entrypoint-initdb.d/init.sql:ro \
  -p 127.0.0.1:3306:3306 \
  mysql:8.0 \
  --character-set-server=utf8mb4 \
  --collation-server=utf8mb4_unicode_ci \
  --default-authentication-plugin=mysql_native_password
```

### 3.3 数据库容器启动状态验证方法

#### 步骤 1: 检查容器状态

```bash
# 检查容器是否运行
sudo docker ps | grep trojan-mysql
# 预期输出: trojan-mysql  Up X minutes (healthy)

# 查看容器日志
sudo docker logs trojan-mysql --tail 20
```

#### 步骤 2: 验证数据库连接

```bash
# 进入 MySQL 容器验证
sudo docker exec -it trojan-mysql mysql -uroot -pyour_secure_root_password -e "
  SELECT 1 AS status;
  SHOW DATABASES;
  USE trojan_go;
  SHOW TABLES;
"
```

#### 步骤 3: 验证初始化数据

```bash
# 检查表是否创建成功
sudo docker exec -it trojan-mysql mysql -uroot -pyour_secure_root_password trojan_go -e "
  DESCRIBE users;
  DESCRIBE nodes;
  DESCRIBE node_sync_receipts;
  DESCRIBE data_plane_sync_receipts;
"
```

### 3.4 各 Go 服务独立容器的部署顺序及配置

#### 部署顺序

```
MySQL → admin-service → control-service → trojan-data-plane → gateway-service → hysteria → HAProxy
```

#### 日本主节点服务配置

##### 1. admin-service 配置

```bash
cat > /opt/trojan-go-jp/config/admin.yaml << 'EOF'
# admin-service 配置
run_type: server
local_addr: 127.0.0.1
local_port: 8081

# 数据库配置
database:
  type: mysql
  host: 127.0.0.1
  port: 3306
  user: trojan
  password: your_trojan_db_password
  dbname: trojan_go

# 管理员配置
admin:
  username: admin
  password: your_secure_admin_password
  path: /admin

# 订阅配置
subscription:
  path: /sub

# 日志配置
log:
  level: 1
  access: /var/log/trojan-go/admin-access.log
  error: /var/log/trojan-go/admin-error.log
EOF
```

##### 2. control-service 配置

```bash
cat > /opt/trojan-go-jp/config/control.yaml << 'EOF'
# control-service 配置
run_type: server
local_addr: 127.0.0.1
local_port: 8082

# Admin 服务地址
admin_address: 127.0.0.1:8081

# 数据库配置
database:
  type: mysql
  host: 127.0.0.1
  port: 3306
  user: trojan
  password: your_trojan_db_password
  dbname: trojan_go

# Hysteria2 认证配置
hysteria2:
  auth_api: http://127.0.0.1:8082/control/v1/hysteria/auth

# 节点同步配置
node_sync:
  enabled: true
  path: /control/v1/nodes/sync

# 心跳配置
heartbeat:
  enabled: true
  path: /control/v1/nodes/heartbeat
  interval: 60

# 日志配置
log:
  level: 1
  access: /var/log/trojan-go/control-access.log
  error: /var/log/trojan-go/control-error.log
EOF
```

##### 3. trojan-data-plane 配置

```bash
cat > /opt/trojan-go-jp/config/data-plane.yaml << 'EOF'
# trojan-data-plane 配置
run_type: server
local_addr: 127.0.0.1
local_port: 14443

# 传输层配置
transport_plugin:
  enabled: true
  type: plaintext

# PROXY protocol
proxy_protocol: true

# 认证数据库配置
database:
  type: mysql
  host: 127.0.0.1
  port: 3306
  user: trojan
  password: your_trojan_db_password
  dbname: trojan_go
  auth_refresh: 30

# 流量上报配置
traffic_report: http://127.0.0.1:8081/internal/control/v1/data-plane/traffic
traffic_interval: 30

# 日志配置
log:
  level: 1
  access: /var/log/trojan-go/data-plane-access.log
  error: /var/log/trojan-go/data-plane-error.log
EOF
```

##### 4. gateway-service 配置

```bash
cat > /opt/trojan-go-jp/config/gateway.yaml << 'EOF'
# gateway-service 配置
run_type: server
local_addr: 0.0.0.0
local_port: 443

# TLS 配置
ssl:
  cert: /etc/trojan-go/tls/jp.liteops.top/fullchain.crt
  key: /etc/trojan-go/tls/jp.liteops.top/private.key
  sni: jp.liteops.top

# 后端服务配置
backends:
  admin:
    address: 127.0.0.1:8081
    paths:
      - /admin
      - /admin/*
      - /sub
  control:
    address: 127.0.0.1:8082
    paths:
      - /control/v1/*
  data_plane:
    address: 127.0.0.1:14443

# 路由配置
router:
  enabled: true
  geoip: /usr/share/trojan-go/geoip.dat
  geosite: /usr/share/trojan-go/geosite.dat
  block:
    - geoip:private

# 日志配置
log:
  level: 1
  access: /var/log/trojan-go/gateway-access.log
  error: /var/log/trojan-go/gateway-error.log
EOF
```

#### 新加坡从节点服务配置

##### 1. control-service 配置

```bash
cat > /opt/trojan-go-sg/config/control.yaml << 'EOF'
# Worker control-service 配置
run_type: server
local_addr: 127.0.0.1
local_port: 8082

# Worker 模式配置
worker:
  enabled: true
  master_url: https://jp.liteops.top/control/v1/nodes/sync
  secret: your_worker_node_secret

# 数据库配置
database:
  type: sqlite
  path: /etc/trojan-go/trojan-go.db

# 日志配置
log:
  level: 1
  access: /var/log/trojan-go/control-access.log
  error: /var/log/trojan-go/control-error.log
EOF
```

##### 2. trojan-data-plane 配置

```bash
cat > /opt/trojan-go-sg/config/data-plane.yaml << 'EOF'
# Worker trojan-data-plane 配置
run_type: server
local_addr: 127.0.0.1
local_port: 14443

# 传输层配置
transport_plugin:
  enabled: true
  type: plaintext

# PROXY protocol
proxy_protocol: true

# 认证数据库配置
database:
  type: sqlite
  path: /etc/trojan-go/trojan-go.db
  auth_refresh: 30

# 节点同步配置
node_sync:
  enabled: true
  master_url: https://jp.liteops.top/control/v1/nodes/sync
  secret: your_worker_node_secret
  interval: 60

# 日志配置
log:
  level: 1
  access: /var/log/trojan-go/data-plane-access.log
  error: /var/log/trojan-go/data-plane-error.log
EOF
```

##### 3. gateway-service 配置

```bash
cat > /opt/trojan-go-sg/config/gateway.yaml << 'EOF'
# Worker gateway-service 配置
run_type: server
local_addr: 0.0.0.0
local_port: 443

# 禁用 admin 路由
admin_disabled: true

# TLS 配置
ssl:
  cert: /etc/trojan-go/tls/xjp.liteops.top/fullchain.crt
  key: /etc/trojan-go/tls/xjp.liteops.top/private.key
  sni: xjp.liteops.top

# 后端服务配置
backends:
  control:
    address: 127.0.0.1:8082
    paths:
      - /control/v1/*
  data_plane:
    address: 127.0.0.1:14443

# 路由配置
router:
  enabled: true
  geoip: /usr/share/trojan-go/geoip.dat
  geosite: /usr/share/trojan-go/geosite.dat
  block:
    - geoip:private

# 日志配置
log:
  level: 1
  access: /var/log/trojan-go/gateway-access.log
  error: /var/log/trojan-go/gateway-error.log
EOF
```

### 3.5 HAProxy 服务部署与端口转发规则配置

> **说明**: HAProxy 仅在日本主节点部署，用于将 TCP/9443 流量转发至新加坡 TCP/443。

#### 步骤 1: 创建 HAProxy 配置

```bash
cat > /opt/trojan-go-jp/config/haproxy.cfg << 'EOF'
global
    log /dev/log local0
    log /dev/log local1 notice
    daemon
    maxconn 4096

defaults
    mode tcp
    log global
    option tcplog
    timeout connect 10s
    timeout client  1h
    timeout server  1h

# DNS 解析器
resolvers public_dns
    nameserver cloudflare 1.1.1.1:53
    nameserver google 8.8.8.8:53
    resolve_retries 3
    timeout resolve 1s
    timeout retry   1s
    hold valid 10s

# 日本 → 新加坡 TCP 中继
listen trojan_relay_to_singapore
    bind :9443
    mode tcp
    option tcp-check
    server singapore xjp.liteops.top:443 check resolvers public_dns init-addr last,libc,none
EOF
```

#### 步骤 2: HAProxy 配置说明

| 配置项 | 值 | 说明 |
|--------|-----|------|
| 监听端口 | 9443 | 日本 HAProxy 前端端口 |
| 后端地址 | xjp.liteops.top | 新加坡节点域名 |
| 后端端口 | 443 | 新加坡 Trojan 端口 |
| 工作模式 | tcp | 四层透明转发，不终止 TLS |
| DNS 解析 | public_dns | 使用公共 DNS 解析后端域名 |

### 3.6 节点间网络连接配置与验证

#### 步骤 1: 验证日本到新加坡的网络连通性

```bash
# 在日本主节点执行
curl -v telnet://xjp.liteops.top:443 --connect-timeout 10
# 预期: Connected to xjp.liteops.top

# 验证新加坡 Trojan 端口可达
openssl s_client -connect xjp.liteops.top:443 -servername xjp.liteops.top </dev/null 2>/dev/null | openssl x509 -noout -subject
```

#### 步骤 2: 验证新加坡到日本的主节点同步接口

```bash
# 在新加坡从节点执行
curl -I https://jp.liteops.top/control/v1/nodes/sync
# 预期: HTTP/2 401 或 405 (表示路由可达，未携带 Secret)
```

---

## 4. Docker Compose 配置详解

### 4.1 日本主节点 docker-compose.yml

```yaml
version: '3.8'

services:
  # ============================================================
  # MySQL 数据库 (第一个启动)
  # ============================================================
  mysql:
    image: mysql:8.0
    container_name: trojan-mysql
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: your_secure_root_password
      MYSQL_DATABASE: trojan_go
      MYSQL_USER: trojan
      MYSQL_PASSWORD: your_trojan_db_password
      MYSQL_CHARSET: utf8mb4
      MYSQL_COLLATION: utf8mb4_unicode_ci
    volumes:
      - ./mysql/data:/var/lib/mysql
      - ./init-db.sql:/docker-entrypoint-initdb.d/init.sql:ro
    ports:
      - "127.0.0.1:3306:3306"
    networks:
      - trojan-network
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "root", "-p$$MYSQL_ROOT_PASSWORD"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  # ============================================================
  # admin-service (依赖 MySQL)
  # ============================================================
  admin-service:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: trojan-admin
    restart: unless-stopped
    command: admin-service -config /etc/trojan-go/config/admin.yaml
    volumes:
      - ./config/admin.yaml:/etc/trojan-go/config/admin.yaml:ro
      - ./data:/etc/trojan-go/data
      - ./logs:/var/log/trojan-go
    ports:
      - "127.0.0.1:8081:8081"
    networks:
      - trojan-network
    depends_on:
      mysql:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  # ============================================================
  # control-service (依赖 admin-service)
  # ============================================================
  control-service:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: trojan-control
    restart: unless-stopped
    command: control-service -config /etc/trojan-go/config/control.yaml
    volumes:
      - ./config/control.yaml:/etc/trojan-go/config/control.yaml:ro
      - ./data:/etc/trojan-go/data
      - ./logs:/var/log/trojan-go
    ports:
      - "127.0.0.1:8082:8082"
    networks:
      - trojan-network
    depends_on:
      admin-service:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8082/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  # ============================================================
  # trojan-data-plane (依赖 control-service)
  # ============================================================
  trojan-data-plane:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: trojan-data-plane
    restart: unless-stopped
    command: -config /etc/trojan-go/config/data-plane.yaml
    volumes:
      - ./config/data-plane.yaml:/etc/trojan-go/config/data-plane.yaml:ro
      - ./data:/etc/trojan-go/data
      - ./logs:/var/log/trojan-go
    ports:
      - "127.0.0.1:14443:14443"
    networks:
      - trojan-network
    depends_on:
      control-service:
        condition: service_healthy
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  # ============================================================
  # gateway-service (依赖 trojan-data-plane)
  # ============================================================
  gateway-service:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: trojan-gateway
    restart: unless-stopped
    command: gateway-service -config /etc/trojan-go/config/gateway.yaml
    volumes:
      - ./config/gateway.yaml:/etc/trojan-go/config/gateway.yaml:ro
      - ./certs/jp.liteops.top:/etc/trojan-go/tls/jp.liteops.top:ro
      - ./geodata:/usr/share/trojan-go:ro
      - ./logs:/var/log/trojan-go
    ports:
      - "0.0.0.0:443:443"
    networks:
      - trojan-network
    depends_on:
      trojan-data-plane:
        condition: service_started
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  # ============================================================
  # Hysteria2 (可选)
  # ============================================================
  hysteria:
    image: tobywei/hysteria:latest
    container_name: trojan-hysteria
    restart: unless-stopped
    command: server -c /etc/hysteria/config.yaml
    volumes:
      - ./config/hysteria.yaml:/etc/hysteria/config.yaml:ro
      - ./certs/jp.liteops.top:/etc/hysteria/tls:ro
    ports:
      - "0.0.0.0:443:443/udp"
    networks:
      - trojan-network
    depends_on:
      control-service:
        condition: service_healthy
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  # ============================================================
  # HAProxy (日本 → 新加坡 TCP 中继)
  # ============================================================
  haproxy:
    image: haproxy:2.8
    container_name: trojan-haproxy
    restart: unless-stopped
    volumes:
      - ./config/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    ports:
      - "0.0.0.0:9443:9443"
    networks:
      - trojan-network
    depends_on:
      - gateway-service
    healthcheck:
      test: ["CMD", "haproxy", "-c", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.1'

# ============================================================
# 网络配置
# ============================================================
networks:
  trojan-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### 4.2 新加坡从节点 docker-compose.yml

```yaml
version: '3.8'

services:
  # ============================================================
  # control-service (Worker 模式)
  # ============================================================
  control-service:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: trojan-control
    restart: unless-stopped
    command: control-service -worker -config /etc/trojan-go/config/control.yaml
    volumes:
      - ./config/control.yaml:/etc/trojan-go/config/control.yaml:ro
      - ./data:/etc/trojan-go/data
      - ./logs:/var/log/trojan-go
    ports:
      - "127.0.0.1:8082:8082"
    networks:
      - trojan-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8082/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  # ============================================================
  # trojan-data-plane (Worker 模式)
  # ============================================================
  trojan-data-plane:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: trojan-data-plane
    restart: unless-stopped
    command: -config /etc/trojan-go/config/data-plane.yaml
    volumes:
      - ./config/data-plane.yaml:/etc/trojan-go/config/data-plane.yaml:ro
      - ./data:/etc/trojan-go/data
      - ./logs:/var/log/trojan-go
    ports:
      - "127.0.0.1:14443:14443"
    networks:
      - trojan-network
    depends_on:
      control-service:
        condition: service_healthy
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  # ============================================================
  # gateway-service (Worker 模式，禁用 admin)
  # ============================================================
  gateway-service:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: trojan-gateway
    restart: unless-stopped
    command: gateway-service -config /etc/trojan-go/config/gateway.yaml
    volumes:
      - ./config/gateway.yaml:/etc/trojan-go/config/gateway.yaml:ro
      - ./certs/xjp.liteops.top:/etc/trojan-go/tls/xjp.liteops.top:ro
      - ./geodata:/usr/share/trojan-go:ro
      - ./logs:/var/log/trojan-go
    ports:
      - "0.0.0.0:443:443"
    networks:
      - trojan-network
    depends_on:
      trojan-data-plane:
        condition: service_started
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

# ============================================================
# 网络配置
# ============================================================
networks:
  trojan-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/16
```

### 4.3 MySQL 服务配置详解

| 配置项 | 值 | 说明 |
|--------|-----|------|
| 镜像 | mysql:8.0 | MySQL 8.0 官方镜像 |
| 容器名 | trojan-mysql | - |
| 重启策略 | unless-stopped | 除非手动停止，否则自动重启 |
| 数据卷 | ./mysql/data:/var/lib/mysql | 数据持久化 |
| 初始化脚本 | ./init-db.sql | 首次启动自动执行 |
| 端口映射 | 127.0.0.1:3306:3306 | 仅本机访问 |
| 内存限制 | 512M | - |
| CPU 限制 | 0.5 核 | - |
| 健康检查 | mysqladmin ping | 每 10 秒检查一次 |

### 4.4 Go 服务容器配置详解

#### 资源限制

| 服务 | 内存限制 | CPU 限制 |
|------|----------|----------|
| admin-service | 256M | 0.25 核 |
| control-service | 256M | 0.25 核 |
| trojan-data-plane | 256M | 0.25 核 |
| gateway-service | 256M | 0.25 核 |
| hysteria | 256M | 0.25 核 |
| haproxy | 128M | 0.1 核 |

#### 依赖关系

```
mysql (healthy)
    ↓
admin-service (healthy)
    ↓
control-service (healthy)
    ↓
trojan-data-plane (started)
    ↓
gateway-service (started)
    ↓
haproxy / hysteria (可选)
```

### 4.5 HAProxy 服务配置详解

| 配置项 | 值 | 说明 |
|--------|-----|------|
| 镜像 | haproxy:2.8 | HAProxy 2.8 官方镜像 |
| 容器名 | trojan-haproxy | - |
| 前端绑定 | 0.0.0.0:9443 | 监听所有接口 |
| 后端地址 | xjp.liteops.top:443 | 新加坡节点 |
| 工作模式 | tcp | 四层透明转发 |
| DNS 解析 | public_dns | 使用公共 DNS |
| 健康检查 | tcp-check | TCP 连接检查 |
| 内存限制 | 128M | - |

---

## 5. 启动与验证流程

### 5.1 容器启动命令及顺序控制

#### 日本主节点启动步骤

```bash
# 步骤 1: 进入项目目录
cd /opt/trojan-go-jp

# 步骤 2: 启动 MySQL（第一个启动）
sudo docker compose up -d mysql

# 步骤 3: 等待 MySQL 健康检查通过
sudo docker compose ps mysql
# 预期: Status 显示 "healthy"

# 步骤 4: 启动所有服务（按依赖顺序自动启动）
sudo docker compose up -d

# 步骤 5: 查看所有服务状态
sudo docker compose ps
```

#### 新加坡从节点启动步骤

```bash
# 步骤 1: 进入项目目录
cd /opt/trojan-go-sg

# 步骤 2: 启动所有服务
sudo docker compose up -d

# 步骤 3: 查看所有服务状态
sudo docker compose ps
```

### 5.2 数据库容器启动成功的验证标准

#### 验证命令

```bash
# 1. 检查容器状态
sudo docker ps | grep trojan-mysql
# 预期输出: trojan-mysql  Up X minutes (healthy)

# 2. 查看容器日志
sudo docker logs trojan-mysql --tail 20
# 预期: "ready for connections" 或 "MySQL init process done. Ready for start up."

# 3. 验证数据库连接
sudo docker exec -it trojan-mysql mysql -uroot -pyour_secure_root_password -e "SELECT 1;"
# 预期输出: 1

# 4. 验证数据库和表
sudo docker exec -it trojan-mysql mysql -uroot -pyour_secure_root_password -e "
  SHOW DATABASES;
  USE trojan_go;
  SHOW TABLES;
"
# 预期: 显示 trojan_go 数据库和 users, nodes 等表
```

### 5.3 各服务容器状态检查方法

#### 日本主节点

```bash
# 查看所有服务状态
cd /opt/trojan-go-jp
sudo docker compose ps

# 预期输出:
# NAME                STATUS                  PORTS
# trojan-mysql        Up X minutes (healthy)  127.0.0.1:3306->3306/tcp
# trojan-admin        Up X minutes (healthy)  127.0.0.1:8081->8081/tcp
# trojan-control      Up X minutes (healthy)  127.0.0.1:8082->8082/tcp
# trojan-data-plane   Up X minutes            127.0.0.1:14443->14443/tcp
# trojan-gateway      Up X minutes            0.0.0.0:443->443/tcp
# trojan-hysteria     Up X minutes            0.0.0.0:443->443/udp
# trojan-haproxy      Up X minutes (healthy)  0.0.0.0:9443->9443/tcp

# 查看各服务日志
sudo docker logs trojan-admin --tail 20
sudo docker logs trojan-control --tail 20
sudo docker logs trojan-data-plane --tail 20
sudo docker logs trojan-gateway --tail 20
sudo docker logs trojan-haproxy --tail 20
```

#### 新加坡从节点

```bash
# 查看所有服务状态
cd /opt/trojan-go-sg
sudo docker compose ps

# 预期输出:
# NAME                STATUS                  PORTS
# trojan-control      Up X minutes (healthy)  127.0.0.1:8082->8082/tcp
# trojan-data-plane   Up X minutes            127.0.0.1:14443->14443/tcp
# trojan-gateway      Up X minutes            0.0.0.0:443->443/tcp
```

### 5.4 HAProxy 流量转发功能测试步骤

#### 测试 1: 验证 HAProxy 监听

```bash
# 检查 HAProxy 端口是否监听
sudo ss -ltnp | grep 9443
# 预期: LISTEN  0  4096  *:9443  *:*

# 查看 HAProxy 统计页面（如已配置）
curl http://127.0.0.1:9443/; echo
```

#### 测试 2: 验证 TLS 中继

```bash
# 通过日本 9443 端口连接，应返回新加坡证书
openssl s_client -connect jp.liteops.top:9443 -servername xjp.liteops.top </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer

# 预期输出:
# subject=CN=xjp.liteops.top
# issuer=C=US, O=Let's Encrypt, CN=R11 (或其他 LE 证书)
```

#### 测试 3: 验证实际代理功能

```bash
# 使用 curl 通过 HAProxy 中继测试
curl -x socks5://jp.liteops.top:9443 https://www.cloudflare.com/cdn-cgi/trace

# 预期: 返回新加坡节点的出口 IP (43.160.204.91)
```

### 5.5 整体服务可用性验证方案

#### 验证清单

| 序号 | 验证项 | 命令 | 预期结果 |
|------|--------|------|----------|
| 1 | MySQL 运行状态 | `docker ps \| grep mysql` | healthy |
| 2 | admin-service 健康 | `curl http://127.0.0.1:8081/health` | HTTP 200 |
| 3 | control-service 健康 | `curl http://127.0.0.1:8082/health` | HTTP 200 |
| 4 | Trojan TCP/443 | `openssl s_client -connect jp.liteops.top:443` | 证书有效 |
| 5 | Hysteria2 UDP/443 | `nc -zuv jp.liteops.top 443` | 端口可达 |
| 6 | 管理面板 | `curl -I https://jp.liteops.top/admin` | HTTP 200 |
| 7 | 订阅接口 | `curl -I https://jp.liteops.top/sub?token=test` | HTTP 200/401 |
| 8 | HAProxy 中继 | `openssl s_client -connect jp.liteops.top:9443 -servername xjp.liteops.top` | 新加坡证书 |
| 9 | Worker 同步 | `docker logs trojan-control \| grep sync` | 无错误 |
| 10 | 日本节点同步 | `ssh sg "docker logs trojan-control"` | 心跳正常 |

---

## 6. 注意事项

### 6.1 多节点部署的网络安全配置

#### 必须遵守的安全规则

1. **内部服务仅绑定本机回环**
   - admin-service: `127.0.0.1:8081`
   - control-service: `127.0.0.1:8082`
   - trojan-data-plane: `127.0.0.1:14443`
   - MySQL: `127.0.0.1:3306`

2. **安全组最小开放原则**
   - 日本: TCP/22(管理), TCP/80(ACME), TCP/443, UDP/443, TCP/9443
   - 新加坡: TCP/22(管理), TCP/80(ACME), TCP/443, UDP/443

3. **TLS 私钥权限**
   - 目录: `0755`
   - 证书: `0644`
   - 私钥: `0600 root:root`

4. **不要自签发证书**
   - 仅使用项目内置 ACME HTTP-01 功能申请 Let's Encrypt 证书
   - 证书申请邮箱: `xwiops@163.com`

#### 网络安全配置检查命令

```bash
# 验证内部服务仅绑定回环地址
sudo ss -ltnp | grep -E '(8081|8082|14443|3306)'
# 预期: 所有端口仅显示 127.0.0.1:PORT

# 验证 TLS 私钥权限
sudo stat -c '%a %U:%G %n' /etc/trojan-go/tls/jp.liteops.top/*.key
# 预期: 600 root:root
```

### 6.2 容器依赖关系处理

#### 启动顺序

```
1. MySQL (等待 healthy)
2. admin-service (依赖 MySQL healthy)
3. control-service (依赖 admin-service healthy)
4. trojan-data-plane (依赖 control-service started)
5. gateway-service (依赖 trojan-data-plane started)
6. HAProxy / hysteria (依赖 gateway-service started)
```

#### 停止顺序

```bash
# 正确停止顺序（反向）
sudo docker compose stop haproxy hysteria gateway-service trojan-data-plane control-service admin-service mysql
```

#### 重启策略

```bash
# 重启单个服务
sudo docker compose restart admin-service

# 重启后等待健康检查
sudo docker compose ps --format "table {{.Name}}\t{{.Status}}"
```

### 6.3 服务日志收集与查看方法

#### 日志文件位置

| 服务 | 日志路径 |
|------|----------|
| admin-service | `/opt/trojan-go-jp/logs/admin-*.log` |
| control-service | `/opt/trojan-go-jp/logs/control-*.log` |
| trojan-data-plane | `/opt/trojan-go-jp/logs/data-plane-*.log` |
| gateway-service | `/opt/trojan-go-jp/logs/gateway-*.log` |
| HAProxy | `/opt/trojan-go-jp/logs/haproxy.log` |

#### 查看日志命令

```bash
# 实时查看所有服务日志
cd /opt/trojan-go-jp
sudo docker compose logs -f

# 查看单个服务日志
sudo docker logs -f trojan-admin --tail 100

# 查看最近 50 行日志
sudo docker logs trojan-gateway --tail 50

# 查看特定时间段日志
sudo docker logs trojan-control --since "2026-07-25T10:00:00" --until "2026-07-25T12:00:00"
```

#### Docker Compose 日志配置

```yaml
# 在 docker-compose.yml 中添加日志配置
services:
  admin-service:
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
        tag: "admin"
```

### 6.4 基本故障排查流程

#### 问题 1: 容器无法启动

```bash
# 查看容器日志
sudo docker logs trojan-admin

# 检查配置文件格式
sudo docker run --rm -v ./config/admin.yaml:/config.yaml your-image admin-service -config /config.yaml config-check

# 检查端口冲突
sudo ss -tlnp | grep 8081
```

#### 问题 2: 数据库连接失败

```bash
# 检查 MySQL 容器状态
sudo docker ps | grep mysql
sudo docker logs mysql --tail 30

# 测试数据库连接
sudo docker exec -it trojan-mysql mysql -uroot -p -e "SELECT 1;"

# 检查 MySQL 用户权限
sudo docker exec -it trojan-mysql mysql -uroot -p -e "SELECT user, host FROM mysql.user;"
```

#### 问题 3: Worker 同步失败

```bash
# 查看新加坡节点日志
ssh sg "cd /opt/trojan-go-sg && sudo docker logs trojan-control --tail 50"

# 检查主节点同步接口
curl -I https://jp.liteops.top/control/v1/nodes/sync

# 验证 Secret 匹配
# 检查日本主节点数据库中的节点配置
sudo docker exec -it trojan-mysql mysql -uroot -p trojan_go -e "SELECT name, secret FROM nodes WHERE name='新加坡';"
```

#### 问题 4: HAProxy 中继失败

```bash
# 检查 HAProxy 状态
sudo docker logs trojan-haproxy --tail 20

# 验证后端可达性
curl -v telnet://xjp.liteops.top:443 --connect-timeout 5

# 检查 HAProxy 配置
docker run --rm -v ./config/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro haproxy:2.8 haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
```

#### 问题 5: 证书续期

```bash
# 使用 certbot 续期
sudo certbot renew --standalone

# 续期后重启 gateway-service
cd /opt/trojan-go-jp
sudo docker compose restart gateway-service
```

---

## 附录

### A. 端口总表

| 节点 | 端口 | 协议 | 服务 | 绑定地址 | 公网开放 |
|------|------|------|------|----------|----------|
| 日本 | 22 | TCP | SSH | 0.0.0.0 | 管理 IP |
| 日本 | 80 | TCP | ACME | 0.0.0.0 | 是 (临时) |
| 日本 | 443 | TCP | gateway-service | 0.0.0.0 | 是 |
| 日本 | 443 | UDP | hysteria | 0.0.0.0 | 是 |
| 日本 | 9443 | TCP | HAProxy | 0.0.0.0 | 是 |
| 日本 | 3306 | TCP | MySQL | 127.0.0.1 | 否 |
| 日本 | 8081 | TCP | admin-service | 127.0.0.1 | 否 |
| 日本 | 8082 | TCP | control-service | 127.0.0.1 | 否 |
| 日本 | 14443 | TCP | trojan-data-plane | 127.0.0.1 | 否 |
| 新加坡 | 22 | TCP | SSH | 0.0.0.0 | 管理 IP |
| 新加坡 | 80 | TCP | ACME | 0.0.0.0 | 是 (临时) |
| 新加坡 | 443 | TCP | gateway-service | 0.0.0.0 | 是 |
| 新加坡 | 443 | UDP | hysteria | 0.0.0.0 | 是 (可选) |
| 新加坡 | 8082 | TCP | control-service | 127.0.0.1 | 否 |
| 新加坡 | 14443 | TCP | trojan-data-plane | 127.0.0.1 | 否 |

### B. 常用命令速查

```bash
# ===== Docker Compose =====
# 启动所有服务
sudo docker compose up -d

# 停止所有服务
sudo docker compose down

# 查看服务状态
sudo docker compose ps

# 查看日志
sudo docker compose logs -f

# 重启服务
sudo docker compose restart <service>

# ===== Docker =====
# 查看运行中的容器
sudo docker ps

# 查看容器日志
sudo docker logs -f <container>

# 进入容器
sudo docker exec -it <container> bash

# 查看容器资源使用
sudo docker stats

# ===== 系统 =====
# 查看端口监听
sudo ss -tlnp

# 查看防火墙状态
sudo ufw status

# 查看系统资源
htop
```

### C. 相关参考文档

- [当前业务架构端口与使用逻辑说明](file:///Users/wangwenjin/Downloads/workbuddy/clawcode/outputs/当前业务架构端口与使用逻辑说明-2026-07-22.md)
- [日本-新加坡Trojan-Hysteria2部署流程与执行记录基底](file:///Users/wangwenjin/Downloads/workbuddy/clawcode/outputs/日本-新加坡Trojan-Hysteria2部署流程与执行记录基底-2026-07-22.md)
- [统一Gateway网关与Trojan-Go服务化架构技术报告](file:///Users/wangwenjin/Downloads/workbuddy/clawcode/outputs/统一Gateway网关与Trojan-Go服务化架构技术报告-2026-07-23.md)
- [Trojan-Go README](file:///Users/wangwenjin/Downloads/workbuddy/clawcode/trojan-go-h2/README.md)
- [Trojan-Go Dockerfile](file:///Users/wangwenjin/Downloads/workbuddy/clawcode/trojan-go-h2/Dockerfile)
