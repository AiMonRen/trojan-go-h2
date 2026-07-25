# install.sh 部署失效问题分析报告

日期：2026-07-26
对象服务器：日本节点（VM-0-15-ubuntu）
部署脚本：`trojan-go-h2/install.sh`（SHA256 `33fe9706...c7f0c`）
分析依据：服务器实测运行状态 + `trojan-go-h2` 源码

---

## 0. 结论摘要

master 模式部署后，**5 个应有的进程只跑起来 1 个**，且这唯一活着的 `gateway-service` 处于功能不可用的降级状态。

| 组件 | 应有状态 | 实际状态 | 根因 |
|---|---|---|---|
| gateway-service | 监听 443，路由到 3 个后端 | active，但全部后端不可达 | 配置 schema 不匹配，全部字段落空走默认值 |
| admin-service | 监听 127.0.0.1:8081 | **重启循环**（计数 38+） | 配置 schema 不匹配，`admin.enabled` 为零值 |
| control-service | 监听 127.0.0.1:8082 | **重启循环**（计数 37+） | internal-token 文件不存在（admin 未启动的连带结果） |
| trojan data-plane | 监听 127.0.0.1:14443 | **从未被创建** | install.sh 无对应逻辑 |
| hysteria2 | 监听 UDP 443 | **从未被创建** | install.sh 无对应逻辑 |

核心矛盾：**install.sh 生成的 YAML 配置与二进制期望的 schema 是两套完全不同的结构**。YAML 解析器对未知字段静默忽略，导致必填字段全部取零值，这类错误不会在解析阶段报错，而是延迟到启动校验或运行期才暴露。

一个需要明确指出的后果：本次部署前服务器上原本运行着一套可用的 trojan-go 服务。上一轮加入的 `cleanup_existing_services()` 把旧的 `trojan-data-plane.service`、`hysteria.service`、`trojan-go.service`、`trojan-web.service` 全部 `stop` + `disable`，而新脚本并未提供替代品。**当前服务器的代理能力比部署前更差**，且因为已被 `disable`，重启机器也不会自动恢复。

---

## 1. 现场证据

### 1.1 进程与监听

```
$ ps aux | grep trojan
root  569851  /opt/trojan-go/bin/trojan-go gateway-service -config /opt/trojan-go/config/gateway.yaml

$ sudo ss -tulnp | grep -E ":443|:8081|:8082|:14443|:3306"
tcp LISTEN 127.0.0.1:3306  users:(("docker-proxy",pid=569241))
tcp LISTEN         *:443   users:(("trojan-go",pid=569851))
```

8081、8082、14443 全部无监听；UDP 443 无监听。

### 1.2 systemd 状态

```
trojan-go-gateway    enabled  active
trojan-go-admin      enabled  activating   ← 重启循环，不是启动中
trojan-go-control    enabled  activating   ← 重启循环
```

`activating` 配合 `Restart=on-failure` + `RestartSec=5s` 意味着进程反复启动失败。`ps` 只能抓到 5 秒窗口内的瞬时进程，所以肉眼看起来"只有一个"。

### 1.3 旧部署遗留单元（均被本次 cleanup 停用）

```
trojan-data-plane    enabled=disabled  active=inactive
hysteria             enabled=disabled  active=inactive
trojan-go            enabled=disabled  active=inactive
trojan-web           enabled=disabled  active=inactive
```

---

## 2. 问题详解

### 问题 1：admin-service 配置 schema 完全不匹配（致命）

**报错**

```
[FATAL] main.go:181 启动 admin-service 失败: 配置文件中未启用 admin 模块
```

**二进制期望**（`internal/webserver/services.go:17-28`，`standaloneConfig`）

```yaml
admin:
  enabled: true          # 必填，校验第一关
  db: "mysql:..."        # 必填，单字符串 DSN
  username: xxx          # 必填
  password: xxx          # 必填
  path: /admin/          # 必填
  sub_path: /sub         # 必填
node:
  enabled: false
```

6 个字段逐一校验，缺任何一个即 `FATAL`（`services.go:40-54`）。

**install.sh 实际生成**（`generate_admin_config`，install.sh:1006-1025）

```yaml
run_type: server
local_addr: 127.0.0.1
local_port: 8081

database:              # ← 二进制不认识这个块
  type: mysql
  host: 127.0.0.1
  port: 3306
  user: trojan
  password: xxx
  dbname: trojan_go

admin:
  username: admin      # ← 只有 2 个字段，缺 enabled/db/path/sub_path
  password: xxx

subscription:          # ← 二进制不认识
  path: /sub
```

**失效链条**：`database:` 和 `subscription:` 两个块在 `standaloneConfig` 里没有对应字段，`yaml.Unmarshal` 静默忽略 → `cfg.Admin.Enabled` = false（bool 零值）→ 撞上 `services.go:40` 的校验 → `log.Fatal` → systemd 5 秒后重启 → 无限循环。

**关键点**：数据库连接不是 host/port 分离的结构，而是**单个字符串**，靠 `mysql:` 前缀判断驱动类型（`internal/database/models.go:184-199`）：

```go
isMySQL := strings.HasPrefix(dbPath, "mysql:")
if isMySQL {
    dsn := strings.TrimPrefix(dbPath, "mysql:")
    dialector = mysql.Open(dsn)
} else {
    dialector = sqlite.Open(dbPath)   // 无前缀 → 当成 SQLite 文件路径
}
```

官方 CLI 的正确拼装方式（`cmd/trojan/actions/install.go:227`）：

```go
dbPath = fmt.Sprintf("mysql:%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
    mysqlUser, mysqlPass, mysqlHost, mysqlPort, mysqlDB)
```

这里有个隐藏陷阱：**若前缀写错或漏掉，不会报错，而是被当作 SQLite 文件路径**，服务能正常启动但连的是一个空的本地文件，MySQL 里的用户数据完全不可见。这比直接崩溃更难排查。

---

### 问题 2：control-service 缺少 internal-token（连带失败）

**报错**

```
[FATAL] main.go:215 启动 control-service 失败: control-service 需要内部服务令牌但无法读取:
read internal token file /var/lib/trojan-go/internal-token: no such file or directory
```

**机制**（`internal/webserver/internal_token.go`）

token 是 loopback 服务间调用的共享凭据，有两个不对称的入口：

- `LoadOrCreateInternalToken()` — 读取，不存在则生成并写入。生产代码中**唯一调用点**是 `newAdminServer`（`server.go:237`）
- `ReadInternalToken()` — 只读，不存在直接报错。control-service 用这个（`control_service.go:35`）

control-service 明确 fail-closed，源码注释写明了理由：

```go
// Fail closed: the internal token must exist before control-service starts.
// Without it every forwarded call would be rejected by admin-service, so we
// refuse to start rather than run in a permanently broken state.
```

**因果关系**：这是问题 1 的**下游后果，不是独立缺陷**。admin 起不来 → 没人创建 token → control 必然失败。修好 admin 后，control 理论上可自愈。

但 install.sh 仍存在一个独立缺陷：`/var/lib/trojan-go/` 目录在服务器上根本不存在，脚本内搜索 `internal-token` / `/var/lib/trojan-go` 结果为 0 处。而 `server.go:233` 的注释明确要求：

```
// The installer provisions /var/lib/trojan-go and the token before any service starts.
```

官方 CLI 确实在 `cmd/trojan/actions/deploy_common.go:303` 预置了该 token，install.sh 遗漏了这一步。依赖 admin 顺带创建属于**启动顺序耦合**，即使 admin 修好，也仍有竞态：`enable_and_start_services()` 中 admin 与 control 之间只 `sleep 2`，若 admin 首次初始化（含 `AutoMigrate` 建表）超过 2 秒，control 仍可能抢先失败。

---

### 问题 3：gateway 配置 schema 不匹配（静默降级，最危险）

gateway 是**唯一 active** 的服务，但它的配置同样完全不匹配——只不过 gateway 的必填校验极其宽松，只检查 `ssl.cert` / `ssl.key`（`gateway.go:92-94`），于是所有错误字段静默走默认值。

**二进制期望**（`gateway.go:65-81`，`gatewayFileConfig`）

```yaml
ssl:
  cert: ...
  key: ...
gateway:
  listen: 0.0.0.0:443
  admin_service: 127.0.0.1:8081
  admin_disabled: false
  control_service: 127.0.0.1:8082
  trojan_service: 127.0.0.1:14443
routes:
  admin_prefix: /admin/
  sub_path: /sub
```

**install.sh 实际生成**（install.sh:955-991）：使用 `local_addr` / `local_port` / `backends:` / `hysteria2:` / `router:`——**除 `ssl.cert` 和 `ssl.key` 外，没有一个字段被二进制识别**。

**实际后果**：

| 配置项 | 脚本意图 | 实际生效值 | 来源 |
|---|---|---|---|
| 监听地址 | `local_port: ${trojan_port}` | `0.0.0.0:443` | `gateway.go:22` 默认值 |
| admin 后端 | `backends.admin.address` | `127.0.0.1:8081` | 默认值 |
| control 后端 | `backends.control.address` | `127.0.0.1:8082` | 默认值 |
| data-plane | `backends.data_plane.address` | `127.0.0.1:14443` | `gateway.go:23` 默认值 |
| `admin_prefix` | 无 | `""` 空字符串 | 零值 |
| `sub_path` | `paths: [/sub]` | `""` 空字符串 | 零值 |
| hysteria2 全部参数 | `hysteria2:` 块 | **完全忽略** | 结构体无此字段 |
| router / geoip 分流 | `router:` 块 | **完全忽略** | 结构体无此字段 |

巧合之处：默认值恰好与脚本意图的端口一致（443 / 8081 / 8082 / 14443），所以**端口层面看不出问题**。但 `admin_prefix` 和 `sub_path` 取空字符串会直接影响路由匹配，且 `hysteria2` 与 `router` 两整块配置形同废纸——用户改 `config.conf` 里的 `hy2_up_mbps`、`hy2_masquerade`、分流规则，全部无任何效果。

**若自定义端口，问题立刻显性化**：用户在 `config.conf` 里把 `trojan_port` 改成 8443，gateway 仍会监听 443。

另有一处独立 bug（install.sh:993-995）：

```bash
if [[ "$DEPLOY_MODE" == "worker" ]]; then
    echo "admin_disabled: true" >> "${CONFIG_DIR}/gateway.yaml"
fi
```

该字段被追加到 YAML **顶层**，而结构体期望 `gateway.admin_disabled`（`gateway.go:73`）。worker 节点的 `admin_disabled` 永远为 false，gateway 会继续尝试把 `/admin` 流量转发到一个不存在的 admin 后端。

---

### 问题 4：data-plane 与 hysteria2 从未被创建（架构缺失）

`setup_systemd()`（install.sh:1179-1202）只创建 3 个单元：gateway、admin、control。而 gateway 架构上必须把解密后的 Trojan 流量转发给 `127.0.0.1:14443` 的 data-plane 进程。

`data-plane` 是 trojan-go 的正式服务形态，有完整的配置校验逻辑（`cmd/trojan-go/main.go:60-110`），要求 `transport_plugin.enabled=true` + `type=plaintext`、`proxy_protocol=true`、`auth_db` 等。install.sh 中 `data-plane` 仅出现在 cleanup 的单元名列表和 gateway.yaml 的无效 `backends` 块里，**没有任何创建逻辑**。

hysteria2 同理：`hy2_enabled`、`hy2_port` 等参数只写进了 gateway.yaml 中那个被忽略的 `hysteria2:` 块，没有对应 systemd 单元，`/mnt/trojan-go/trojan` 二进制（24MB）被部署但从未被拉起。

**后果**：即使问题 1-3 全部修复，**代理功能依然完全不可用**——gateway 能完成 TLS 握手，但转发目标 14443 无人监听，所有客户端连接会在握手后立即断开。

---

### 问题 5：master 模式的 control.yaml 是死文件

`create_control_service()`（install.sh:1250）传入 `-config ${CONFIG_DIR}/control.yaml`，但 `main.go:211-213` 中非 worker 分支走的是：

```go
err = webserver.RunControlService(listenAddress, adminAddress)
```

签名只接收两个地址参数，`configPath` **被完全丢弃**。`RunControlService`（`control_service.go:21`）只认 `-listen` / `-admin` 命令行参数。

因此 `generate_control_config()` 生成的全部内容——`node_sync`、`heartbeat.interval`（用户可配的 `sync_interval`）、`hysteria2.auth_api`——**一条都没生效**。心跳间隔等参数看似可配，实际全是摆设。

对比：worker 模式走 `RunWorkerControlService(configPath, listenAddress)`，确实读 config，但用的是与 admin 相同的 `standaloneConfig` schema，且额外要求 `node.enabled=true`（`services.go:68`）。而 `generate_control_worker_config()` 生成的是 `worker:` + `database:` 结构，同样不匹配——**worker 模式部署会以完全相同的方式失败**。

---

### 问题 6：install.sh 未使用二进制自带的 config-check

二进制提供了 `config-check` 子命令（`main.go:158-164`），支持 `gateway` / `admin` / `worker-control` / `data-plane` 四种服务的启动前校验，复用的正是运行期同一套校验函数。

install.sh 中 `config-check` 出现次数为 **0**。

这是本次所有问题得以进入生产的**流程性根因**：脚本先 `systemctl start` 再无验证地打印成功，把本可在部署时暴露的配置错误，转化成了生产环境里的 systemd 无限重启循环。同时 `enable_and_start_services()` 启动后不检查 `is-active`，`print_result` 无条件输出成功信息，用户被误导为部署成功。

---

## 3. 修复方案

修复需按依赖顺序进行。**问题 1、3、4 是彼此独立的致命缺陷，只修其中任意一个都不能让服务可用。**

### 3.1 重写 `generate_admin_config`（问题 1）

按 `standaloneConfig` 真实 schema 生成，并拼装带 `mysql:` 前缀的 DSN：

```bash
generate_admin_config() {
    if [[ "$admin_password" == "AutoGenerate" ]]; then
        admin_password=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 16)
    fi

    # 单字符串 DSN，mysql: 前缀决定驱动类型（models.go:184）
    # 缺前缀会被静默当作 SQLite 文件路径，务必保留
    local db_dsn="mysql:${mysql_user}:${mysql_password}@tcp(${mysql_host}:${mysql_port})/${mysql_dbname}?charset=utf8mb4&parseTime=True&loc=Local"

    cat > "${CONFIG_DIR}/admin.yaml" << EOF
admin:
  enabled: true
  db: "${db_dsn}"
  username: ${admin_username}
  password: ${admin_password}
  path: /admin/
  sub_path: /sub
node:
  enabled: false
EOF
    chmod 600 "${CONFIG_DIR}/admin.yaml"
}
```

注意：密码含 YAML 特殊字符时需引号包裹；DSN 中的密码若含 `@` 或 `/` 需额外转义。当前自动生成的密码经 `tr -dc 'a-zA-Z0-9'` 过滤，暂无此风险，但用户自定义密码时会踩到。

`admin.yaml` 含 MySQL 明文口令，应设 `chmod 600`（现状为默认权限）。

### 3.2 预置 internal-token（问题 2）

在 `enable_and_start_services` 之前执行，消除对 admin 启动顺序的隐式依赖：

```bash
provision_internal_token() {
    local token_dir="/var/lib/trojan-go"
    local token_file="${token_dir}/internal-token"
    install -d -m 0700 -o root -g root "${token_dir}"
    if [[ ! -f "${token_file}" ]]; then
        openssl rand -hex 32 > "${token_file}"
        chmod 0600 "${token_file}"
        chown root:root "${token_file}"
    fi
}
```

权限要求来自 `internal/secretfile`：必须是非符号链接、owner-only、属主正确的常规文件，否则读取被拒。长度须 ≥16 字符，`openssl rand -hex 32` 产出 64 字符符合要求。

### 3.3 重写 `generate_gateway_config`（问题 3）

```bash
cat > "${CONFIG_DIR}/gateway.yaml" << EOF
ssl:
  cert: ${CERTS_DIR}/fullchain.crt
  key: ${CERTS_DIR}/private.key
gateway:
  listen: 0.0.0.0:${trojan_port}
  admin_service: 127.0.0.1:8081
  admin_disabled: ${admin_disabled_value}
  control_service: 127.0.0.1:8082
  trojan_service: 127.0.0.1:14443
routes:
  admin_prefix: /admin/
  sub_path: /sub
EOF
```

worker 模式把 `admin_disabled_value` 设为 `true`，替代原先追加到顶层的错误写法。

需同时向用户说明：`hysteria2:` 与 `router:` 两块配置 gateway 不消费。hysteria2 参数应交由独立的 hysteria 服务配置；分流规则需确认由 data-plane 承载，`config.conf` 中相关项当前无效。

### 3.4 补齐 data-plane 与 hysteria2 单元（问题 4）

这是工作量最大的一项，需按 `validateDataPlaneConfig`（`main.go:60-110`）的约束生成 data-plane 配置：`run_type: server`、`local_addr` 为 loopback、`local_port: 14443`、`transport_plugin.enabled=true` 且 `type=plaintext`、`proxy_protocol=true`、`auth_db` 指向同一 MySQL DSN，以及 `traffic_report` / `traffic_outbox` 的配套要求。

建议在补齐前先确认预期架构：hysteria2 是由 `/mnt/trojan-go/trojan` 独立进程承载，还是应由 data-plane 内建。这一点需要产品侧确认，我不宜自行假定。

### 3.5 修正 master control 单元（问题 5）

```bash
ExecStart=${BIN_DIR}/trojan-go control-service -listen 127.0.0.1:8082 -admin 127.0.0.1:8081
```

并删除 `generate_control_config()`，或明确注释其仅为文档用途，避免继续误导。worker 模式的 `generate_control_worker_config()` 需按 `standaloneConfig` + `node.enabled: true` 重写。

### 3.6 接入 config-check 与启动后验证（问题 6）

启动前逐个校验：

```bash
"${BIN_DIR}/trojan-go" config-check --service admin --config "${CONFIG_DIR}/admin.yaml" || return 1
"${BIN_DIR}/trojan-go" config-check --service gateway --config "${CONFIG_DIR}/gateway.yaml" || return 1
```

启动后确认 `is-active`，失败则输出 `journalctl` 尾部日志并以非零码退出，而非无条件打印成功。

---

## 4. 后续可能出现的问题

### 4.1 修复过程中的风险

**证书校验时序**：`config-check --service gateway` 会执行 `tls.LoadX509KeyPair`（`gateway.go:143`），证书未就绪时校验必然失败。必须放在 `setup_ssl_certificates` 之后。`--path-override` 选项（仅 gateway 支持）可用于校验暂存路径的证书。

**AutoMigrate 首次耗时**：admin 首启会执行 5 张表的 `AutoMigrate` 加两次过期数据清理（`models.go:214-222`）。即使预置了 token，control 若在 admin 就绪前启动仍可能因连不上 8081 而失败。建议改为轮询 8081 就绪，替代固定 `sleep 2`。

**MySQL DSN 转义**：用户自定义含特殊字符的 MySQL 密码时，DSN 拼装会被破坏。需做 URL 转义或在文档中限制字符集。

### 4.2 已被 disable 的旧服务

`trojan-data-plane`、`hysteria`、`trojan-go`、`trojan-web` 已被 `disable`，机器重启不会自愈。若新部署最终不可用，需明确回滚路径：重新 `enable` + `start` 这批旧单元，其配置文件（如 `/etc/trojan-go/config.yaml`）应确认仍完好。

建议在 cleanup 前自动备份 `systemctl is-enabled` 状态，以便回滚。当前 `cleanup_existing_services()` 无备份、无回滚，是不可逆操作。

### 4.3 端口与共存

旧 data-plane 单元的 ExecStart 是 `/usr/bin/trojan-go -config /etc/trojan-go/config.yaml`（默认模式，可能直接监听 443）。若新旧同时启用会撞端口。`verify_ports_released()` 目前只在 cleanup 阶段检查，不覆盖后续手动操作。

`kill_leftover_processes` 使用 `pgrep -x` 精确匹配 `trojan-go` / `trojan` / `hysteria` 三个名字。若未来二进制改名或以不同 argv[0] 启动，会漏杀。

### 4.4 静默降级的系统性风险

本次最值得警惕的教训：**gateway 的宽松校验让错误配置以"看起来正常"的形态运行了下来**。它 active、监听 443、日志无报错，但 `admin_prefix` / `sub_path` 为空、hysteria2 与 router 配置被丢弃、转发目标无人监听。

这类问题在 YAML + 静态结构体反序列化的组合下会反复出现，因为未知字段默认被忽略。建议：

- 对所有服务配置引入严格模式（`yaml.Decoder.KnownFields(true)`），未知字段直接报错
- 让 gateway 的必填校验覆盖 `gateway.*` 与 `routes.*` 关键字段，而非仅 ssl
- 在 install.sh 中加入部署后端到端连通性验证（TLS 握手 + 订阅接口探测），而非仅检查进程存活

### 4.5 config.conf 中的失效项

需向用户明确当前哪些配置项实际无效，避免继续基于错误预期调参：`hy2_*` 全系列、`sync_interval`、router / geoip 分流相关项，以及 `trojan_port`（gateway 走默认 443）。

---

## 5. 建议执行顺序

1. 重写 `generate_admin_config`（3.1）——解锁 admin，连带解锁 control
2. 预置 internal-token（3.2）——消除启动顺序耦合
3. 重写 `generate_gateway_config`（3.3）——修正静默降级
4. 修正 master control 单元（3.5）——小改动
5. 接入 config-check 与启动后验证（3.6）——防止同类问题再次静默进入生产
6. 补齐 data-plane / hysteria2（3.4）——需先确认架构意图

1-5 完成后管理面（订阅、用户管理）应可用；**代理数据面需 6 完成后才真正可用**。

建议在日本服务器上验证前先确认回滚路径（4.2），因为旧服务已被 disable，当前无可用代理能力。
