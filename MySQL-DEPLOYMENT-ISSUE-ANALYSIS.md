# MySQL 部署问题分析报告

> **日期**: 2026-07-25
> **服务器**: Tokyo (124.156.213.217)
> **问题**: MySQL Docker 容器部署成功，但 `verify_mysql_deployment` 连接测试失败
> **状态**: 已定位根因并修复，服务器上已验证通过

---

## 1. 问题现象

`install.sh --master` 部署时，MySQL 容器启动正常，但验证环节稳定报错：

```
[! WARN] 检测到已有 MySQL 数据目录，需要重新初始化...
[✓ INFO] 清除旧数据目录...
[✓ INFO] 已清除旧数据，MySQL 将重新初始化
[✓ INFO] 启动 MySQL 容器...
b3c216ec6245e643927859a95632ebc7996f9077cd69d06835d19d6871c4bafe
[✓ INFO] 等待 MySQL 启动...
....mysqld is alive

  ✓ MySQL Docker 部署完成
[✓ INFO] 验证 MySQL 部署...
[✗ ERROR] MySQL 连接测试失败
```

关键特征：**清除旧数据后依然失败**，说明问题不是「旧数据残留」。

---

## 2. 根因：`mysqladmin ping` 会命中初始化阶段的临时服务器

### 2.1 官方镜像的两阶段启动

`mysql:8.0` 官方镜像的 `docker-entrypoint.sh` 在首次初始化时分两个阶段：

| 阶段 | 行为 |
|------|------|
| 阶段一 | 启动一个**临时 mysqld**（仅本地 socket），用于执行 root 改密、建库、建用户、跑 `/docker-entrypoint-initdb.d/*.sql` |
| 阶段二 | 关闭临时服务器，再以 PID 1 启动**正式 mysqld** |

### 2.2 服务器上抓到的真实时间线

从 `docker logs trojan-mysql` 与 `docker inspect` 得到：

| 时间 | 事件 |
|------|------|
| 17:09:33 | 容器创建，entrypoint 启动 |
| 17:09:34 | `Initializing database files` |
| 17:09:35 | `root@localhost is created with an empty password`（root 此刻无密码） |
| 17:09:39 | `Database files initialized`，**临时服务器起来** |
| ~17:09:41 | 脚本的 `mysqladmin ping` 返回 `mysqld is alive` → **循环提前退出** |
| 17:09:42 | `Creating database trojan_go` / `Creating user trojan` / 跑 `01-schema.sql` |
| 17:09:43 | `Received SHUTDOWN`，临时服务器开始关闭 |
| 17:09:45 | `MySQL init process done. Ready for start up.` → 正式服务器 `ready for connections` |

脚本日志里 `....mysqld is alive` 只等了约 4 秒，正好落在 **17:09:41**。

### 2.3 失败链条

`mysqladmin ping` 的语义是「服务器是否可达」，**不校验账号密码**，甚至 access denied 也会回 alive。所以：

1. 等待循环在**临时服务器**上就判定「MySQL 已就绪」并退出
2. 紧接着 `verify_mysql_deployment` 用 `trojan` 账号连接
3. 但此时 `trojan` 用户**尚未创建**（17:09:42 才创建），或临时服务器正在关闭（17:09:43）
4. → `ERROR 1045 Access denied` → 报「连接测试失败」

**这是竞态条件（race condition），不是密码不一致**。所以清除数据目录也无法解决，且必然可复现。

### 2.4 反证：初始化跑完后凭据完全可用

等容器彻底初始化完成后，用凭据文件里的密码连接立即成功：

```bash
$ sudo docker exec trojan-mysql mysql -utrojan -pEZCA9AmHIF6gLxJTrJcsuVjD -e 'SHOW TABLES' trojan_go
Tables_in_trojan_go
data_plane_sync_receipts
node_sync_receipts
nodes
users

$ sudo docker exec trojan-mysql mysql -uroot -pAtCgW70LRzMOeRl0UPJ8rsEk -e 'SELECT 1'
1
```

证明密码、建库、建表、初始化脚本**全部正常**，唯一的问题是脚本**查得太早**。

### 2.5 修正前一版报告的结论

上一版报告判断为「数据目录残留旧数据导致跳过初始化、密码不同步」。该结论**不成立**：本次日志明确出现 `Initializing database files`，说明确实执行了全新初始化，但依旧失败。真正原因是上述就绪判定竞态。

---

## 3. 附带发现的第二个缺陷（复用容器时写坏凭据）

在「容器已存在且在运行」的分支里，脚本会**先生成新随机密码，再把新密码写入 `.credentials` 并直接 return**。

但容器内 MySQL 的密码是创建时固化的，不会因为环境变量变化而改变。结果是：

- `.credentials` 里是**新随机密码**
- MySQL 内实际是**旧密码**
- 后续所有读取凭据文件的操作全部认证失败

这个缺陷会在「复用已有容器」时，真正制造出前一版报告所描述的「密码不一致」现象。

---

## 4. 修复内容

改动文件：[install.sh](file:///Users/wangwenjin/Downloads/workbuddy/clawcode/trojan-go-h2/install.sh)

### 4.1 就绪判定改为「初始化完成 + 真实登录成功」

放弃 `mysqladmin ping`，改为双重条件，两者同时满足才认为就绪：

1. 日志出现 `MySQL init process done`（临时服务器已退场）
2. 用目标账号 `mysql -u<user> -p<pass> -e 'SELECT 1' <db>` 真实登录成功

```bash
info "等待 MySQL 初始化完成..."
local max_wait=180
local waited=0
while true; do
    if sudo docker logs "${mysql_docker_name}" 2>&1 | grep -q "MySQL init process done"; then
        if sudo docker exec "${mysql_docker_name}" \
            mysql -u"${mysql_user}" -p"${mysql_password}" \
            -e "SELECT 1" "${mysql_dbname}" >/dev/null 2>&1; then
            break
        fi
    fi

    if ! sudo docker ps --format '{{.Names}}' | grep -q "^${mysql_docker_name}$"; then
        error "MySQL 容器意外退出，请检查: sudo docker logs ${mysql_docker_name}"
        return 1
    fi

    sleep 3
    waited=$((waited + 3))
    if [[ $waited -ge $max_wait ]]; then
        error "MySQL 初始化超时（${max_wait}s）"
        return 1
    fi
    echo -n "."
done
```

同时把超时从 60s 提到 180s（冷启动初始化可能超过 60s），并新增容器意外退出的提前失败判断。

### 4.2 复用容器时改为读取容器内真实密码

不再把新生成的密码覆盖写入，而是从运行中的容器读回真实生效的密码：

```bash
local live_root_pw live_pw
live_root_pw=$(sudo docker exec "${mysql_docker_name}" printenv MYSQL_ROOT_PASSWORD 2>/dev/null || true)
live_pw=$(sudo docker exec "${mysql_docker_name}" printenv MYSQL_PASSWORD 2>/dev/null || true)
[[ -n "$live_root_pw" ]] && mysql_docker_root_password="$live_root_pw"
[[ -n "$live_pw" ]] && mysql_password="$live_pw"
```

### 4.3 验证函数增加重试与诊断输出

原来单次失败即报错，且 `&>/dev/null` 把错误全吞掉。现在改为最多重试 5 次（间隔 3s），全部失败后**打印真实报错**并提示查看日志：

```bash
for attempt in 1 2 3 4 5; do
    if sudo docker exec "${mysql_docker_name}" mysql -u"${mysql_user}" -p"${mysql_password}" \
        -e "SELECT 1" "${mysql_dbname}" >/dev/null 2>&1; then
        success "MySQL 连接测试通过"
        return 0
    fi
    sleep 3
done

error "MySQL 连接测试失败"
warn "诊断信息如下："
sudo docker exec "${mysql_docker_name}" mysql -u"${mysql_user}" -p"${mysql_password}" \
    -e "SELECT 1" "${mysql_dbname}" 2>&1 | sed 's/^/    /' || true
warn "可执行以下命令查看容器日志: sudo docker logs ${mysql_docker_name}"
```

---

## 5. 修复验证（已在服务器实测）

`bash -n install.sh` 语法检查通过，上传到 `/mnt/trojan-go/` 后重跑主节点部署：

```bash
cd /mnt/trojan-go && sudo bash install.sh --config=/mnt/trojan-go/config.conf --master --local-binaries
```

结果：

```
  ✓ 主节点部署完成
  部署模式: master
  部署目录: /opt/trojan-go
  Secret: TG-21dacfb06868daa9f942f5fec17e13ea4e99362e50ce4b9537f7ad0221ffcf54
```

凭据一致性与认证复核：

```
# .credentials
MYSQL_PASSWORD=FIeVPeQxlMIhR6qrtseOcf4y

# 容器内实际生效值
FIeVPeQxlMIhR6qrtseOcf4y

# 用凭据文件密码认证
Tables_in_trojan_go
data_plane_sync_receipts
node_sync_receipts
nodes
users
```

| 检查项 | 结果 |
|--------|------|
| 脚本语法 | ✅ 通过 |
| MySQL 就绪判定 | ✅ 不再提前退出 |
| MySQL 连接测试 | ✅ 通过 |
| 凭据文件 vs 容器实际密码 | ✅ 一致 |
| 4 张表初始化 | ✅ 完整 |
| 主节点部署整体流程 | ✅ 完成 |

需要说明：本次验证覆盖到主节点部署流程跑通与 MySQL 相关逻辑，**尚未验证** Gateway/Admin/Control 三个 systemd 服务的实际运行状态与 SSL 证书签发结果。

---

## 6. 补充说明：为什么之前排查会被误导

`verify_mysql_deployment` 里的 `&>/dev/null` 把 `ERROR 1045` 完整吞掉，只留一行「连接测试失败」，导致无法区分以下三种完全不同的故障：

- Docker 权限不足（`permission denied ... docker API`）
- 账号密码不匹配（`Access denied`）
- 服务尚未就绪（连接被拒 / 用户不存在）

此次已在失败分支补上真实错误输出，后续同类问题可一眼定位。

---

## 7. 关键文件位置

| 内容 | 路径 |
|------|------|
| 二进制 / 脚本 / 配置 | `/mnt/trojan-go/` |
| 实际部署目录 | `/opt/trojan-go/` |
| MySQL 数据 | `/opt/trojan-go/mysql/data/` |
| MySQL 凭据 | `/opt/trojan-go/mysql/.credentials`（`chmod 600`） |

---

## 8. 结论

失败根因是 **MySQL 就绪判定竞态**：`mysqladmin ping` 在官方镜像初始化阶段的临时服务器上就返回成功，脚本因此在 `trojan` 用户尚未创建（或临时服务器正在关闭）时就发起验证，必然拿到 `Access denied`。

修复方式是把就绪判定改为「日志确认 `MySQL init process done` + 目标账号真实登录成功」双条件，并顺带修掉复用容器时覆盖写坏 `.credentials` 的缺陷、补上验证重试与真实错误输出。修复后在日本服务器实测主节点部署已完整跑通。
