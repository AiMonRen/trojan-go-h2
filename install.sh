#!/bin/bash
#
# Trojan-Go 节点部署脚本 v2.0
# 支持主节点（--master）和从节点（--worker）部署模式
#
# 二进制来源：克隆 voidluo/trojan-go 的 buildtest 分支到本机后使用 Go 编译，
#             不从 GitHub Release 下载任何预编译文件。
#
# 用法:
#   sudo bash install.sh --config=<配置文件路径> --master [--local-binaries]
#   sudo bash install.sh --config=<配置文件路径> --worker [--local-binaries]
#   sudo bash install.sh --config=<配置文件路径> --secret
#   sudo bash install.sh --config=<配置文件路径> --ssl [--force]
#
# 示例:
#   sudo bash install.sh --config=/mnt/trojan-go/config.conf --master
#   sudo bash install.sh --config=/mnt/trojan-go/config.conf --worker
#   sudo bash install.sh --config=/mnt/trojan-go/config.conf --secret
#   sudo bash install.sh --config=/mnt/trojan-go/config.conf --ssl
#   sudo bash install.sh --config=/mnt/trojan-go/config.conf --ssl --force
#

set -euo pipefail

# ==============================================================================
# 全局配置
# ==============================================================================
readonly REPO_OWNER="voidluo"
readonly REPO_NAME="trojan-go"

# 源码来源：仅允许克隆 voidluo/trojan-go 的 buildtest 分支后本地编译，
# 不再从 GitHub Release 下载任何预编译二进制。
readonly SOURCE_REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
readonly SOURCE_BRANCH="buildtest"
# 源码克隆与编译目录（与部署目录分离）。
# 固定用 src 子目录，避免 /opt/trojan-go 下旧部署残留（尤其 mysql/data
# 可能仍被运行中的容器挂载）被克隆前的清理动作误删。
readonly SOURCE_ROOT="/opt/trojan-go"
readonly SOURCE_DIR="${SOURCE_ROOT}/src"
readonly GO_PACKAGE_NAME="github.com/${REPO_OWNER}/${REPO_NAME}"

# Go 工具链要求（与 go.mod 中 go 指令保持一致）
readonly GO_MIN_VERSION="1.25.0"
readonly GO_VERSION="1.25.0"
readonly GO_INSTALL_DIR="/usr/local/go"

# 部署目录：编译产物与运行时配置的落地位置
readonly DEPLOY_DIR="/mnt/trojan-go"
readonly BIN_DIR="${DEPLOY_DIR}/bin"
readonly CONFIG_DIR="${DEPLOY_DIR}/config"
readonly CERTS_DIR="${DEPLOY_DIR}/certs"
readonly DATA_DIR="${DEPLOY_DIR}/data"
readonly LOGS_DIR="${DEPLOY_DIR}/logs"
readonly MYSQL_DIR="${DEPLOY_DIR}/mysql"
readonly GEODATA_DIR="${DEPLOY_DIR}/geodata"

readonly LOG_FILE="${LOGS_DIR}/install.log"
readonly SECRET_FILE="${DEPLOY_DIR}/secret.key"

# 服务间共享的固定地址与路由前缀。
# gateway 的 routes.* 必须与 admin 的 path/sub_path 一致，否则订阅链接 404。
readonly ADMIN_ADDR="127.0.0.1:8081"
readonly CONTROL_ADDR="127.0.0.1:8082"
readonly DATA_PLANE_ADDR="127.0.0.1:14443"
readonly ADMIN_PREFIX="/admin/"
readonly SUB_PATH="/sub"

# 服务间内部调用令牌。admin / control / data-plane 三方共读此文件
readonly INTERNAL_TOKEN_DIR="/var/lib/trojan-go"
readonly INTERNAL_TOKEN_FILE="${INTERNAL_TOKEN_DIR}/internal-token"

# hysteria2 由独立二进制承载，非 trojan-go 子命令
readonly HYSTERIA_BIN="/usr/local/bin/hysteria"

# 部署模式
DEPLOY_MODE=""
CONFIG_FILE=""
USE_LOCAL_BINARIES=false
SSL_FORCE=false

# 配置变量（默认值）
master=""
worker=""
secret=""
email=""
trojan_port=443
ws_enabled=false
ws_path="/trojan-go"
hy2_enabled=true
hy2_port=443
hy2_masquerade="https://www.bilibili.com"
hy2_up_mbps=100
hy2_down_mbps=500
db_type="mysql"
mysql_deploy="docker"
mysql_docker_name="trojan-mysql"
mysql_docker_root_password="AutoGenerate"
mysql_docker_port=3306
mysql_host="127.0.0.1"
mysql_port=3306
mysql_user="trojan"
mysql_password="AutoGenerate"
mysql_dbname="trojan_go"
sync_interval=60
admin_username="admin"
admin_password="AutoGenerate"
relay_entry_domain=""
relay_exit_domain=""
relay_exit_ip=""
relay_node_name=""

# ==============================================================================
# 颜色定义
# ==============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# ==============================================================================
# 日志函数
# ==============================================================================
_log() {
    local level=$1
    shift
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # 确保日志目录存在（首次调用时可能还未 create_deploy_directory）
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    echo "[${timestamp}] [${level}] $*" >> "$LOG_FILE" 2>/dev/null || true
}

info() {
    echo -e "${GREEN}[✓ INFO]${NC} $*"
    _log "INFO" "$*"
}

warn() {
    echo -e "${YELLOW}[! WARN]${NC} $*"
    _log "WARN" "$*"
}

error() {
    echo -e "${RED}[✗ ERROR]${NC} $*" >&2
    _log "ERROR" "$*"
}

debug() {
    _log "DEBUG" "$*"
}

header() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

success() {
    echo -e "${GREEN}  ✓ $*${NC}"
}

# ==============================================================================
# 1. 参数解析
# ==============================================================================
parse_args() {
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config=*)
                CONFIG_FILE="${1#*=}"
                shift
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --master)
                if [[ -n "$DEPLOY_MODE" && "$DEPLOY_MODE" != "secret" && "$DEPLOY_MODE" != "ssl" ]]; then
                    error "不能同时指定 --master 和 --worker (错误码: 3)"
                    exit 3
                fi
                DEPLOY_MODE="master"
                shift
                ;;
            --worker)
                if [[ -n "$DEPLOY_MODE" && "$DEPLOY_MODE" != "secret" && "$DEPLOY_MODE" != "ssl" ]]; then
                    error "不能同时指定 --master 和 --worker (错误码: 3)"
                    exit 3
                fi
                DEPLOY_MODE="worker"
                shift
                ;;
            --secret)
                DEPLOY_MODE="secret"
                shift
                ;;
            --ssl)
                DEPLOY_MODE="ssl"
                shift
                ;;
            --relay)
                DEPLOY_MODE="relay"
                shift
                ;;
            --force|-f)
                SSL_FORCE=true
                shift
                ;;
            --local-binaries|--local)
                USE_LOCAL_BINARIES=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                error "未知参数: $1"
                show_usage
                exit 3
                ;;
        esac
    done

    # 验证必需参数
    if [[ -z "$CONFIG_FILE" ]]; then
        error "请指定配置文件路径: --config=<path>"
        show_usage
        exit 1
    fi

    if [[ "$DEPLOY_MODE" != "secret" && "$DEPLOY_MODE" != "ssl" && "$DEPLOY_MODE" != "relay" && -z "$DEPLOY_MODE" ]]; then
        error "请指定部署模式 --master 或 --worker (错误码: 2)"
        show_usage
        exit 2
    fi
}

show_usage() {
    cat << EOF
${BOLD}Trojan-Go 节点部署脚本 v2.0${NC}

${BOLD}用法:${NC}
  sudo bash install.sh --config=<配置文件路径> --master [--local-binaries]
  sudo bash install.sh --config=<配置文件路径> --worker [--local-binaries]
  sudo bash install.sh --config=<配置文件路径> --secret
  sudo bash install.sh --config=<配置文件路径> --ssl [--force]
  sudo bash install.sh --config=<配置文件路径> --relay

${BOLD}参数:${NC}
  --config=<path>     配置文件路径（必填）
  --master            主节点模式
  --worker            从节点模式
  --secret            显示主节点 Secret
  --ssl               手动 SSL 证书续期模式
  --force             强制续期（忽略到期时间检查，与 --ssl 配合使用）
  --relay             中继节点模式（Gateway 内置 SNI 路由 + 订阅虚拟节点）
  --local-binaries    使用本地预编译二进制（跳过编译）
  --local-binaries    使用当前目录已有的 trojan-go / trojan（跳过源码编译）
                      别名: --local

${BOLD}中继模式说明:${NC}
  --relay 利用 Gateway 内置的 TLS ClientHello SNI 窥探功能实现 TCP 中继。
  无需 HAProxy，无需改端口。流量从 443 进入，Gateway 根据 SNI 路由:
    - 入口域名 → 正常 TLS 终止 + Trojan 代理
    - 出口域名 → TCP 直转到目标 Worker
  --help, -h          显示帮助

${BOLD}示例:${NC}
  # 主节点部署
  sudo bash install.sh --config=/mnt/trojan-go/config.conf --master

  # 从节点部署
  sudo bash install.sh --config=/mnt/trojan-go/config.conf --worker

  # 获取 Secret
  sudo bash install.sh --config=/mnt/trojan-go/config.conf --secret

  # 配置中继节点（日本入口 → 新加坡出口）
  sudo bash install.sh --config=/mnt/trojan-go/config.conf --relay

${BOLD}错误码:${NC}
  1 - 配置文件路径不存在
  2 - 未指定部署模式（--master/--worker）
  3 - 同时指定了 --master 和 --worker
  4 - 配置项缺失或不合法
  5 - 主节点模式下配置了非法的 worker/secret 值
  6 - 从节点模式下 worker 或 secret 为空
  7 - 二进制文件不存在或损坏

EOF
}

# ==============================================================================
# 2. 加载配置文件
# ==============================================================================
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "配置文件不存在: ${CONFIG_FILE} (错误码: 1)"
        exit 1
    fi

    info "加载配置文件: ${CONFIG_FILE}"

    # 解析配置文件
    while IFS='=' read -r key value; do
        # 跳过注释和空行
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue

        # 去除首尾空格
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)

        case "$key" in
            master) master="$value" ;;
            worker) worker="$value" ;;
            secret) secret="$value" ;;
            email) email="$value" ;;
            trojan_port) trojan_port="$value" ;;
            ws_enabled) ws_enabled="$value" ;;
            ws_path) ws_path="$value" ;;
            hy2_enabled) hy2_enabled="$value" ;;
            hy2_port) hy2_port="$value" ;;
            hy2_masquerade) hy2_masquerade="$value" ;;
            hy2_up_mbps) hy2_up_mbps="$value" ;;
            hy2_down_mbps) hy2_down_mbps="$value" ;;
            db_type) db_type="$value" ;;
            mysql_deploy) mysql_deploy="$value" ;;
            mysql_docker_name) mysql_docker_name="$value" ;;
            mysql_docker_root_password) mysql_docker_root_password="$value" ;;
            mysql_docker_port) mysql_docker_port="$value" ;;
            mysql_host) mysql_host="$value" ;;
            mysql_port) mysql_port="$value" ;;
            mysql_user) mysql_user="$value" ;;
            mysql_password) mysql_password="$value" ;;
            mysql_dbname) mysql_dbname="$value" ;;
            sync_interval) sync_interval="$value" ;;
            admin_username) admin_username="$value" ;;
            admin_password) admin_password="$value" ;;
            relay_entry_domain) relay_entry_domain="$value" ;;
            relay_exit_domain) relay_exit_domain="$value" ;;
            relay_exit_ip) relay_exit_ip="$value" ;;
            relay_node_name) relay_node_name="$value" ;;
        esac
    done < "$CONFIG_FILE"

    debug "配置加载完成: master=${master}, worker=${worker}, db_type=${db_type}"
}

# ==============================================================================
# 3. 环境预检
# ==============================================================================
preflight_check() {
    header "环境预检 / Pre-flight Check"

    # 操作系统检测
    if [[ "$(uname -s)" != "Linux" ]]; then
        error "仅支持 Linux 系统 (当前: $(uname -s))"
        exit 1
    fi
    info "操作系统: Linux"

    # 架构检测
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)
            error "不支持的架构: $ARCH (仅支持 x86_64/aarch64)"
            exit 1
            ;;
    esac
    info "系统架构: ${ARCH}"

    # 权限检测
    if [[ $EUID -ne 0 ]]; then
        error "需要 root 权限，请使用 sudo 运行"
        exit 1
    fi
    info "权限检查: root"

    # 依赖检测。ss 用于端口占用检查与服务就绪轮询，git 用于克隆源码
    local -A dep_pkgs=(
        [curl]=curl
        [tar]=tar
        [openssl]=openssl
        [git]=git
        [ss]=iproute2
    )
    local missing_deps=() missing_pkgs=()
    local cmd
    for cmd in curl tar openssl git ss; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
            missing_pkgs+=("${dep_pkgs[$cmd]}")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warn "缺少依赖: ${missing_deps[*]}"
        info "尝试自动安装: ${missing_pkgs[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq "${missing_pkgs[@]}"
        elif command -v yum &>/dev/null; then
            # RHEL 系的 ss 来自 iproute，xxd 来自 vim-common
            yum install -y -q "${missing_pkgs[@]/iproute2/iproute}"
        elif command -v dnf &>/dev/null; then
            dnf install -y -q "${missing_pkgs[@]/iproute2/iproute}"
        else
            error "无法自动安装依赖，请手动安装: ${missing_pkgs[*]}"
            exit 1
        fi

        # 安装后复检，缺失关键命令时后续流程会静默走错分支
        local still_missing=()
        for cmd in "${missing_deps[@]}"; do
            command -v "$cmd" &>/dev/null || still_missing+=("$cmd")
        done
        if [[ ${#still_missing[@]} -gt 0 ]]; then
            error "以下依赖安装失败: ${still_missing[*]}"
            exit 1
        fi
    fi
    info "依赖检查通过"

    # systemd 检测
    if ! command -v systemctl &>/dev/null; then
        error "未检测到 systemd，请使用支持 systemd 的发行版"
        exit 1
    fi
    info "systemd 检测通过"

    # 初始化日志目录
    mkdir -p "$LOGS_DIR"
    echo "===== Trojan-Go 安装日志 $(date) =====" >> "$LOG_FILE"
}

# ==============================================================================
# 4. 配置校验
# ==============================================================================
validate_config() {
    header "配置校验 / Config Validation"

    if [[ "$DEPLOY_MODE" == "master" ]]; then
        validate_master_config
    elif [[ "$DEPLOY_MODE" == "worker" ]]; then
        validate_worker_config
    elif [[ "$DEPLOY_MODE" == "relay" ]]; then
        validate_relay_config
    fi
}

validate_master_config() {
    info "校验主节点配置..."

    # 校验 master 域名
    if [[ -z "$master" ]]; then
        error "master 域名不能为空 (错误码: 4)"
        exit 4
    fi

    # 校验 worker 必须为 no
    if [[ "$worker" != "no" ]]; then
        error "主节点模式下 worker 必须为 'no' (错误码: 5)"
        exit 5
    fi

    # 校验 secret 必须为 no
    if [[ "$secret" != "no" ]]; then
        error "主节点模式下 secret 必须为 'no' (错误码: 5)"
        exit 5
    fi

    # 校验邮箱格式
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        error "邮箱格式不合法: ${email} (错误码: 4)"
        exit 4
    fi

    success "主节点配置校验通过"
}

validate_worker_config() {
    info "校验从节点配置..."

    # 校验 master 域名
    if [[ -z "$master" ]]; then
        error "master 域名不能为空 (错误码: 4)"
        exit 4
    fi

    # 校验 worker 域名
    if [[ -z "$worker" || "$worker" == "no" ]]; then
        error "从节点模式下 worker 必须填写有效域名 (错误码: 6)"
        exit 6
    fi

    # 校验 secret
    if [[ -z "$secret" || "$secret" == "no" ]]; then
        error "从节点模式下 secret 不能为空 (错误码: 6)"
        exit 6
    fi

    # 校验邮箱格式
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        error "邮箱格式不合法: ${email} (错误码: 4)"
        exit 4
    fi

    success "从节点配置校验通过"
}

validate_relay_config() {
    info "校验中继节点配置..."

    if [[ -z "$relay_entry_domain" ]]; then
        error "relay_entry_domain 不能为空（入口节点域名） (错误码: 4)"
        exit 4
    fi

    if [[ -z "$relay_exit_domain" ]]; then
        error "relay_exit_domain 不能为空（出口节点域名） (错误码: 4)"
        exit 4
    fi

    if [[ -z "$relay_exit_ip" ]]; then
        error "relay_exit_ip 不能为空（出口节点 IP） (错误码: 4)"
        exit 4
    fi

    if [[ -z "$relay_node_name" ]]; then
        relay_node_name="relay"
        info "relay_node_name 未设置，使用默认值: relay"
    fi

    # 确保已部署的 gateway 存在
    if ! systemctl is-active --quiet trojan-go-gateway.service 2>/dev/null; then
        error "trojan-go-gateway.service 未运行 — 请先在当前节点部署 trojan-go"
        exit 4
    fi

    success "中继节点配置校验通过"
}

# ==============================================================================
# 4.5 清理已有服务与残留进程
# ==============================================================================
# 已知的 trojan-go / hysteria2 相关 systemd 单元（含旧版部署使用的命名）
readonly KNOWN_UNITS=(
    "trojan-go-gateway"
    "trojan-go-admin"
    "trojan-go-control"
    "trojan-go-data-plane"
    "trojan-go-hysteria"
    "gateway-service"
    "admin-service"
    "control-service"
    "trojan-data-plane"
    "trojan-go"
    "trojan"
    "trojan-web"
    "hysteria"
    "hysteria2"
    "hy2"
)

cleanup_existing_services() {
    header "清理已有服务 / Cleanup Existing Services"

    warn "本步骤会停止并杀死所有 trojan-go / hysteria2 相关进程"

    # 1. 先停止并禁用 systemd 单元，避免 Restart=on-failure 把进程自动拉起
    #    使用 systemctl cat 判断单元是否存在（单条命令，避免管道 SIGPIPE 导致漏判）
    local unit
    for unit in "${KNOWN_UNITS[@]}"; do
        if systemctl cat "${unit}.service" &>/dev/null; then
            info "停止服务: ${unit}.service"
            systemctl stop "${unit}.service" 2>/dev/null || true
            systemctl disable "${unit}.service" 2>/dev/null || true
        fi
    done

    # 2. 清理残留进程
    kill_leftover_processes

    # 3. 校验端口；若仍被占用，说明有进程在单元停止过程中被拉起，再清理一轮
    if ! verify_ports_released; then
        warn "检测到端口未释放，执行第二轮清理..."
        kill_leftover_processes
        verify_ports_released || true
    fi

    success "已有服务清理完成"
}

kill_leftover_processes() {
    # 只匹配可执行文件名，避免误杀本安装脚本自身（脚本路径可能含 trojan-go）
    local patterns=("trojan-go" "trojan" "hysteria")
    local self_pid=$$
    local pattern pid pids exe

    for pattern in "${patterns[@]}"; do
        # 第一轮 SIGTERM
        pids=$(pgrep -x "$pattern" 2>/dev/null || true)
        for pid in $pids; do
            [[ "$pid" == "$self_pid" ]] && continue
            exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)
            info "SIGTERM 结束进程 ${pid} (${exe:-$pattern})"
            kill -TERM "$pid" 2>/dev/null || true
        done
    done

    sleep 3

    for pattern in "${patterns[@]}"; do
        # 第二轮 SIGKILL，处理未响应 SIGTERM 的进程
        pids=$(pgrep -x "$pattern" 2>/dev/null || true)
        for pid in $pids; do
            [[ "$pid" == "$self_pid" ]] && continue
            warn "SIGKILL 强制结束进程 ${pid} (${pattern})"
            kill -KILL "$pid" 2>/dev/null || true
        done
    done

    sleep 1
}

verify_ports_released() {
    # MySQL 容器占用 3306，属于本脚本自身依赖，不在检查范围
    # trojan_port 与 hy2_port 默认同为 443（TCP/UDP 不冲突），需去重避免重复告警
    local check_ports
    check_ports=$(printf '%s\n' "${trojan_port}" "${hy2_port}" 8081 8082 14443 | sort -u)

    local port occupied_by still_occupied=()

    for port in $check_ports; do
        occupied_by=$(ss -tulnp 2>/dev/null | grep -E "[:.]${port}\s" | grep -viE 'docker|mysql' || true)
        if [[ -n "$occupied_by" ]]; then
            still_occupied+=("$port")
            warn "端口 ${port} 仍被占用:"
            echo "$occupied_by" | sed 's/^/    /'
        fi
    done

    if [[ ${#still_occupied[@]} -gt 0 ]]; then
        warn "以下端口未释放: ${still_occupied[*]}"
        warn "服务启动可能失败，请手动确认占用进程"
        return 1
    fi

    info "关键端口已全部释放"
    return 0
}

# ==============================================================================
# 5. 二进制文件检测与部署
# 二进制文件一律在本机从源码编译，不从 GitHub Release 下载
# ==============================================================================
detect_or_build_binaries() {
    header "编译并部署二进制文件 / Build & Deploy Binaries"

    mkdir -p "$BIN_DIR"

    if [[ "$USE_LOCAL_BINARIES" == "true" ]]; then
        deploy_local_binaries
    else
        build_binaries_from_source
    fi

    # 验证二进制文件
    verify_binaries
}

deploy_local_binaries() {
    info "使用本地已编译的二进制文件..."

    local required_bins=("trojan-go" "trojan")
    local missing_bins=()

    for bin in "${required_bins[@]}"; do
        if [[ ! -f "./${bin}" ]]; then
            missing_bins+=("$bin")
        fi
    done

    if [[ ${#missing_bins[@]} -gt 0 ]]; then
        error "本地二进制文件不存在: ${missing_bins[*]} (错误码: 7)"
        error "请确保 trojan-go 和 trojan 在当前目录，或去掉 --local-binaries 由脚本源码编译"
        exit 7
    fi

    cp -f trojan-go trojan "$BIN_DIR/"
    chmod +x "${BIN_DIR}/trojan-go" "${BIN_DIR}/trojan"
    success "本地二进制文件已复制到 ${BIN_DIR}"
}

# 从 voidluo/trojan-go 的 buildtest 分支克隆源码并本地编译
build_binaries_from_source() {
    info "从源码编译二进制文件（仓库: ${SOURCE_REPO_URL}，分支: ${SOURCE_BRANCH}）"

    ensure_go_toolchain

    install -d -m 0755 "$(dirname "$SOURCE_DIR")"

    if [[ -d "${SOURCE_DIR}/.git" ]]; then
        info "源码目录已存在，拉取 ${SOURCE_BRANCH} 最新代码"
        git -C "$SOURCE_DIR" remote set-url origin "$SOURCE_REPO_URL"
        git -C "$SOURCE_DIR" fetch --depth=1 origin "$SOURCE_BRANCH" || {
            error "拉取源码失败: ${SOURCE_REPO_URL} (${SOURCE_BRANCH}) (错误码: 7)"
            exit 7
        }
        git -C "$SOURCE_DIR" checkout -B "$SOURCE_BRANCH" FETCH_HEAD || {
            error "切换分支失败: ${SOURCE_BRANCH} (错误码: 7)"
            exit 7
        }
    else
        rm -rf "$SOURCE_DIR"
        info "克隆源码到 ${SOURCE_DIR}"
        git clone --depth=1 --branch "$SOURCE_BRANCH" "$SOURCE_REPO_URL" "$SOURCE_DIR" || {
            error "克隆源码失败: ${SOURCE_REPO_URL} (${SOURCE_BRANCH}) (错误码: 7)"
            exit 7
        }
    fi

    local commit
    commit=$(git -C "$SOURCE_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    info "源码版本: ${SOURCE_BRANCH}@${commit}"

    info "开始编译 trojan-go 与 trojan（架构: ${ARCH}）..."
    local build_out="${SOURCE_DIR}/build/linux-${ARCH}"
    (
        cd "$SOURCE_DIR"
        export PATH="${GO_INSTALL_DIR}/bin:${PATH}"
        export GOFLAGS=-mod=mod
        export CGO_ENABLED=0
        export GOOS=linux
        export GOARCH="$ARCH"
        export GOCACHE="${SOURCE_DIR}/.cache/go-build"
        export GOMODCACHE="${SOURCE_DIR}/.cache/go-mod"
        local ldflags="-s -w -buildid= -X ${GO_PACKAGE_NAME}/version.Version=${SOURCE_BRANCH}-${commit} -X ${GO_PACKAGE_NAME}/version.Commit=${commit}"
        mkdir -p "build/linux-${ARCH}"
        go build -a -tags "full" -trimpath -ldflags="$ldflags" -o "build/linux-${ARCH}/trojan-go" ./cmd/trojan-go
        go build -a -tags "full" -trimpath -ldflags="$ldflags" -o "build/linux-${ARCH}/trojan" ./cmd/trojan
    ) || {
        error "源码编译失败，请检查上方 go build 输出 (错误码: 7)"
        exit 7
    }

    install -m 0755 "${build_out}/trojan-go" "${BIN_DIR}/trojan-go"
    install -m 0755 "${build_out}/trojan" "${BIN_DIR}/trojan"
    success "编译完成，二进制已安装到 ${BIN_DIR}"
}

# 保证 go 工具链存在且版本满足 go.mod 要求
ensure_go_toolchain() {
    local go_bin=""
    if [[ -x "${GO_INSTALL_DIR}/bin/go" ]]; then
        go_bin="${GO_INSTALL_DIR}/bin/go"
    elif command -v go &>/dev/null; then
        go_bin="$(command -v go)"
    fi

    if [[ -n "$go_bin" ]]; then
        local cur
        cur=$("$go_bin" env GOVERSION 2>/dev/null | sed 's/^go//')
        if [[ -n "$cur" ]] && version_ge "$cur" "$GO_MIN_VERSION"; then
            info "检测到 Go ${cur}"
            export PATH="$(dirname "$go_bin"):${PATH}"
            return 0
        fi
        warn "当前 Go 版本 ${cur:-未知} 低于要求的 ${GO_MIN_VERSION}，将安装官方工具链"
    else
        info "未检测到 Go 工具链，开始安装 Go ${GO_VERSION}"
    fi

    local go_tar="go${GO_VERSION}.linux-${ARCH}.tar.gz"
    local go_url="https://go.dev/dl/${go_tar}"
    local temp_dir
    temp_dir=$(mktemp -d)

    info "下载 Go 工具链: ${go_url}"
    if ! curl -fsSL -o "${temp_dir}/${go_tar}" "$go_url"; then
        rm -rf "$temp_dir"
        error "Go 工具链下载失败: ${go_url} (错误码: 7)"
        error "请手动安装 Go >= ${GO_MIN_VERSION} 后重新运行"
        exit 7
    fi

    rm -rf "$GO_INSTALL_DIR"
    tar -C "$(dirname "$GO_INSTALL_DIR")" -xzf "${temp_dir}/${go_tar}" || {
        rm -rf "$temp_dir"
        error "Go 工具链解压失败 (错误码: 7)"
        exit 7
    }
    rm -rf "$temp_dir"

    export PATH="${GO_INSTALL_DIR}/bin:${PATH}"
    if ! "${GO_INSTALL_DIR}/bin/go" version &>/dev/null; then
        error "Go 工具链安装校验失败 (错误码: 7)"
        exit 7
    fi
    success "Go 工具链就绪: $("${GO_INSTALL_DIR}/bin/go" version)"
}

# 版本号比较：$1 >= $2 返回 0
version_ge() {
    [[ "$1" == "$2" ]] && return 0
    local greater
    greater=$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)
    [[ "$greater" == "$1" ]]
}

verify_binaries() {
    info "验证二进制文件..."

    # 检查文件是否存在
    if [[ ! -f "${BIN_DIR}/trojan-go" ]]; then
        error "trojan-go 二进制文件不存在 (错误码: 7)"
        exit 7
    fi

    if [[ ! -f "${BIN_DIR}/trojan" ]]; then
        error "trojan 二进制文件不存在 (错误码: 7)"
        exit 7
    fi

    # 检查可执行权限
    chmod +x "${BIN_DIR}/trojan-go" "${BIN_DIR}/trojan"

    # 尝试获取版本信息
    if "${BIN_DIR}/trojan-go" -version &>/dev/null; then
        local version
        version=$("${BIN_DIR}/trojan-go" -version 2>&1 | head -1)
        success "trojan-go 验证通过: ${version}"
    else
        warn "trojan-go 版本验证失败，但文件存在"
    fi

    # hysteria2 是独立二进制，不在 trojan-go 发布包内
    ensure_hysteria_binary
}

# hysteria2 由独立进程承载，需单独确保二进制存在
ensure_hysteria_binary() {
    [[ "$hy2_enabled" != "true" ]] && return 0

    if [[ -x "$HYSTERIA_BIN" ]]; then
        info "hysteria 二进制已存在: ${HYSTERIA_BIN}"
        return 0
    fi

    info "下载 hysteria2 二进制..."

    local hy_arch
    case "$ARCH" in
        amd64) hy_arch="amd64" ;;
        arm64) hy_arch="arm64" ;;
        *)
            error "hysteria2 不支持的架构: ${ARCH} (错误码: 7)"
            exit 7
            ;;
    esac

    local hy_url="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${hy_arch}"
    if ! curl -sL --fail -o "$HYSTERIA_BIN" "$hy_url"; then
        error "hysteria2 二进制下载失败: ${hy_url} (错误码: 7)"
        error "hy2_enabled=true 但无法获取二进制，部署已中止"
        error "可手动下载后放置到 ${HYSTERIA_BIN} 并重新执行"
        exit 7
    fi

    chmod +x "$HYSTERIA_BIN"

    if ! "$HYSTERIA_BIN" version &>/dev/null; then
        error "hysteria2 二进制无法执行 (错误码: 7)"
        exit 7
    fi

    success "hysteria2 二进制已就绪: ${HYSTERIA_BIN}"
}

# 预置服务间内部令牌。
# admin 启动时也会自动创建，但 control-service 与 data-plane 只读不创建，
# 依赖 admin 先启动属于隐式顺序耦合，因此在启动任何服务前先落盘。
provision_internal_token() {
    header "预置内部服务令牌 / Provision Internal Token"

    install -d -m 0700 -o root -g root "$INTERNAL_TOKEN_DIR"

    if [[ -f "$INTERNAL_TOKEN_FILE" ]]; then
        # secretfile.Read 要求非符号链接、owner-only、属主正确的常规文件
        if [[ -L "$INTERNAL_TOKEN_FILE" || ! -f "$INTERNAL_TOKEN_FILE" ]]; then
            error "${INTERNAL_TOKEN_FILE} 不是常规文件，拒绝使用 (错误码: 9)"
            exit 9
        fi
        chmod 0600 "$INTERNAL_TOKEN_FILE"
        chown root:root "$INTERNAL_TOKEN_FILE"
        info "内部令牌已存在，复用并修正权限"
        success "内部令牌就绪"
        return 0
    fi

    # 64 字符十六进制，满足 >=16 字符的长度校验
    # tr -d '\n' 去除 openssl 输出的尾部换行，避免 Go net/http 拒绝 header value
    ( umask 077 && openssl rand -hex 32 | tr -d '\n' > "$INTERNAL_TOKEN_FILE" )
    chmod 0600 "$INTERNAL_TOKEN_FILE"
    chown root:root "$INTERNAL_TOKEN_FILE"

    success "内部令牌已生成: ${INTERNAL_TOKEN_FILE}"
}

# 用二进制自带的 config-check 在启动前校验配置，
# 把 schema 错误暴露在部署阶段而非 systemd 重启循环里
validate_generated_configs() {
    header "校验生成的配置 / Validate Generated Configs"

    local failed=0

    _check_one() {
        local svc="$1" cfg="$2"
        if [[ ! -f "$cfg" ]]; then
            error "配置文件缺失: ${cfg}"
            failed=1
            return
        fi
        local output
        if output=$("${BIN_DIR}/trojan-go" config-check --service "$svc" --config "$cfg" 2>&1); then
            info "配置校验通过: ${svc}"
        else
            error "配置校验失败: ${svc}"
            echo "$output" | sed 's/^/    /'
            failed=1
        fi
    }

    _check_one gateway "${CONFIG_DIR}/gateway.yaml"
    _check_one data-plane "${CONFIG_DIR}/data-plane.yaml"

    if [[ "$DEPLOY_MODE" == "master" ]]; then
        _check_one admin "${CONFIG_DIR}/admin.yaml"
    else
        _check_one worker-control "${CONFIG_DIR}/control-worker.yaml"
    fi

    if [[ $failed -ne 0 ]]; then
        error "配置校验未通过，已在启动服务前中止 (错误码: 10)"
        exit 10
    fi

    success "全部配置校验通过"
}

# ==============================================================================
# 6. 创建部署目录
# ==============================================================================
create_deploy_directory() {
    header "创建部署目录 / Create Deploy Directory"

    local dirs=(
        "$BIN_DIR"
        "$CONFIG_DIR"
        "$CERTS_DIR"
        "$DATA_DIR"
        "$LOGS_DIR"
        "$MYSQL_DIR"
        "$MYSQL_DIR/data"
        "$MYSQL_DIR/init"
        "$GEODATA_DIR"
    )

    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done

    # 复制配置文件到部署目录
    cp -f "$CONFIG_FILE" "${CONFIG_DIR}/config.conf"
    chmod 600 "${CONFIG_DIR}/config.conf"

    success "部署目录创建完成: ${DEPLOY_DIR}"
}

# ==============================================================================
# 7. Secret 生成
# ==============================================================================
generate_secret() {
    local random_bytes
    random_bytes=$(openssl rand -hex 32)
    secret="TG-${random_bytes}"

    # 保存到文件
    echo "$secret" > "$SECRET_FILE"
    chmod 600 "$SECRET_FILE"

    info "节点认证密钥已生成"
}

# ==============================================================================
# 8. Docker MySQL 自动部署
# ==============================================================================
deploy_mysql_docker() {
    header "部署 MySQL Docker 容器 / Deploy MySQL Docker"

    # 检查 Docker 是否安装
    if ! command -v docker &>/dev/null; then
        info "Docker 未安装，正在安装..."

        # 等待 apt lock 释放（可能有 unattended-upgrades 在运行）
        local lock_wait=0
        while fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock-frontend &>/dev/null; do
            if (( lock_wait >= 120 )); then
                warn "等待 apt lock 超时 (${lock_wait}s)，强制继续"
                break
            fi
            info "等待 apt lock 释放... (${lock_wait}s)"
            sleep 10
            (( lock_wait += 10 ))
        done

        curl -fsSL https://get.docker.com | sh
        systemctl enable docker
        systemctl start docker
        success "Docker 安装完成"
    fi

    # 生成随机密码（在检查容器之前生成，确保后续使用）
    if [[ "$mysql_docker_root_password" == "AutoGenerate" ]]; then
        mysql_docker_root_password=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
    fi
    if [[ "$mysql_password" == "AutoGenerate" ]]; then
        mysql_password=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
    fi

    # 检查数据目录是否已有数据（需要重置）
    if [[ -d "${MYSQL_DIR}/data" ]] && [[ -n "$(ls -A "${MYSQL_DIR}/data" 2>/dev/null)" ]]; then
        warn "检测到已有 MySQL 数据目录，需要重新初始化..."
        
        # 停止并删除旧容器
        if sudo docker ps -a --format '{{.Names}}' | grep -q "^${mysql_docker_name}$"; then
            info "停止并删除旧容器..."
            sudo docker stop "${mysql_docker_name}" 2>/dev/null || true
            sudo docker rm "${mysql_docker_name}" 2>/dev/null || true
        fi
        
        # 删除旧数据
        info "清除旧数据目录..."
        sudo rm -rf "${MYSQL_DIR}/data"/*
        info "已清除旧数据，MySQL 将重新初始化"
    fi

    # 检查容器是否已存在（复用容器时必须沿用容器内已有的密码，不能写入新生成的密码）
    if sudo docker ps -a --format '{{.Names}}' | grep -q "^${mysql_docker_name}$"; then
        warn "MySQL 容器已存在: ${mysql_docker_name}"

        if ! sudo docker ps --format '{{.Names}}' | grep -q "^${mysql_docker_name}$"; then
            info "启动已存在的 MySQL 容器..."
            sudo docker start "${mysql_docker_name}"
            sleep 5
        else
            info "MySQL 容器正在运行"
        fi

        # 从容器环境变量读取真实生效的密码
        local live_root_pw live_pw
        live_root_pw=$(sudo docker exec "${mysql_docker_name}" printenv MYSQL_ROOT_PASSWORD 2>/dev/null || true)
        live_pw=$(sudo docker exec "${mysql_docker_name}" printenv MYSQL_PASSWORD 2>/dev/null || true)
        [[ -n "$live_root_pw" ]] && mysql_docker_root_password="$live_root_pw"
        [[ -n "$live_pw" ]] && mysql_password="$live_pw"

        cat > "${MYSQL_DIR}/.credentials" << EOF
MYSQL_ROOT_PASSWORD=${mysql_docker_root_password}
MYSQL_USER=${mysql_user}
MYSQL_PASSWORD=${mysql_password}
MYSQL_DATABASE=${mysql_dbname}
EOF
        chmod 600 "${MYSQL_DIR}/.credentials"
        return 0
    fi

    # 创建初始化脚本
    create_mysql_init_script

    # 启动 MySQL 容器
    info "启动 MySQL 容器..."
    sudo docker run -d \
        --name "${mysql_docker_name}" \
        --restart unless-stopped \
        -e MYSQL_ROOT_PASSWORD="${mysql_docker_root_password}" \
        -e MYSQL_DATABASE="${mysql_dbname}" \
        -e MYSQL_USER="${mysql_user}" \
        -e MYSQL_PASSWORD="${mysql_password}" \
        -v "${MYSQL_DIR}/data:/var/lib/mysql" \
        -v "${MYSQL_DIR}/init:/docker-entrypoint-initdb.d:ro" \
        -p "127.0.0.1:${mysql_port}:3306" \
        mysql:8.0 \
        --character-set-server=utf8mb4 \
        --collation-server=utf8mb4_unicode_ci \
        --default-authentication-plugin=mysql_native_password

    # 等待 MySQL 就绪
    # 注意：不能用 mysqladmin ping 判断，初始化期间的临时服务器也会响应 ping，
    # 此时用户与密码尚未创建完成。必须等到 entrypoint 输出 "ready for connections"
    # 且能用目标账号真实登录，才算就绪。
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
            echo ""
            error "MySQL 容器意外退出，请检查: sudo docker logs ${mysql_docker_name}"
            return 1
        fi

        sleep 3
        waited=$((waited + 3))
        if [[ $waited -ge $max_wait ]]; then
            echo ""
            error "MySQL 初始化超时（${max_wait}s）"
            return 1
        fi
        echo -n "."
    done
    echo ""

    success "MySQL Docker 部署完成"

    # 保存密码到安全文件
    cat > "${MYSQL_DIR}/.credentials" << EOF
MYSQL_ROOT_PASSWORD=${mysql_docker_root_password}
MYSQL_USER=${mysql_user}
MYSQL_PASSWORD=${mysql_password}
MYSQL_DATABASE=${mysql_dbname}
EOF
    chmod 600 "${MYSQL_DIR}/.credentials"
}

create_mysql_init_script() {
    cat > "${MYSQL_DIR}/init/01-schema.sql" << 'EOF'
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
EOF
}

verify_mysql_deployment() {
    info "验证 MySQL 部署..."

    # 检查容器状态
    if ! sudo docker ps --format '{{.Names}}' | grep -q "^${mysql_docker_name}$"; then
        error "MySQL 容器未运行"
        return 1
    fi

    # 测试连接（带重试，避免服务刚重启时的瞬时失败）
    local attempt
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
    return 1
}

# ==============================================================================
# 9. 服务配置生成
# ==============================================================================
generate_service_configs() {
    header "生成服务配置 / Generate Service Configs"

    # 生成 Gateway 配置
    generate_gateway_config

    if [[ "$DEPLOY_MODE" == "master" ]]; then
        # 生成 Admin 配置（master control-service 不读配置文件）
        generate_admin_config
    else
        # 生成 Worker Control 配置
        generate_control_worker_config
    fi

    # 生成 data-plane 配置（承载实际代理流量，两种模式都需要）
    generate_data_plane_config

    # 生成 hysteria2 配置（独立进程）
    generate_hysteria_config

    success "服务配置生成完成"
}

generate_gateway_config() {
    local sni
    if [[ "$DEPLOY_MODE" == "master" ]]; then
        sni="$master"
    else
        sni="$worker"
    fi

    # worker 节点不承载 admin 面板，需在 gateway.admin_disabled 内声明
    local admin_disabled="false"
    if [[ "$DEPLOY_MODE" == "worker" ]]; then
        admin_disabled="true"
    fi

    # schema 对应 internal/webserver.gatewayFileConfig。
    # 注意：gateway 仅消费 ssl / gateway / routes 三段，
    # hysteria2 与分流规则分别由独立的 hysteria 进程和 data-plane 承载。
    cat > "${CONFIG_DIR}/gateway.yaml" << EOF
ssl:
  cert: ${CERTS_DIR}/fullchain.crt
  key: ${CERTS_DIR}/private.key

gateway:
  listen: 0.0.0.0:${trojan_port}
  admin_service: ${ADMIN_ADDR}
  admin_disabled: ${admin_disabled}
  control_service: ${CONTROL_ADDR}
  trojan_service: ${DATA_PLANE_ADDR}
EOF

    # 中继路由表：SNI=出口域名 → 转发到出口 IP:443
    if [[ -n "$relay_exit_domain" && -n "$relay_exit_ip" ]]; then
        cat >> "${CONFIG_DIR}/gateway.yaml" << INNEREOF
  relay:
    ${relay_exit_domain}: ${relay_exit_ip}:443
INNEREOF
        info "Gateway 中继路由: SNI=${relay_exit_domain} -> ${relay_exit_ip}:443"
    fi

    cat >> "${CONFIG_DIR}/gateway.yaml" << EOF

routes:
  admin_prefix: ${ADMIN_PREFIX}
  sub_path: ${SUB_PATH}
EOF

    # sni 由证书自身携带，gateway 不单独消费该字段
    debug "Gateway SNI 来自证书: ${sni}"

    info "Gateway 配置已生成"
}

# 构造 admin/data-plane 共用的数据库连接串。
# internal/database.InitDb 以 "mysql:" 前缀判定驱动；缺前缀会被静默当成
# SQLite 文件路径，服务能起但连的是空库，因此前缀必须保留。
build_db_dsn() {
    if [[ "$db_type" == "mysql" ]]; then
        printf 'mysql:%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local' \
            "$mysql_user" "$mysql_password" "$mysql_host" "$mysql_port" "$mysql_dbname"
    else
        printf '%s/trojan-go.db' "$DATA_DIR"
    fi
}

generate_admin_config() {
    # 生成管理员密码
    if [[ "$admin_password" == "AutoGenerate" ]]; then
        admin_password=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 16)
    fi

    local db_dsn
    db_dsn=$(build_db_dsn)

    # schema 对应 internal/webserver.standaloneConfig
    # node.enabled=true 表示当前节点运行 control（Worker 模式），否则运行 admin（Master 模式）
    local node_enabled="false"
    if [[ "$DEPLOY_MODE" == "worker" ]]; then
        node_enabled="true"
    fi
    cat > "${CONFIG_DIR}/admin.yaml" << EOF
admin:
  enabled: true
  db: "${db_dsn}"
  username: "${admin_username}"
  password: "${admin_password}"
  path: ${ADMIN_PREFIX}
  sub_path: ${SUB_PATH}
  server_domain: "${master}"
node:
  enabled: ${node_enabled}
EOF
    # 含 MySQL 明文口令
    chmod 600 "${CONFIG_DIR}/admin.yaml"

    # 保存管理员凭据
    cat > "${CONFIG_DIR}/.admin_credentials" << EOF
ADMIN_USERNAME=${admin_username}
ADMIN_PASSWORD=${admin_password}
EOF
    chmod 600 "${CONFIG_DIR}/.admin_credentials"

    info "Admin 配置已生成"
}

# master 模式的 control-service 不读配置文件：
# cmd/trojan-go/main.go 走 RunControlService(listen, admin)，仅认命令行参数。
# 监听地址与 admin 后端地址在 create_control_service 中通过 -listen/-admin 传入。

generate_control_worker_config() {
    # worker control-service 与 admin 共用 standaloneConfig schema，
    # 且额外要求 node.enabled=true（services.go:68）

    # 该分支不经过 generate_admin_config，需自行展开 AutoGenerate，
    # 否则字面量 "AutoGenerate" 会被当成真实口令写入配置
    if [[ "$admin_password" == "AutoGenerate" ]]; then
        admin_password=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 16)
    fi

    local db_dsn
    db_dsn=$(build_db_dsn)

    cat > "${CONFIG_DIR}/control-worker.yaml" << EOF
admin:
  enabled: true
  db: "${db_dsn}"
  username: "${admin_username}"
  password: "${admin_password}"
  path: ${ADMIN_PREFIX}
  sub_path: ${SUB_PATH}
  server_domain: "${worker}"
node:
  enabled: true
  master_url: https://${master}/control/v1/nodes/sync
  secret: "${secret}"
  sync_interval: ${sync_interval}
  traffic_outbox: ${DATA_DIR}/traffic-outbox.json
EOF
    chmod 600 "${CONFIG_DIR}/control-worker.yaml"

    cat > "${CONFIG_DIR}/.admin_credentials" << EOF
ADMIN_USERNAME=${admin_username}
ADMIN_PASSWORD=${admin_password}
EOF
    chmod 600 "${CONFIG_DIR}/.admin_credentials"

    info "Worker Control 配置已生成"
}

# data-plane 是承载实际 Trojan 流量的进程，gateway 把解密后的字节转发给它。
# 约束来自 cmd/trojan-go/main.go:validateDataPlaneConfig
generate_data_plane_config() {
    local db_dsn dp_host dp_port
    db_dsn=$(build_db_dsn)
    dp_host="${DATA_PLANE_ADDR%:*}"
    dp_port="${DATA_PLANE_ADDR##*:}"

    cat > "${CONFIG_DIR}/data-plane.yaml" << EOF
run_type: server
log_level: 1

local_addr: ${dp_host}
local_port: ${dp_port}
remote_addr: 127.0.0.1
remote_port: 0

# gateway 已完成 TLS 卸载，data-plane 收到的是明文 + PROXY 协议头
# remote_port=0 禁用固定重定向，由 freedom 隧道按目标地址直连
transport_plugin:
  enabled: true
  type: plaintext
proxy_protocol: true

auth_db: "${db_dsn}"
auth_refresh: 30
internal_token_path: ${INTERNAL_TOKEN_FILE}
traffic_outbox: ${DATA_DIR}/traffic-outbox.json

router:
  enabled: true
  geoip: ${GEODATA_DIR}/geoip.dat
  geosite: ${GEODATA_DIR}/geosite.dat
  block:
    - geoip:private
EOF

    if [[ "$DEPLOY_MODE" == "master" ]]; then
        # master 本机有 admin-service，直连其内部路由上报流量
        cat >> "${CONFIG_DIR}/data-plane.yaml" << EOF

traffic_report: http://${ADMIN_ADDR}/internal/control/v1/data-plane/traffic
traffic_interval: 30
EOF
    else
        # worker 本机没有 admin-service，traffic_report 指向 8081 会一直失败；
        # 流量经 node 段的 nodesync 回传主节点
        cat >> "${CONFIG_DIR}/data-plane.yaml" << EOF

node:
  enabled: true
  master_url: https://${master}/control/v1/nodes/sync
  secret: "${secret}"
  sync_interval: ${sync_interval}
  traffic_outbox: ${DATA_DIR}/traffic-outbox.json
EOF
    fi

    chmod 600 "${CONFIG_DIR}/data-plane.yaml"

    info "Data-Plane 配置已生成"
}

# hysteria2 由独立的 hysteria 二进制承载（QUIC/UDP），
# 通过 HTTP 回调 control-service 完成用户鉴权
generate_hysteria_config() {
    [[ "$hy2_enabled" != "true" ]] && return 0

    cat > "${CONFIG_DIR}/hysteria.yaml" << EOF
listen: :${hy2_port}

tls:
  cert: ${CERTS_DIR}/fullchain.crt
  key: ${CERTS_DIR}/private.key

auth:
  type: http
  http:
    url: http://${CONTROL_ADDR}/control/v1/hysteria/auth
    insecure: true

masquerade:
  type: proxy
  proxy:
    url: ${hy2_masquerade}
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 60s
  keepAliveInterval: 10s

bandwidth:
  up: ${hy2_up_mbps} mbps
  down: ${hy2_down_mbps} mbps
EOF

    info "Hysteria2 配置已生成"
}

# ==============================================================================
# 10. SSL 证书申请
# ==============================================================================
setup_ssl_certificates() {
    header "配置 SSL 证书 / Setup SSL Certificates"

    local domain
    if [[ "$DEPLOY_MODE" == "master" ]]; then
        domain="$master"
    else
        domain="$worker"
    fi

    local le_dir="/etc/letsencrypt/live/${domain}"

    # 已有 Let's Encrypt 证书：直接同步副本，不重复申请
    if [[ -f "${le_dir}/fullchain.pem" && -f "${le_dir}/privkey.pem" ]]; then
        info "检测到 ${domain} 已有 Let's Encrypt 证书，同步到部署目录"
        sync_certificates "$domain"
        install_cert_renewal_hook "$domain"
        success "SSL 证书配置完成（复用已有证书）"
        return 0
    fi

    # 部署目录已有证书：必须校验来源，禁止自签名
    if [[ -f "${CERTS_DIR}/fullchain.crt" && -f "${CERTS_DIR}/private.key" ]]; then
        if is_self_signed_cert "${CERTS_DIR}/fullchain.crt"; then
            error "部署目录存在自签名证书，已拒绝使用 (错误码: 8)"
            error "自签名证书会导致客户端 TLS 校验失败并暴露流量特征"
            error "请删除 ${CERTS_DIR}/fullchain.crt 与 private.key 后重新部署"
            exit 8
        fi
        info "部署目录已有受信任证书，跳过申请"
        return 0
    fi

    # 安装 certbot
    if ! command -v certbot &>/dev/null; then
        info "安装 certbot..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y -qq certbot
        elif command -v yum &>/dev/null; then
            yum install -y -q certbot
        elif command -v dnf &>/dev/null; then
            dnf install -y -q certbot
        fi
    fi
    if ! command -v certbot &>/dev/null; then
        error "certbot 安装失败，无法申请受信任证书 (错误码: 8)"
        exit 8
    fi

    preflight_acme_domain "$domain"

    # 申请证书。--standalone 需要独占 80 端口，此处已确认 80 空闲
    info "为 ${domain} 申请 Let's Encrypt 证书..."
    if ! certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "$email" \
        -d "$domain" \
        --http-01-port=80; then
        error "证书申请失败 (错误码: 8)"
        error "本脚本不会退回自签名证书，部署已中止"
        error "请依次确认："
        error "  1. ${domain} 的 A/AAAA 记录已解析到本机公网 IP"
        error "  2. 80 端口未被占用且防火墙/安全组已放行"
        error "  3. 未触发 Let's Encrypt 速率限制（同域名每周 5 次）"
        error "  4. email=${email} 为有效邮箱"
        exit 8
    fi

    sync_certificates "$domain"
    install_cert_renewal_hook "$domain"

    success "SSL 证书申请完成"
}

# ACME HTTP-01 前置检查：域名解析与 80 端口占用
preflight_acme_domain() {
    local domain="$1"

    local resolved_ip public_ip
    resolved_ip=$(getent hosts "$domain" 2>/dev/null | awk '{print $1; exit}')
    if [[ -z "$resolved_ip" ]]; then
        error "域名 ${domain} 无法解析 (错误码: 8)"
        error "HTTP-01 验证要求域名已正确解析到本机，部署已中止"
        exit 8
    fi

    public_ip=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || true)
    if [[ -n "$public_ip" && "$resolved_ip" != "$public_ip" ]]; then
        warn "域名 ${domain} 解析到 ${resolved_ip}，本机公网 IP 为 ${public_ip}"
        warn "若使用 CDN/代理请确认已关闭代理，否则 HTTP-01 验证会失败"
    fi

    # certbot --standalone 会自行监听 80，占用则必然失败
    if ss -tlnp 2>/dev/null | grep -qE '[:.]80\s'; then
        error "80 端口已被占用，certbot --standalone 无法完成验证 (错误码: 8)"
        ss -tlnp 2>/dev/null | grep -E '[:.]80\s' | sed 's/^/    /'
        error "请先停止占用 80 端口的服务后重新部署"
        exit 8
    fi
}

# 判定证书是否为自签名（issuer 与 subject 相同）
is_self_signed_cert() {
    local cert="$1"
    local issuer subject

    issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    subject=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject=//')

    [[ -n "$issuer" && "$issuer" == "$subject" ]]
}

# 将 Let's Encrypt 证书同步到部署目录，并校验非自签名
sync_certificates() {
    local domain="$1"
    local le_dir="/etc/letsencrypt/live/${domain}"

    cp -fL "${le_dir}/fullchain.pem" "${CERTS_DIR}/fullchain.crt"
    cp -fL "${le_dir}/privkey.pem" "${CERTS_DIR}/private.key"
    chmod 600 "${CERTS_DIR}/private.key"
    chmod 644 "${CERTS_DIR}/fullchain.crt"

    if is_self_signed_cert "${CERTS_DIR}/fullchain.crt"; then
        error "同步到部署目录的证书为自签名，已中止 (错误码: 8)"
        exit 8
    fi

    local issuer
    issuer=$(openssl x509 -in "${CERTS_DIR}/fullchain.crt" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    info "证书签发者: ${issuer}"
}

# certbot 续期后自动同步副本并重载服务。
# 缺少该 hook 时，certbot.timer 只更新 /etc/letsencrypt，
# 部署目录里的副本会保持旧证书直至过期。
install_cert_renewal_hook() {
    local domain="$1"
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    local hook_file="${hook_dir}/trojan-go-sync-certs.sh"

    mkdir -p "$hook_dir"

    cat > "$hook_file" << EOF
#!/usr/bin/env bash
# 由 install.sh 自动生成：certbot 续期后同步证书到 trojan-go 部署目录
set -euo pipefail

DOMAIN="${domain}"
CERTS_DIR="${CERTS_DIR}"
LE_DIR="/etc/letsencrypt/live/\${DOMAIN}"

# 仅在本次续期涉及目标域名时执行
if [[ -n "\${RENEWED_LINEAGE:-}" && "\${RENEWED_LINEAGE}" != "\${LE_DIR}" ]]; then
    exit 0
fi

cp -fL "\${LE_DIR}/fullchain.pem" "\${CERTS_DIR}/fullchain.crt"
cp -fL "\${LE_DIR}/privkey.pem" "\${CERTS_DIR}/private.key"
chmod 600 "\${CERTS_DIR}/private.key"
chmod 644 "\${CERTS_DIR}/fullchain.crt"

# gateway 与 hysteria 均持有 TLS 证书，需重启以加载新证书
systemctl restart trojan-go-gateway.service 2>/dev/null || true
if systemctl is-enabled trojan-go-hysteria.service &>/dev/null; then
    systemctl restart trojan-go-hysteria.service 2>/dev/null || true
fi
EOF

    chmod +x "$hook_file"
    info "已安装证书续期钩子: ${hook_file}"
}

# ==============================================================================
# 11. GeoData 下载
# ==============================================================================
download_geodata() {
    header "下载 GeoData / Download GeoData"

    local geodata_files=("geoip.dat" "geosite.dat")
    local geodata_urls=(
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    )

    for i in "${!geodata_files[@]}"; do
        local file="${geodata_files[$i]}"
        local url="${geodata_urls[$i]}"

        if [[ -f "${GEODATA_DIR}/${file}" ]]; then
            info "${file} 已存在，跳过下载"
            continue
        fi

        info "下载 ${file}..."
        # data-plane 的 router.block 依赖该文件；缺失时 trojan-go 只打印一行
        # ERROR 后降级继续运行，geoip:private 静默失效，内网地址不再被拦截。
        # 因此这里必须视为硬失败。
        curl -sL --fail -o "${GEODATA_DIR}/${file}" "$url" || {
            rm -f "${GEODATA_DIR}/${file}"
            error "${file} 下载失败: ${url} (错误码: 7)"
            error "data-plane 的 geoip:private 拦截规则依赖该文件，不能缺失"
            exit 7
        }
    done

    success "GeoData 下载完成"
}

# ==============================================================================
# 12. systemd 服务配置
# ==============================================================================
setup_systemd() {
    header "配置 systemd 服务 / Setup systemd"

    # 创建 Gateway 服务
    create_gateway_service

    if [[ "$DEPLOY_MODE" == "master" ]]; then
        # 创建 Admin 服务
        create_admin_service
        # 创建 Control 服务
        create_control_service
    else
        # 创建 Worker Control 服务
        create_control_worker_service
    fi

    # 创建 data-plane 服务（gateway 的转发目标）
    create_data_plane_service

    # 创建 hysteria2 服务（独立进程）
    create_hysteria_service

    # 重载 systemd
    systemctl daemon-reload

    # 启用并启动服务
    enable_and_start_services

    success "systemd 服务配置完成"
}

create_gateway_service() {
    # gateway 是边缘入口，需在后端就绪后启动：admin/control 提供面板与订阅，
    # data-plane 接收解密后的代理流量
    local -a after=("network.target" "trojan-go-control.service" "trojan-go-data-plane.service")
    if [[ "$DEPLOY_MODE" == "master" ]]; then
        after+=("trojan-go-admin.service")
    fi

    cat > /etc/systemd/system/trojan-go-gateway.service << EOF
[Unit]
Description=Trojan-Go Gateway Service
After=${after[*]}
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/trojan-go gateway-service -config ${CONFIG_DIR}/gateway.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
}

create_admin_service() {
    # admin 是唯一写库方，必须最先起；不能反向依赖 gateway，
    # 否则 Wants= 会在 admin 之前把 gateway 拉起，而 gateway 此时无后端可连
    cat > /etc/systemd/system/trojan-go-admin.service << EOF
[Unit]
Description=Trojan-Go Admin Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/trojan-go admin-service -config ${CONFIG_DIR}/admin.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
}

create_control_service() {
    # master 模式只认 -listen / -admin；传 -config 会被静默忽略
    cat > /etc/systemd/system/trojan-go-control.service << EOF
[Unit]
Description=Trojan-Go Control Service
After=network.target trojan-go-admin.service
Wants=trojan-go-admin.service

[Service]
Type=simple
ExecStart=${BIN_DIR}/trojan-go control-service -listen ${CONTROL_ADDR} -admin ${ADMIN_ADDR}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
}

create_data_plane_service() {
    cat > /etc/systemd/system/trojan-go-data-plane.service << EOF
[Unit]
Description=Trojan-Go Data Plane
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/trojan-go -config ${CONFIG_DIR}/data-plane.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
}

create_hysteria_service() {
    [[ "$hy2_enabled" != "true" ]] && return 0

    cat > /etc/systemd/system/trojan-go-hysteria.service << EOF
[Unit]
Description=Trojan-Go Hysteria2 Service
After=network.target trojan-go-control.service
Wants=trojan-go-control.service

[Service]
Type=simple
ExecStart=${HYSTERIA_BIN} server -c ${CONFIG_DIR}/hysteria.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
}

create_control_worker_service() {
    # 同 admin：control 先于 gateway 启动，不能反向依赖 gateway
    cat > /etc/systemd/system/trojan-go-control.service << EOF
[Unit]
Description=Trojan-Go Worker Control Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/trojan-go control-service -worker -config ${CONFIG_DIR}/control-worker.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
}

# 按依赖顺序启动：admin（唯一写库方）→ control → data-plane → gateway → hysteria
enable_and_start_services() {
    local -a units=()

    if [[ "$DEPLOY_MODE" == "master" ]]; then
        units+=("trojan-go-admin")
    fi
    units+=("trojan-go-control" "trojan-go-data-plane" "trojan-go-gateway")
    if [[ "$hy2_enabled" == "true" ]]; then
        units+=("trojan-go-hysteria")
    fi

    local unit
    for unit in "${units[@]}"; do
        info "启动 ${unit}.service"
        systemctl enable "${unit}.service" &>/dev/null
        systemctl restart "${unit}.service"

        # admin 首启需执行 AutoMigrate，固定 sleep 不可靠，改为轮询端口
        if [[ "$unit" == "trojan-go-admin" ]]; then
            wait_for_port "${ADMIN_ADDR##*:}" 30 "admin-service"
        fi
    done

    verify_services_active "${units[@]}"
}

# 轮询等待端口就绪，替代固定 sleep
wait_for_port() {
    local port="$1" timeout="$2" name="$3"
    local waited=0

    while (( waited < timeout )); do
        if ss -tln 2>/dev/null | grep -qE "[:.]${port}\s"; then
            info "${name} 已就绪 (${port})"
            return 0
        fi
        sleep 1
        (( waited++ ))
    done

    warn "${name} 在 ${timeout}s 内未监听 ${port}，继续启动后续服务"
    return 1
}

# 启动后确认服务真实存活。
# activating 状态说明进程在 Restart=on-failure 下反复崩溃，必须视为失败。
verify_services_active() {
    local units=("$@")
    local unit state failed=()

    # 给崩溃型故障留出暴露窗口
    sleep 3

    for unit in "${units[@]}"; do
        state=$(systemctl is-active "${unit}.service" 2>&1 || true)
        if [[ "$state" == "active" ]]; then
            success "${unit}.service: active"
        else
            failed+=("$unit")
            error "${unit}.service: ${state}"
            journalctl -u "${unit}.service" -n 15 --no-pager 2>&1 | sed 's/^/    /'
        fi
    done

    if [[ ${#failed[@]} -gt 0 ]]; then
        error "以下服务未正常启动: ${failed[*]} (错误码: 11)"
        error "上方日志为各服务最后 15 行输出"
        exit 11
    fi
}

# ==============================================================================
# 13. 部署流程
# ==============================================================================
deploy_master() {
    header "开始主节点部署 / Deploy Master Node"

    # 1. 生成 Secret
    generate_secret

    # 2. 部署 MySQL
    if [[ "$mysql_deploy" == "docker" ]]; then
        deploy_mysql_docker
        verify_mysql_deployment
    fi

    # 3. 配置 SSL 证书（须先于 config-check，gateway 校验会加载证书）
    setup_ssl_certificates

    # 4. 生成服务配置
    generate_service_configs

    # 5. 下载 GeoData（data-plane 分流依赖）
    download_geodata

    # 6. 预置内部服务令牌（须先于任何服务启动）
    provision_internal_token

    # 7. 启动前校验配置
    validate_generated_configs

    # 8. 配置并启动 systemd 服务
    setup_systemd

    success "主节点部署完成"
}

deploy_worker() {
    header "开始从节点部署 / Deploy Worker Node"

    # 1. 部署 MySQL（如果需要本地缓存）
    if [[ "$mysql_deploy" == "docker" ]]; then
        deploy_mysql_docker
        verify_mysql_deployment
    fi

    # 2. 配置 SSL 证书（须先于 config-check）
    setup_ssl_certificates

    # 3. 生成服务配置
    generate_service_configs

    # 4. 下载 GeoData
    download_geodata

    # 5. 预置内部服务令牌
    provision_internal_token

    # 6. 启动前校验配置
    validate_generated_configs

    # 7. 配置并启动 systemd 服务
    setup_systemd

    success "从节点部署完成"
}

# ==============================================================================
# 14. --secret 模式
# ==============================================================================
show_secret() {
    header "主节点认证密钥 / Master Node Secret"

    if [[ ! -f "$SECRET_FILE" ]]; then
        error "Secret 文件不存在，请先部署主节点"
        exit 1
    fi

    local saved_secret
    saved_secret=$(cat "$SECRET_FILE")

    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}           主节点认证密钥 / Master Node Secret${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Secret:${NC} ${GREEN}${saved_secret}${NC}"
    echo ""
    echo -e "  请妥善保存此密钥，从节点部署时需要配置此密钥"
    echo -e "  Please save this secret, worker nodes need it to connect"
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ==============================================================================
# 14a2. 配置 TCP 中继节点（Gateway 内置 SNI 路由）
# --relay 模式：Gateway 在 TLS 握手前窥探 ClientHello SNI，
# 匹配 relay_exit_domain 的流量直接 TCP 转发到 relay_exit_ip。
# 无需 HAProxy，无需改端口，Gateway 内部完成所有路由。
# ==============================================================================
setup_relay_node() {
    header "配置 TCP 中继节点 / Setup TCP Relay Node"

    local entry_domain="${relay_entry_domain:-$master}"
    local exit_domain="${relay_exit_domain}"
    local exit_ip="${relay_exit_ip}"
    local node_name="${relay_node_name:-relay}"

    if [[ -z "$exit_domain" || -z "$exit_ip" ]]; then
        error "relay_exit_domain, relay_exit_ip 为必填项 (错误码: 4)"
        exit 4
    fi

    info "中继路由: SNI=${exit_domain} -> ${exit_ip}:443"
    info "入口节点: ${entry_domain}"
    info "订阅节点名: ${node_name}"

    # 1. 确保 gateway.yaml ���含 relay 路由表（deploy_master 已生成，此处幂等检查）
    if ! grep -q "relay:" "${CONFIG_DIR}/gateway.yaml" 2>/dev/null; then
        sed -i "/trojan_service:/a\  relay:\n    ${exit_domain}: ${exit_ip}:443" "${CONFIG_DIR}/gateway.yaml"
    fi
    success "Gateway relay 路由已配置"

    # 2. 重启 gateway 加载 relay 路由表
    info "重启 gateway 加载 relay 路由表..."
    systemctl restart trojan-go-gateway.service 2>/dev/null
    sleep 2
    if systemctl is-active --quiet trojan-go-gateway.service; then
        success "Gateway 已重启，SNI relay 路由生效"
    else
        error "Gateway 重启失败: journalctl -u trojan-go-gateway -n 20"
        exit 11
    fi

    # 3. 插入中继虚拟节点到 MySQL（名称含 "(转)" 触发订阅 relay-only 行为）
    local db_name="${node_name}"
    if ! echo "${node_name}" | grep -q '(转)'; then
        db_name="${node_name}(转)"
    fi

    local mysql_cmd
    if [[ "$mysql_deploy" == "docker" ]]; then
        mysql_cmd="docker exec ${mysql_docker_name} mysql -u root -p${mysql_docker_root_password} ${mysql_dbname}"
    else
        mysql_cmd="mysql -h ${mysql_host} -P ${mysql_port} -u ${mysql_user} -p${mysql_password} ${mysql_dbname}"
    fi

    $mysql_cmd -e "DELETE FROM nodes WHERE name='${db_name}';" 2>/dev/null || true
    $mysql_cmd -e "INSERT INTO nodes (name, address, port, sni, secret, status, ws_enabled, ws_path, traffic_rate, created_at, updated_at) VALUES ('${db_name}', '${entry_domain}', 443, '${exit_domain}', '', 1, false, '/trojan-go', 1.0, NOW(), NOW());" 2>/dev/null &&         success "节点已注册: ${db_name}" ||         warn "节点注册失败，请手动 INSERT INTO nodes"

    echo ""
    echo -e "  ${BOLD}中继架构（Gateway 内置 SNI 路由）:${NC}"
    echo -e "    客户端 ──TLS(:443)──→ Gateway"
    echo -e "      ├─ SNI=${entry_domain}  → 本地 TLS/Trojan"
    echo -e "      └─ SNI=${exit_domain}   → TCP 转发 ${exit_ip}:443"
    echo -e ""
    echo -e "  ${BOLD}订阅节点:${NC} ${db_name}"
    echo -e "  ${BOLD}Address:${NC}   ${entry_domain}"
    echo -e "  ${BOLD}SNI:${NC}       ${exit_domain}"
    echo -e "  ${BOLD}协议:${NC}       TCP/Trojan (无 Hysteria2)"
}


# ==============================================================================
# 14b. 自动创建管理员用户
# ==============================================================================
create_admin_user() {
    info "创建管理员账户..."

    local admin_token="${DEPLOY_DIR}/internal-token"
    local max_wait=30 waited=0

    # 等待 admin API 就绪
    while (( waited < max_wait )); do
        if curl -s -o /dev/null -w '%{http_code}' "http://${ADMIN_ADDR}${ADMIN_PREFIX}api/ping" 2>/dev/null | grep -q '200'; then
            break
        fi
        sleep 1
        (( waited++ ))
    done

    if (( waited >= max_wait )); then
        warn "Admin API 未在 ${max_wait}s 内就绪，跳过高可用账户创建"
        warn "请稍后手动创建: mysql -e \"INSERT INTO users (username, password_hash, quota, expiry_time) VALUES ('${admin_username}', '<bcrypt_hash>', -1, -1)\""
        return 0
    fi

    # 读取内部 Token 用于 API 认证
    local token=""
    if [[ -f "$admin_token" ]]; then
        token=$(head -c 64 "$admin_token" 2>/dev/null || true)
    fi

    if [[ -z "$token" ]]; then
        warn "无法读取内部 Token，跳过自动创建管理员"
        return 0
    fi

    # 同时通过内部 API 设置 web 管理面板凭据（configs 表中的 admin_username/admin_password）
    # handleUpdateAdmin 会自动 bcrypt 哈希密码并保存
    if [[ -n "$admin_username" && -n "$admin_password" ]]; then
        local admin_http_code
        admin_http_code=$(curl -s -w '%{http_code}' -o /dev/null \
            -X PUT "http://127.0.0.1:8081/internal/control/v1/settings/admin" \
            -H "Content-Type: application/json" \
            -H "X-Internal-Token: ${token}" \
            -d "{\"username\":\"${admin_username}\",\"password\":\"${admin_password}\"}" \
            2>/dev/null)
        if [[ "$admin_http_code" == "200" ]]; then
            success "Web 管理面板凭据已保存 (用户名: ${admin_username})"
        else
            warn "Web 管理面板凭据设置返回 HTTP ${admin_http_code}"
        fi
    fi

    # 通过内部 API 创建管理员用户（/internal/control/v1/users 走 X-Internal-Token 认证，用于代理认证）
    local http_code
    http_code=$(curl -s -w '%{http_code}' -o /dev/null \
        -X POST "http://127.0.0.1:8081/internal/control/v1/users" \
        -H "Content-Type: application/json" \
        -H "X-Internal-Token: ${token}" \
        -d "{\"username\":\"${admin_username}\",\"password\":\"${admin_password}\",\"quota\":-1,\"expiry_time\":-1}" \
        2>/dev/null)

    if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
        success "管理员代理账户已创建: ${admin_username}"
    elif [[ "$http_code" == "409" || "$http_code" == "400" ]]; then
        info "管理员代理账户已存在或参数冲突 (HTTP ${http_code})"
    else
        warn "管理员 API 返回 HTTP ${http_code}"
    fi
}

# ==============================================================================
# 14c. SSL 证书手动续期
# ==============================================================================
ssl_renew_certificate() {
    header "SSL 证书续期 / SSL Certificate Renewal"

    local domain="${master}"
    if [[ -z "$domain" ]]; then
        error "无法确定域名，请检查配置文件中 master 字段"
        exit 4
    fi

    local le_dir="/etc/letsencrypt/live/${domain}"
    local cert_path="${CERTS_DIR}/fullchain.crt"
    local key_path="${CERTS_DIR}/private.key"
    local certbot_hook="/etc/letsencrypt/renewal-hooks/deploy/trojan-go-sync-certs.sh"

    info "域名: ${domain}"

    # 证书存在性检查
    if [[ ! -f "${cert_path}" ]]; then
        warn "部署目录中未找到证书文件 (${cert_path})"
        warn "如果首次部署，请在 /mnt/trojan-go/config/ 下手动放置证书"
        warn "或使用 certbot 申请: certbot certonly --standalone -d ${domain}"
    fi

    # 检查是否需要续期
    if [[ "$SSL_FORCE" != "true" ]]; then
        if [[ -f "${cert_path}" ]]; then
            local expiry_ts now_ts remaining_days expiry_str
            expiry_str=$(openssl x509 -in "${cert_path}" -noout -enddate 2>/dev/null | cut -d= -f2)
            if [[ -n "$expiry_str" ]]; then
                expiry_ts=$(date -d "$expiry_str" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_str" +%s 2>/dev/null)
                now_ts=$(date +%s)
                if [[ -n "$expiry_ts" ]]; then
                    remaining_days=$(( (expiry_ts - now_ts) / 86400 ))
                    if (( remaining_days > 30 )); then
                        info "证书还有 ${remaining_days} 天到期 (> 30 天)，无需续期"
                        info "如需强制续期，请使用 --ssl --force"
                        exit 0
                    fi
                    info "证书将在 ${remaining_days} 天后到期，开始续期..."
                fi
            fi
        fi
    else
        info "强制执行证书续期..."
    fi

    # 执行 certbot 续期
    if command -v certbot &>/dev/null; then
        info "使用 certbot 续期..."
        if ! certbot renew --cert-name "$domain" --force-renewal --non-interactive --deploy-hook "${certbot_hook}" 2>&1 | tee -a "$LOG_FILE"; then
            error "certbot 续期失败"
            exit 8
        fi
        success "certbot 续期完成"
    else
        error "未找到 certbot，无法执行续期"
        exit 8
    fi

    # 同步证书到部署目录
    if [[ -f "${le_dir}/fullchain.pem" ]]; then
        install -m 0644 "${le_dir}/fullchain.pem" "${cert_path}"
        install -m 0600 "${le_dir}/privkey.pem" "${key_path}"
        success "证书已同步到 ${cert_path}"
    fi

    # 重启服务加载新证书
    info "重启 Gateway 服务加载新证书..."
    systemctl restart trojan-go-gateway.service 2>/dev/null || true
    if systemctl is-enabled trojan-go-hysteria.service &>/dev/null; then
        systemctl restart trojan-go-hysteria.service 2>/dev/null || true
    fi
    sleep 2

    # 验证
    if systemctl is-active --quiet trojan-go-gateway.service; then
        success "Gateway 服务已正常运行"
    else
        warn "Gateway 服务重启后未 active，请检查: journalctl -u trojan-go-gateway -n 20"
    fi

    local new_expiry
    if [[ -f "${cert_path}" ]]; then
        new_expiry=$(openssl x509 -in "${cert_path}" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
        success "证书续期完成，新证书到期: ${new_expiry}"
    fi
}

# ==============================================================================
# 15. 部署结果输出
# ==============================================================================
print_result() {
    header "部署完成 / Deployment Complete"

    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Trojan-Go 节点部署成功${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}部署模式:${NC} ${DEPLOY_MODE}"
    echo -e "  ${BOLD}主节点域名:${NC} ${master}"
    echo -e "  ${BOLD}从节点域名:${NC} ${worker}"
    echo -e "  ${BOLD}部署目录:${NC} ${DEPLOY_DIR}"
    echo -e "  ${BOLD}配置文件:${NC} ${CONFIG_DIR}/config.conf"
    echo ""

    # 证书来源，便于确认非自签名
    if [[ -f "${CERTS_DIR}/fullchain.crt" ]]; then
        local cert_issuer cert_expiry
        cert_issuer=$(openssl x509 -in "${CERTS_DIR}/fullchain.crt" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
        cert_expiry=$(openssl x509 -in "${CERTS_DIR}/fullchain.crt" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
        echo -e "  ${BOLD}证书签发者:${NC} ${cert_issuer}"
        echo -e "  ${BOLD}证书到期:${NC} ${cert_expiry}"
        echo -e "  ${BOLD}自动续期:${NC} certbot.timer + deploy-hook 自动同步"
        echo ""
    fi

    echo -e "  ${BOLD}Gateway 服务:${NC}    systemctl status trojan-go-gateway"
    if [[ "$DEPLOY_MODE" == "master" ]]; then
        echo -e "  ${BOLD}Admin 服务:${NC}      systemctl status trojan-go-admin"
    fi
    echo -e "  ${BOLD}Control 服务:${NC}    systemctl status trojan-go-control"
    echo -e "  ${BOLD}Data-Plane 服务:${NC} systemctl status trojan-go-data-plane"
    if [[ "$hy2_enabled" == "true" ]]; then
        echo -e "  ${BOLD}Hysteria2 服务:${NC}  systemctl status trojan-go-hysteria"
    fi

    if [[ "$DEPLOY_MODE" == "master" ]]; then
        echo ""
        echo -e "  ${BOLD}节点 Secret:${NC}"
        echo ""
        show_secret
        echo ""
        echo -e "  ${BOLD}══════════════════════════════════════════════════════════${NC}"
        echo -e "  ${BOLD}  🔑 管理员凭据 / Admin Credentials${NC}"
        echo -e "  ${BOLD}══════════════════════════════════════════════════════════${NC}"
        echo ""
        if [[ -f "${CONFIG_DIR}/.admin_credentials" ]]; then
            source "${CONFIG_DIR}/.admin_credentials" 2>/dev/null || true
        fi
        echo -e "  ${BOLD}面板地址:${NC}   https://${master}${ADMIN_PREFIX}"
        echo -e "  ${BOLD}用户名:${NC}     ${GREEN:-}${admin_username}${NC}"
        echo -e "  ${BOLD}密码:${NC}       ${GREEN:-}${admin_password}${NC}"
        echo ""
        echo -e "  凭据已保存至: ${CONFIG_DIR}/.admin_credentials"
        echo ""
        echo -e "${CYAN}  ⚠️  首次登录后请立即修改密码${NC}"
        echo ""
    fi

    echo ""
    echo -e "  ${BOLD}查看日志:${NC} journalctl -u trojan-go-gateway -f"
    echo -e "  ${BOLD}CLI 管理:${NC} ${BIN_DIR}/trojan"
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ==============================================================================
# 主入口
# ==============================================================================
main() {
    # 1. 参数解析
    parse_args "$@"

    # 2. 加载配置
    load_config

    # 3. 环境预检
    preflight_check

    # 4. 配置校验
    validate_config

    # 5. 如果是 --secret 模式，仅显示 Secret
    if [[ "$DEPLOY_MODE" == "secret" ]]; then
        show_secret
        exit 0
    fi

    # 5b. 如果是 --ssl 模式，执行证书续期
    if [[ "$DEPLOY_MODE" == "ssl" ]]; then
        ssl_renew_certificate
        exit 0
    fi

    # 5c. 如果是 --relay 模式，仅配置中继节点
    if [[ "$DEPLOY_MODE" == "relay" ]]; then
        header "中继节点配置 / Relay Node Setup"
        setup_relay_node
        exit 0
    fi

    # 6. 清理已有服务与残留进程（避免端口占用、二进制文件被占用）
    cleanup_existing_services

    # 7. 部署二进制文件
    detect_or_build_binaries

    # 8. 创建部署目录
    create_deploy_directory

    # 9. 根据模式执行部署
    if [[ "$DEPLOY_MODE" == "master" ]]; then
        deploy_master
    else
        deploy_worker
    fi

    # 9b. 自动创建管理员用户 (master 模式)
    if [[ "$DEPLOY_MODE" == "master" ]]; then
        create_admin_user
    fi

    # 10. 输出结果
    print_result
}

# 执行主函数
main "$@"
