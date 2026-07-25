#!/bin/bash
#
# Trojan-Go AI Agent 自动化部署脚本（零交互，源码编译版）
# 用途：供 AI Agent / CI-CD 无人值守部署，所有参数通过命令行传入
# 用法：sudo bash install-ai.sh [OPTIONS]
# 支持系统：Ubuntu 18.04+, Debian 9+, CentOS 7.9+, RHEL 7.9+
#

set -euo pipefail

# ==============================================================================
# 全局配置
# ==============================================================================
readonly REPO_URL="https://github.com/voidluo/trojan-go.git"
readonly REPO_OWNER="voidluo"
readonly REPO_NAME="trojan-go"

# 默认值 / Default values
MODE=""
BRANCH="Hysteria2"
HOST="0.0.0.0"
PORT=443
PASSWORD=""
MASTER=""
IS_MASTER="false"
WS_ENABLED=false
WS_PATH="/trojan-go"
HY2_ENABLED=false
HY2_PORT=8443
CERT_PATH=""
KEY_PATH=""
INSTALL_DIR=""
CONFIG_ONLY=false
NO_START=false
DRY_RUN=false
VERBOSE=false
UNINSTALL=false

SRC_DIR="/tmp/trojan-go-src-$$"

# ==============================================================================
# 颜色定义
# ==============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# ==============================================================================
# 日志函数 (双语) / Logging functions (bilingual)
# ==============================================================================
log_info()  { printf "${GREEN}[INFO]${NC} %s\n" "$*"; }
log_warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
log_debug() { [[ "$VERBOSE" == true ]] && printf "${BLUE}[DEBUG]${NC} %s\n" "$*" || true; }

# ==============================================================================
# 帮助信息
# ==============================================================================
usage() {
    cat << 'EOF'

================================================================================
        Trojan-Go AI Agent 自动化部署脚本 / Automated Deployment Script
================================================================================

用法 / Usage:
  sudo bash install-ai.sh [OPTIONS]

必要参数 / Required:
  -m, --mode <native|docker>     部署模式 / Deployment mode
                                    - native: 原生二进制部署（systemd管理）/ native binary (systemd)
                                    - docker: Docker容器部署 / Docker container deployment

  -P, --password <password>      Trojan代理连接密码 / Trojan proxy password

可选参数 / Optional:
  -b, --branch <branch>          Git代码分支 (默认: Hysteria2) / Git branch
                                  指定要从GitHub拉取并编译的代码分支 / branch to clone and compile

  -H, --host <host>              监听地址 (默认: 0.0.0.0) / Listening address

  -p, --port <port>              Trojan TCP端口 (默认: 443) / Trojan TCP port
                                  范围 / Range: 1-65535

      --master <domain>          主节点域名 / Master domain (用于TLS证书和SNI / for TLS & SNI)
                                  例如 / e.g.: jp.liteops.top
                                  携带此参数时节点将作为主节点部署 / Node will be deployed as master

      --ws                       启用WebSocket传输 / Enable WebSocket transport
                                  允许将Trojan流量伪装在WebSocket中 / Disguise Trojan traffic in WebSocket

      --ws-path <path>           WebSocket路径 (默认: /trojan-go) / WebSocket path

      --hy2                      启用Hysteria2 (UDP) / Enable Hysteria2 (UDP)
                                  提供QUIC加速代理 / QUIC acceleration proxy

      --hy2-port <port>          Hysteria2 UDP端口 (默认: 8443) / Hysteria2 UDP port

  -c, --cert <path>              TLS证书文件路径 / TLS certificate path
                                  如果不指定，将使用Let's Encrypt申请 / Let's Encrypt if not specified

  -k, --key <path>               TLS私钥文件路径 / TLS private key path
                                  如果不指定，将使用Let's Encrypt申请 / Let's Encrypt if not specified

      --install-dir <path>       安装目录 / Installation directory
                                   - native模式默认 / default: /usr/local/bin
                                   - docker模式默认 / default: /opt/trojan-go

      --config-only              仅生成配置文件，不启动服务 / Generate config only, don't start
                                  用于调试配置或手动启动 / For debugging or manual start

      --no-start                 安装完成后不启动服务 / Don't start after install
                                  适用于需要先检查配置的场景 / For config verification first

      --dry-run                  仅打印将要执行的操作，不实际执行 / Print operations only, don't execute
                                  用于验证参数和流程 / For parameter and flow validation

  -v, --verbose                  显示详细输出 / Verbose output
                                  包括编译日志、下载进度等 / Include build logs, download progress

      --uninstall                卸载服务 / Uninstall service
                                  停止服务、删除二进制文件 / Stop service, remove binaries

  -h, --help                     显示此帮助信息 / Show this help

================================================================================
                          使用示例 / Usage Examples
================================================================================

1. 基本原生部署 (推荐) / Basic native deployment (recommended):
   sudo bash install-ai.sh --mode native --password mypassword --master example.com

2. Docker部署 / Docker deployment:
   sudo bash install-ai.sh --mode docker --password mypassword --master example.com

3. 使用指定分支部署 / Deploy with specific branch:
   sudo bash install-ai.sh --mode native --password mypass --branch develop

4. 启用WebSocket + Hysteria2 / Enable WebSocket + Hysteria2:
   sudo bash install-ai.sh --mode native --password mypass --master example.com --ws --hy2

5. 指定端口和安装目录 / Specify port and install dir:
   sudo bash install-ai.sh --mode native --password mypass --port 8443 --install-dir /opt/trojan-go

6. 仅生成配置（调试用）/ Config only (debugging):
   sudo bash install-ai.sh --mode native --password mypass --config-only --verbose

7. Dry run（验证参数）/ Dry run (validate parameters):
   sudo bash install-ai.sh --mode native --password mypass --dry-run

8. 卸载 / Uninstall:
   sudo bash install-ai.sh --uninstall

9. 显示帮助 / Show help:
   bash install-ai.sh --help

================================================================================

EOF
}

# ==============================================================================
# 系统检测 / System Detection
# ==============================================================================
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_NAME="${NAME:-unknown}"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="centos"
        OS_VERSION=$(grep -oP '\d+\.\d+' /etc/redhat-release | head -1)
        OS_NAME=$(cat /etc/redhat-release)
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
        OS_NAME="unknown"
    fi
    log_debug "系统 / System: ${OS_NAME} (${OS_ID} ${OS_VERSION})"
}

# 检查是否为支持的系统 / Check if OS is supported
is_supported_os() {
    case "$OS_ID" in
        ubuntu)
            local major minor
            major=$(echo "$OS_VERSION" | cut -d. -f1)
            minor=$(echo "$OS_VERSION" | cut -d. -f2)
            if ((major >= 18)) && ((minor >= 4)); then
                return 0
            fi
            ;;
        debian)
            local major
            major=$(echo "$OS_VERSION" | cut -d. -f1)
            if ((major >= 9)); then
                return 0
            fi
            ;;
        centos)
            local major minor
            major=$(echo "$OS_VERSION" | cut -d. -f1)
            minor=$(echo "$OS_VERSION" | cut -d. -f2)
            if ((major >= 7)) && ((minor >= 9)); then
                return 0
            fi
            ;;
        rhel|rocky|almalinux)
            local major minor
            major=$(echo "$OS_VERSION" | cut -d. -f1)
            minor=$(echo "$OS_VERSION" | cut -d. -f2)
            if ((major >= 7)) && ((minor >= 9)); then
                return 0
            fi
            ;;
        *)
            return 1
            ;;
    esac
    return 1
}

# 获取包管理器命令 / Get package manager install command
get_pkg_install_cmd() {
    case "$OS_ID" in
        ubuntu|debian)
            echo "apt-get install -y"
            ;;
        centos|rhel|rocky|almalinux)
            echo "yum install -y"
            ;;
        *)
            echo ""
            ;;
    esac
}

# 获取包管理器更新命令 / Get package manager update command
get_pkg_update_cmd() {
    case "$OS_ID" in
        ubuntu|debian)
            echo "apt-get update"
            ;;
        centos|rhel|rocky|almalinux)
            echo "yum update -y"
            ;;
        *)
            echo ""
            ;;
    esac
}

# 检查并安装依赖 / Check and install dependencies
install_dependencies() {
    local missing_deps=()
    
    for cmd in curl wget git make go jq; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [[ ${#missing_deps[@]} -eq 0 ]]; then
        return 0
    fi

    log_info "缺少依赖 / Missing dependencies: ${missing_deps[*]}"
    
    local pkg_install
    pkg_install=$(get_pkg_install_cmd)
    
    if [[ -z "$pkg_install" ]]; then
        log_error "不支持的系统，请手动安装 / Unsupported system, install manually: ${missing_deps[*]}"
        exit 1
    fi

    log_info "正在安装依赖... / Installing dependencies..."
    
    case "$OS_ID" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq "${missing_deps[@]}" golang-go || {
                # golang-go 包名可能不同 / golang-go package name may differ
                if [[ " ${missing_deps[*]} " =~ " go " ]]; then
                    apt-get install -y -qq golang
                fi
            }
            ;;
        centos|rhel|rocky|almalinux)
            yum install -y -q epel-release
            yum install -y -q "${missing_deps[@]}" golang || {
                if [[ " ${missing_deps[*]} " =~ " go " ]]; then
                    # CentOS 可能需要启用 extras repo / CentOS may need extras repo
                    yum install -y -q centos-release-scl
                    yum install -y -q rh-python38
                fi
            }
            ;;
    esac
    
    log_info "依赖安装完成 / Dependencies installed"
}

# ==============================================================================
# 1. 参数解析 / Argument Parsing
# ==============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--mode)
                MODE="$2"
                shift 2
                ;;
            -b|--branch)
                BRANCH="$2"
                shift 2
                ;;
            -H|--host)
                HOST="$2"
                shift 2
                ;;
            -p|--port)
                PORT="$2"
                shift 2
                ;;
            -P|--password)
                PASSWORD="$2"
                shift 2
                ;;
            --master)
                MASTER="$2"
                IS_MASTER="true"
                shift 2
                ;;
            --ws)
                WS_ENABLED=true
                shift
                ;;
            --ws-path)
                WS_PATH="$2"
                shift 2
                ;;
            --hy2)
                HY2_ENABLED=true
                shift
                ;;
            --hy2-port)
                HY2_PORT="$2"
                shift 2
                ;;
            -c|--cert)
                CERT_PATH="$2"
                shift 2
                ;;
            -k|--key)
                KEY_PATH="$2"
                shift 2
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --config-only)
                CONFIG_ONLY=true
                shift
                ;;
            --no-start)
                NO_START=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "未知参数 / Unknown argument: $1"
                echo ""
                echo "使用 --help 查看所有可用参数 / Use --help to see all available arguments"
                exit 1
                ;;
        esac
    done
}

# ==============================================================================
# 2. 参数校验 / Argument Validation
# ==============================================================================
validate_args() {
    # 帮助模式已处理 / Help mode already handled
    # 卸载模式跳过校验 / Skip validation for uninstall
    [[ "$UNINSTALL" == true ]] && return

    local errors=()

    # 必填参数 / Required parameters
    if [[ -z "$MODE" ]]; then
        errors+=("缺少必填参数 / Missing required: --mode")
    fi

    if [[ -z "$PASSWORD" ]]; then
        errors+=("缺少必填参数 / Missing required: --password")
    fi

    # 模式校验 / Mode validation
    if [[ -n "$MODE" && "$MODE" != "native" && "$MODE" != "docker" ]]; then
        errors+=("无效的模式 / Invalid mode: $MODE (可选 / options: native, docker)")
    fi

    # 端口校验 / Port validation
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
        errors+=("无效端口 / Invalid port: $PORT (范围 / range: 1-65535)")
    fi

    # Hysteria2 端口校验 / Hysteria2 port validation
    if ! [[ "$HY2_PORT" =~ ^[0-9]+$ ]] || ((HY2_PORT < 1 || HY2_PORT > 65535)); then
        errors+=("无效 Hysteria2 端口 / Invalid Hysteria2 port: $HY2_PORT (范围 / range: 1-65535)")
    fi

    # 证书校验 / Certificate validation
    if [[ -n "$CERT_PATH" && ! -f "$CERT_PATH" ]]; then
        errors+=("证书文件不存在 / Certificate file not found: $CERT_PATH")
    fi

    if [[ -n "$KEY_PATH" && ! -f "$KEY_PATH" ]]; then
        errors+=("私钥文件不存在 / Private key file not found: $KEY_PATH")
    fi

    # 端口冲突检查 / Port conflict check
    if [[ "$PORT" == "$HY2_PORT" ]]; then
        errors+=("Trojan 端口与 Hysteria2 端口不能相同 / Trojan and Hysteria2 ports cannot be the same")
    fi

    # 输出错误并退出 / Output errors and exit
    if [[ ${#errors[@]} -gt 0 ]]; then
        echo ""
        log_error "参数校验失败 / Parameter validation failed:"
        for err in "${errors[@]}"; do
            echo "  - $err"
        done
        echo ""
        echo "使用 --help 查看所有可用参数 / Use --help to see all available arguments"
        exit 1
    fi

    log_debug "参数校验通过 / Parameter validation passed"
}

# ==============================================================================
# 3. Dry Run
# ==============================================================================
dry_run() {
    # 检测系统信息用于输出 / Detect system info for output
    detect_os 2>/dev/null || true

    cat << EOF
{
    "dry_run": true,
    "mode": "${MODE}",
    "branch": "${BRANCH}",
    "host": "${HOST}",
    "port": ${PORT},
    "master": "${MASTER}",
    "is_master": ${IS_MASTER},
    "ws": ${WS_ENABLED},
    "hy2": ${HY2_ENABLED},
    "os": "${OS_ID:-unknown} ${OS_VERSION:-unknown}"
}
EOF
    exit 0
}

# ==============================================================================
# 4. 环境预检 / Preflight Check
# ==============================================================================
preflight_check() {
    log_debug "执行环境预检... / Running preflight check..."

    # OS 检测 / OS Detection
    detect_os

    if ! is_supported_os; then
        log_error "不支持的系统 / Unsupported system: ${OS_NAME}"
        log_info "支持的系统 / Supported: Ubuntu 18.04+, Debian 9+, CentOS 7.9+, RHEL 7.9+, Rocky Linux 8+, AlmaLinux 8+"
        exit 1
    fi
    log_info "操作系统 / Operating System: ${OS_NAME}"

    # 架构检测 / Architecture Detection
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        *)
            log_error "不支持的架构 / Unsupported architecture: $ARCH (仅支持 / only: x86_64/aarch64)"
            exit 1
            ;;
    esac
    log_debug "架构 / Architecture: $ARCH"

    # 权限检测 / Permission Check
    if [[ $EUID -ne 0 ]]; then
        log_error "需要 root 权限，请使用 sudo 运行 / Root permission required, run with sudo"
        exit 1
    fi

    # 编译依赖检查 / Build dependency check
    install_dependencies

    # Go 版本检查 >= 1.20 / Go version check >= 1.20
    local go_version
    go_version=$(go version | grep -oP '\d+\.\d+' | head -1)
    local major minor
    major=$(echo "$go_version" | cut -d. -f1)
    minor=$(echo "$go_version" | cut -d. -f2)

    if ((major < 1 || (major == 1 && minor < 20))); then
        log_error "Go 版本过低 / Go version too low: ${go_version}，需要 / required >= 1.20"
        exit 1
    fi
    log_debug "Go 版本 / Go version: ${go_version}"

    # Docker 模式额外检查 / Docker mode extra check
    if [[ "$MODE" == "docker" ]]; then
        if ! command -v docker &>/dev/null; then
            log_error "docker 模式需要 Docker / Docker mode requires Docker"
            exit 1
        fi
    fi

    # Native 模式额外检查 / Native mode extra check
    if [[ "$MODE" == "native" ]]; then
        if ! command -v systemctl &>/dev/null; then
            log_error "native 模式需要 systemd / Native mode requires systemd"
            exit 1
        fi
    fi

    # 主节点信息输出 / Master node info output
    if [[ "$IS_MASTER" == "true" ]]; then
        log_info "主节点域名 / Master domain: ${MASTER}"
        log_info "此节点将作为主节点部署 / This node will be deployed as master"
    fi

    log_debug "环境预检通过 / Preflight check passed"
}

# ==============================================================================
# 5. 源码获取 & 编译 / Source Code Fetch & Build
# ==============================================================================
clone_and_build() {
    log_info "克隆仓库 / Cloning repository: ${REPO_URL} (分支 / branch: ${BRANCH})"

    # 清理旧目录 / Clean old directory
    rm -rf "$SRC_DIR"
    mkdir -p "$SRC_DIR"

    # 克隆指定分支 / Clone specified branch
    local clone_output
    if [[ "$VERBOSE" == true ]]; then
        git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
        clone_output=""
    else
        clone_output=$(git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$SRC_DIR" 2>&1)
    fi

    if [[ $? -ne 0 ]]; then
        log_error "克隆失败 / Clone failed"
        echo "$clone_output" >&2
        rm -rf "$SRC_DIR"
        exit 1
    fi

    cd "$SRC_DIR"

    # 获取实际 commit / Get actual commit
    COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    log_info "代码版本 / Code version: ${BRANCH}@${COMMIT}"

    # 编译 / Build
    log_info "开始编译... / Starting build..."
    local build_output
    if [[ "$VERBOSE" == true ]]; then
        make trojan-go trojan
        build_output=""
    else
        build_output=$(make trojan-go trojan 2>&1)
    fi

    if [[ $? -ne 0 ]]; then
        log_error "编译失败 / Build failed"
        echo "$build_output" >&2
        rm -rf "$SRC_DIR"
        exit 1
    fi

    # 检查编译产物 / Check build artifacts
    local build_dir="build/linux-${ARCH}"
    if [[ ! -f "${build_dir}/trojan-go" ]]; then
        log_error "编译失败 / Build failed: 未找到 trojan-go 二进制 / trojan-go binary not found"
        rm -rf "$SRC_DIR"
        exit 1
    fi

    log_info "编译完成 / Build completed"
}

# ==============================================================================
# 6. 生成配置 / Generate Configuration
# ==============================================================================
generate_config() {
    local config_path=$1

    local cert="${CERT_PATH:-/etc/trojan-go/certs/fullchain.crt}"
    local key="${KEY_PATH:-/etc/trojan-go/certs/private.key}"

    # Docker 模式使用容器内路径 / Use container path for Docker mode
    if [[ "$MODE" == "docker" ]]; then
        cert="/etc/trojan-go/certs/fullchain.crt"
        key="/etc/trojan-go/certs/private.key"
    fi

    # 转义 JSON 特殊字符 / Escape JSON special characters
    local escaped_password escaped_master escaped_ws_path
    escaped_password=$(echo "$PASSWORD" | sed 's/\\/\\\\/g; s/"/\\"/g')
    escaped_master=$(echo "$MASTER" | sed 's/\\/\\\\/g; s/"/\\"/g')
    escaped_ws_path=$(echo "$WS_PATH" | sed 's/\\/\\\\/g; s/"/\\"/g')

    cat > "$config_path" << EOF
{
    "run_type": "server",
    "local_addr": "${HOST}",
    "local_port": ${PORT},
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": ["${escaped_password}"],
    "ssl": {
        "cert": "${cert}",
        "key": "${key}",
        "sni": "${escaped_master}"
    },
    "websocket": {
        "enabled": ${WS_ENABLED},
        "path": "${escaped_ws_path}",
        "hostname": "${escaped_master}"
    },
    "router": {
        "enabled": true,
        "block": ["geoip:private"],
        "geoip": "/usr/share/trojan-go/geoip.dat",
        "geosite": "/usr/share/trojan-go/geosite.dat"
    },
    "hysteria2": {
        "enabled": ${HY2_ENABLED},
        "port": ${HY2_PORT},
        "up_mbps": 100,
        "down_mbps": 500,
        "masquerade_url": "https://www.bilibili.com",
        "auth_api": "http://127.0.0.1:8080/admin/api/hysteria/auth"
    }
}
EOF

    log_debug "配置已生成 / Config generated: $config_path"
}

# ==============================================================================
# 7. Native 部署 / Native Deployment
# ==============================================================================
deploy_native() {
    log_info "开始 Native 部署... / Starting Native deployment..."

    local install_dir="${INSTALL_DIR:-/usr/local/bin}"
    local config_dir="/etc/trojan-go"
    local geodata_dir="/usr/share/trojan-go"

    # 1. 编译 / Build
    clone_and_build

    local build_dir="${SRC_DIR}/build/linux-${ARCH}"

    # 2. 备份旧版本 / Backup old version
    if [[ -f "${install_dir}/trojan-go" ]]; then
        cp "${install_dir}/trojan-go" "${install_dir}/trojan-go.bak.$(date +%s)" 2>/dev/null || true
    fi

    # 3. 安装二进制 / Install binaries
    log_info "安装二进制到 / Installing binaries to ${install_dir}..."
    cp "${build_dir}/trojan-go" "${install_dir}/trojan-go"
    chmod +x "${install_dir}/trojan-go"

    if [[ -f "${build_dir}/trojan" ]]; then
        cp "${build_dir}/trojan" "${install_dir}/trojan"
        chmod +x "${install_dir}/trojan"
    fi

    # 4. 安装 geodata / Install geodata
    mkdir -p "$geodata_dir"
    for f in geoip.dat geosite.dat geoip-only-cn-private.dat; do
        if [[ -f "${SRC_DIR}/${f}" ]]; then
            cp "${SRC_DIR}/${f}" "$geodata_dir/"
        fi
    done

    # 5. 配置 / Config
    mkdir -p "$config_dir"
    generate_config "${config_dir}/config.json"

    # 6. 证书 / Certificates
    if [[ -n "$CERT_PATH" && -n "$KEY_PATH" ]]; then
        mkdir -p "${config_dir}/certs"
        cp "$CERT_PATH" "${config_dir}/certs/fullchain.crt"
        cp "$KEY_PATH" "${config_dir}/certs/private.key"
    fi

    # 7. systemd
    if [[ "$CONFIG_ONLY" == false ]]; then
        setup_systemd "$install_dir" "$config_dir"
    fi

    # 8. 启动 / Start
    if [[ "$CONFIG_ONLY" == false && "$NO_START" == false ]]; then
        systemctl daemon-reload
        systemctl enable trojan-go
        systemctl start trojan-go
        sleep 2
    fi

    # 9. 清理源码 / Clean source
    rm -rf "$SRC_DIR"

    # 10. 输出结果 / Output result
    output_result "native" "$COMMIT" "$config_dir"
}

setup_systemd() {
    local bin_dir=$1
    local cfg_dir=$2

    cat > /etc/systemd/system/trojan-go.service << EOF
[Unit]
Description=Trojan-Go Service
Documentation=https://github.com/${REPO_OWNER}/${REPO_NAME}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${bin_dir}/trojan-go -config ${cfg_dir}/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
}

# ==============================================================================
# 8. Docker 部署 / Docker Deployment
# ==============================================================================
deploy_docker() {
    log_info "开始 Docker 部署... / Starting Docker deployment..."

    local project_dir="${INSTALL_DIR:-/opt/trojan-go}"

    # 1. 编译 / Build
    clone_and_build

    local build_dir="${SRC_DIR}/build/linux-${ARCH}"

    # 2. 初始化目录 / Init directories
    mkdir -p "${project_dir}"/{certs,data,geodata}

    # 3. 复制二进制到项目目录 / Copy binaries to project dir
    cp "${build_dir}/trojan-go" "${project_dir}/trojan-go"
    if [[ -f "${build_dir}/trojan" ]]; then
        cp "${build_dir}/trojan" "${project_dir}/trojan"
    fi
    chmod +x "${project_dir}/trojan-go" "${project_dir}/trojan" 2>/dev/null || true

    # 4. 复制 geodata / Copy geodata
    for f in geoip.dat geosite.dat geoip-only-cn-private.dat; do
        if [[ -f "${SRC_DIR}/${f}" ]]; then
            cp "${SRC_DIR}/${f}" "${project_dir}/geodata/"
        fi
    done

    # 5. 生成 Dockerfile / Generate Dockerfile
    cat > "${project_dir}/Dockerfile" << 'DOCKERFILE'
FROM alpine:3.19
RUN apk add --no-cache tzdata ca-certificates wget

WORKDIR /

COPY trojan-go /usr/local/bin/trojan-go
COPY trojan /usr/local/bin/trojan
RUN chmod +x /usr/local/bin/trojan-go /usr/local/bin/trojan

COPY geodata /usr/share/trojan-go

RUN mkdir -p /etc/trojan-go/certs

ENTRYPOINT ["/usr/local/bin/trojan-go", "-config"]
CMD ["/etc/trojan-go/config.json"]
DOCKERFILE

    # 6. 生成 docker-compose.yml / Generate docker-compose.yml
    cat > "${project_dir}/docker-compose.yml" << EOF
version: '3.8'

services:
  trojan-go:
    build:
      context: .
      dockerfile: Dockerfile
    image: trojan-go:local-${COMMIT}
    container_name: trojan-go
    restart: unless-stopped
    ports:
      - "${PORT}:${PORT}"
      - "${HY2_PORT}:${HY2_PORT}/udp"
    volumes:
      - ./config.json:/etc/trojan-go/config.json:ro
      - ./certs:/etc/trojan-go/certs:ro
      - trojan-go-data:/data
    environment:
      - TZ=Asia/Shanghai

volumes:
  trojan-go-data:
EOF

    # 7. 配置 / Config
    generate_config "${project_dir}/config.json"

    # 8. 证书 / Certificates
    if [[ -n "$CERT_PATH" && -n "$KEY_PATH" ]]; then
        cp "$CERT_PATH" "${project_dir}/certs/fullchain.crt"
        cp "$KEY_PATH" "${project_dir}/certs/private.key"
    fi

    # 9. 构建 & 启动 / Build & Start
    if [[ "$CONFIG_ONLY" == false && "$NO_START" == false ]]; then
        cd "$project_dir"
        log_info "构建 Docker 镜像... / Building Docker image..."
        docker compose build

        log_info "启动容器... / Starting containers..."
        docker compose up -d
        sleep 3
    fi

    # 10. 清理源码 / Clean source
    rm -rf "$SRC_DIR"

    # 11. 输出结果 / Output result
    output_result "docker" "$COMMIT" "$project_dir"
}

# ==============================================================================
# 9. 结果输出（JSON 格式，供 Agent 解析）/ Result Output (JSON for Agent)
# ==============================================================================
output_result() {
    local mode=$1
    local version=$2
    local config_path=$3

    local status="unknown"

    if [[ "$CONFIG_ONLY" == true ]]; then
        status="config_only"
    elif [[ "$NO_START" == true ]]; then
        status="installed"
    elif [[ "$mode" == "native" ]]; then
        if systemctl is-active --quiet trojan-go 2>/dev/null; then
            status="running"
        else
            status="failed"
        fi
    elif [[ "$mode" == "docker" ]]; then
        if docker ps 2>/dev/null | grep -q trojan-go; then
            status="running"
        else
            status="failed"
        fi
    fi

    # JSON 输出 / JSON output
    cat << EOF
{
    "success": true,
    "mode": "${mode}",
    "branch": "${BRANCH}",
    "version": "${version}",
    "status": "${status}",
    "config": "${config_path}/config.json",
    "port": ${PORT},
    "master": "${MASTER}",
    "is_master": ${IS_MASTER},
    "ws": ${WS_ENABLED},
    "hy2": ${HY2_ENABLED},
    "password": "${PASSWORD}",
    "os": "${OS_ID} ${OS_VERSION}"
}
EOF
}

# ==============================================================================
# 10. 卸载 / Uninstall
# ==============================================================================
do_uninstall() {
    log_info "开始卸载... / Starting uninstall..."

    # Native 模式清理 / Native mode cleanup
    if systemctl list-unit-files 2>/dev/null | grep -q trojan-go; then
        log_info "停止并禁用服务... / Stopping and disabling service..."
        systemctl stop trojan-go 2>/dev/null || true
        systemctl disable trojan-go 2>/dev/null || true
        rm -f /etc/systemd/system/trojan-go.service
        systemctl daemon-reload
    fi

    if [[ -f /usr/local/bin/trojan-go ]]; then
        rm -f /usr/local/bin/trojan-go /usr/local/bin/trojan
        log_info "二进制已删除 / Binaries removed"
    fi

    # Docker 模式清理 / Docker mode cleanup
    if [[ -d /opt/trojan-go ]]; then
        cd /opt/trojan-go
        log_info "停止并删除容器... / Stopping and removing containers..."
        docker compose down -v 2>/dev/null || docker-compose down -v 2>/dev/null || true
    fi

    log_info "卸载完成 / Uninstall complete"
    echo '{"success": true, "action": "uninstall"}'
}

# ==============================================================================
# 主流程 / Main Process
# ==============================================================================
main() {
    parse_args "$@"
    validate_args

    [[ "$DRY_RUN" == true ]] && dry_run
    [[ "$UNINSTALL" == true ]] && do_uninstall && exit 0

    preflight_check

    case $MODE in
        native)
            deploy_native
            ;;
        docker)
            deploy_docker
            ;;
    esac
}

main "$@"
