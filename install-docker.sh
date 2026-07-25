#!/bin/bash
#
# Trojan-Go Docker-Compose 部署脚本（交互式）
# 用途：通过 Docker-Compose 部署 Trojan-Go 服务
# 用法：sudo bash install-docker.sh [--uninstall]
#

set -euo pipefail

# ==============================================================================
# 全局配置
# ==============================================================================
readonly REPO_OWNER="voidluo"
readonly REPO_NAME="trojan-go"
readonly REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}"
readonly REMOTE_IMAGE="ghcr.io/${REPO_OWNER}/${REPO_NAME}:latest"

readonly DEFAULT_DIR="/opt/trojan-go"
readonly LOG_FILE="/var/log/trojan-go-install.log"

# ==============================================================================
# 全局变量
# ==============================================================================
MASTER=""
IS_MASTER="false"

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
# 日志函数 (双语)
# ==============================================================================
_log() {
    local level=$1
    shift
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] $*" >> "$LOG_FILE"
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

# 双语提示函数
prompt_bilingual() {
    echo -e "${BLUE}$1${NC}"
}

show_config_item() {
    echo -e "  ${BOLD}$1:${NC} $2"
}

# ==============================================================================
# 1. 环境预检 / Preflight Check
# ==============================================================================
preflight_check() {
    header "Trojan-Go Docker-Compose 部署脚本 / Deployment Script"

    # OS 检测 / OS Detection
    if [[ "$(uname -s)" != "Linux" ]]; then
        error "仅支持 Linux 系统 / Only Linux is supported, 当前系统: $(uname -s)"
        exit 1
    fi
    info "操作系统 / Operating System: Linux"

    # 权限检测 / Permission Check
    if [[ $EUID -ne 0 ]]; then
        if ! groups | grep -q docker; then
            error "需要 root 权限或加入 docker 组 / Root permission or docker group required"
            exit 1
        fi
    fi
    info "权限检查通过 / Permission check passed"

    # 依赖检查 / Dependency Check
    if ! command -v curl &>/dev/null; then
        warn "缺少 curl，尝试安装... / Missing curl, trying to install..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq curl
        elif command -v yum &>/dev/null; then
            yum install -y -q curl
        elif command -v apk &>/dev/null; then
            apk add --no-cache curl
        else
            error "无法安装 curl / Unable to install curl"
            exit 1
        fi
    fi

    echo ""
    info "环境预检通过 / Preflight check passed"
}

# ==============================================================================
# 2. Docker 环境检查/安装 / Docker Environment Check/Install
# ==============================================================================
check_docker() {
    header "检查 Docker 环境 / Check Docker Environment"

    if command -v docker &>/dev/null; then
        local docker_version
        docker_version=$(docker --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' || echo "unknown")
        info "Docker 已安装 / Docker installed: ${docker_version}"

        # 检查 Docker 服务状态 / Check Docker service status
        if ! docker info &>/dev/null; then
            warn "Docker 服务未运行，尝试启动... / Docker service not running, trying to start..."
            if command -v systemctl &>/dev/null; then
                systemctl start docker
                systemctl enable docker
            else
                error "无法启动 Docker 服务 / Unable to start Docker service"
                exit 1
            fi
        fi
        info "Docker 服务运行正常 / Docker service running"
        return 0
    fi

    warn "Docker 未安装 / Docker not installed"
    echo ""
    read -rp "是否自动安装 Docker? [Y/n] / Auto install Docker? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        error "需要 Docker 才能继续 / Docker is required to continue"
        exit 1
    fi

    install_docker
}

install_docker() {
    info "正在安装 Docker... / Installing Docker..."

    # 使用官方安装脚本 / Use official install script
    if ! curl -fsSL https://get.docker.com | sh; then
        error "Docker 安装失败 / Docker installation failed"
        exit 1
    fi

    # 启动并启用 / Start and enable
    if command -v systemctl &>/dev/null; then
        systemctl start docker
        systemctl enable docker
    fi

    # 验证 / Verify
    if command -v docker &>/dev/null; then
        info "Docker 安装完成 / Docker installed: $(docker --version)"
    else
        error "Docker 安装验证失败 / Docker installation verification failed"
        exit 1
    fi
}

check_compose() {
    # Docker Compose v2 (plugin)
    if docker compose version &>/dev/null; then
        info "Docker Compose 已安装 / Docker Compose installed: $(docker compose version)"
        COMPOSE_CMD="docker compose"
        return 0
    fi

    # Docker Compose v1 (standalone)
    if command -v docker-compose &>/dev/null; then
        info "Docker Compose 已安装 / Docker Compose installed: $(docker-compose --version)"
        COMPOSE_CMD="docker-compose"
        return 0
    fi

    warn "Docker Compose 未安装 / Docker Compose not installed"
    echo ""
    read -rp "是否自动安装 Docker Compose? [Y/n] / Auto install Docker Compose? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        error "需要 Docker Compose 才能继续 / Docker Compose is required to continue"
        exit 1
    fi

    install_compose
}

install_compose() {
    info "正在安装 Docker Compose... / Installing Docker Compose..."

    local compose_version
    compose_version=$(curl -fsSL \
        "https://api.github.com/repos/docker/compose/releases/latest" \
        2>/dev/null | jq -r '.tag_name // empty')

    if [[ -z "$compose_version" ]]; then
        compose_version="v2.24.0"
        warn "无法获取最新版本，使用默认版本 / Cannot get latest version, using default: ${compose_version}"
    fi

    local arch
    arch=$(uname -m)
    case $arch in
        x86_64) arch="x86_64" ;;
        aarch64) arch="aarch64" ;;
    esac

    local download_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-${arch}"

    info "下载 Docker Compose ${compose_version}... / Downloading Docker Compose ${compose_version}..."
    if ! curl -fSL "$download_url" -o /usr/local/bin/docker-compose; then
        error "Docker Compose 下载失败 / Docker Compose download failed"
        exit 1
    fi

    chmod +x /usr/local/bin/docker-compose

    # 创建 v2 兼容链接 / Create v2 compatible link
    mkdir -p /usr/libexec/docker/cli-plugins 2>/dev/null || true
    ln -sf /usr/local/bin/docker-compose /usr/libexec/docker/cli-plugins/docker-compose 2>/dev/null || true

    # 验证 / Verify
    if docker compose version &>/dev/null; then
        COMPOSE_CMD="docker compose"
        info "Docker Compose 安装完成 / Docker Compose installed: $(docker compose version)"
    elif command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
        info "Docker Compose 安装完成 / Docker Compose installed: $(docker-compose --version)"
    else
        error "Docker Compose 安装验证失败 / Docker Compose installation verification failed"
        exit 1
    fi
}

# ==============================================================================
# 3. 项目初始化 / Project Initialization
# ==============================================================================
init_project() {
    header "初始化项目 / Initialize Project"

    # 选择目录 / Select directory
    prompt_bilingual "项目目录 (所有配置文件和数据将存放在此) / Project directory (configs and data will be stored here)"
    read -rp " [${DEFAULT_DIR}]: " project_dir
    PROJECT_DIR="${project_dir:-$DEFAULT_DIR}"

    if [[ -d "$PROJECT_DIR" ]]; then
        warn "目录已存在 / Directory exists: ${PROJECT_DIR}"
        echo ""
        read -rp " 是否重新初始化? [y/N] / Re-initialize? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            # 备份旧配置 / Backup old config
            if [[ -f "${PROJECT_DIR}/config.json" ]]; then
                cp "${PROJECT_DIR}/config.json" "${PROJECT_DIR}/config.json.bak.$(date +%s)"
                info "已备份旧配置 / Old config backed up"
            fi
            # 停止旧容器 / Stop old containers
            if [[ -f "${PROJECT_DIR}/docker-compose.yml" ]]; then
                cd "$PROJECT_DIR"
                $COMPOSE_CMD down 2>/dev/null || true
            fi
        fi
    fi

    # 创建目录结构 / Create directory structure
    mkdir -p "${PROJECT_DIR}"/{certs,data,geodata}
    info "项目目录 / Project directory: ${PROJECT_DIR}"
    info "  ├── certs/   (TLS 证书 / TLS certificates)"
    info "  ├── data/    (数据卷 / Data volume)"
    info "  └── geodata/ (路由规则 / Routing rules)"
}

# ==============================================================================
# 4. 配置生成 / Configuration Generation
# ==============================================================================
init_config() {
    header "配置初始化 / Configuration Initialization"

    if [[ -f "${PROJECT_DIR}/config.json" ]]; then
        warn "配置文件已存在 / Config file exists: ${PROJECT_DIR}/config.json"
        echo ""
        read -rp " 是否重新生成? [y/N] / Regenerate? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            info "保留现有配置 / Keeping existing config"
            return
        fi
    fi

    echo ""
    echo -e "${BOLD}===== Trojan-Go 配置向导 / Configuration Wizard =====${NC}"
    echo ""

    # 默认值 / Default values
    local port=443
    local password
    password=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | xxd -p 2>/dev/null || date +%s%N | md5sum | head -c 32)
    local ws_enabled="false"
    local ws_path="/trojan-go"
    local hy2_enabled="false"
    local hy2_port=8443

    # 交互式输入 / Interactive input
    read -rp " 监听端口 [${port}] / Listening port [${port}]: " input
    [[ -n "$input" ]] && port="$input"

    while ! [[ "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); do
        warn "无效端口 / Invalid port, 请输入 1-65535 之间的数字 / enter a number between 1-65535"
        read -rp " 监听端口 [443] / Listening port [443]: " port
        [[ -z "$port" ]] && port=443
    done

    echo ""
    prompt_bilingual " 密码 (留空使用随机密码) / Password (leave empty for random)"
    read -rp " [${password:0:8}...]: " input
    [[ -n "$input" ]] && password="$input"

    echo ""
    prompt_bilingual " 主节点域名 / Master domain (e.g. jp.liteops.top, 可选 / optional)"
    read -rp " 主节点域名 / Master domain: " MASTER
    
    if [[ -n "$MASTER" ]]; then
        IS_MASTER="true"
        info "已设置主节点域名 / Master domain set: ${MASTER}"
        info "此节点将作为主节点部署 / This node will be deployed as master"
    fi

    echo ""
    read -rp " 启用 WebSocket? [y/N] / Enable WebSocket? [y/N]: " input
    if [[ "$input" =~ ^[Yy]$ ]]; then
        ws_enabled="true"
        read -rp "  WebSocket 路径 [${ws_path}] / WebSocket path [${ws_path}]: " input
        [[ -n "$input" ]] && ws_path="$input"
    fi

    echo ""
    read -rp " 启用 Hysteria2 (UDP)? [y/N] / Enable Hysteria2 (UDP)? [y/N]: " input
    if [[ "$input" =~ ^[Yy]$ ]]; then
        hy2_enabled="true"
        read -rp "  Hysteria2 端口 [${hy2_port}] / Hysteria2 port [${hy2_port}]: " input
        [[ -n "$input" ]] && hy2_port="$input"
    fi

    # 生成配置 / Generate config
    generate_config "$port" "$password" "$ws_enabled" "$ws_path" "$hy2_enabled" "$hy2_port" \
        > "${PROJECT_DIR}/config.json"

    echo ""
    info "配置文件已生成 / Config file generated: ${PROJECT_DIR}/config.json"
    echo ""
    echo -e "${BOLD}  配置摘要 / Configuration Summary:${NC}"
    echo "  ──────────────────────────────────"
    show_config_item "端口/Port" "${port}"
    show_config_item "密码/Password" "${password}"
    show_config_item "主节点/Master" "${MASTER:-未设置/Not set}"
    show_config_item "WebSocket" "${ws_enabled} (${ws_path})"
    show_config_item "Hysteria2" "${hy2_enabled} (端口/port ${hy2_port})"
    echo "  ──────────────────────────────────"
}

generate_config() {
    local port=$1 password=$2 ws_enabled=$3 ws_path=$4 hy2_enabled=$5 hy2_port=$6

    # 转义 JSON 特殊字符 / Escape JSON special characters
    password=$(echo "$password" | sed 's/\\/\\\\/g; s/"/\\"/g')
    local escaped_master
    escaped_master=$(echo "$MASTER" | sed 's/\\/\\\\/g; s/"/\\"/g')
    ws_path=$(echo "$ws_path" | sed 's/\\/\\\\/g; s/"/\\"/g')

    cat << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": ${port},
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": ["${password}"],
    "ssl": {
        "cert": "/etc/trojan-go/certs/fullchain.crt",
        "key": "/etc/trojan-go/certs/private.key",
        "sni": "${escaped_master}"
    },
    "websocket": {
        "enabled": ${ws_enabled},
        "path": "${ws_path}",
        "hostname": "${escaped_master}"
    },
    "router": {
        "enabled": true,
        "block": ["geoip:private"],
        "geoip": "/usr/share/trojan-go/geoip.dat",
        "geosite": "/usr/share/trojan-go/geosite.dat"
    },
    "hysteria2": {
        "enabled": ${hy2_enabled},
        "port": ${hy2_port},
        "up_mbps": 100,
        "down_mbps": 500,
        "masquerade_url": "https://www.bilibili.com",
        "auth_api": "http://127.0.0.1:8080/admin/api/hysteria/auth"
    }
}
EOF
}

# ==============================================================================
# 5. 生成 docker-compose.yml / Generate Docker Compose Configuration
# ==============================================================================
generate_compose() {
    header "生成 Docker Compose 配置 / Generate Docker Compose Configuration"

    info "创建 docker-compose.yml... / Creating docker-compose.yml..."

    cat > "${PROJECT_DIR}/docker-compose.yml" << EOF
version: '3.8'

services:
  trojan-go:
    image: ${REMOTE_IMAGE}
    container_name: trojan-go
    restart: unless-stopped
    ports:
      - "443:443"
      - "8443:8443/udp"
    volumes:
      - ./config.json:/etc/trojan-go/config.json:ro
      - ./certs:/etc/trojan-go/certs:ro
      - ./geodata:/usr/share/trojan-go:ro
      - trojan-go-data:/data
    environment:
      - TZ=Asia/Shanghai
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:80"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

volumes:
  trojan-go-data:
EOF

    info "docker-compose.yml 已生成 / docker-compose.yml generated"
}

# ==============================================================================
# 6. 启动服务 / Start Service
# ==============================================================================
start_service() {
    header "启动服务 / Start Service"

    cd "$PROJECT_DIR"

    info "拉取最新镜像... / Pulling latest image..."
    if ! $COMPOSE_CMD pull; then
        warn "镜像拉取失败，尝试使用本地缓存 / Image pull failed, trying local cache"
    fi

    info "启动容器... / Starting containers..."
    $COMPOSE_CMD up -d

    # 等待启动 / Wait for startup
    info "等待服务就绪... / Waiting for service to be ready..."
    sleep 5

    # 检查状态 / Check status
    if $COMPOSE_CMD ps | grep -q "Up"; then
        info "服务启动成功 / Service started successfully ✓"
    else
        error "服务启动失败 / Service failed to start"
        echo ""
        info "查看日志 / View logs: docker logs trojan-go"
        exit 1
    fi
}

# ==============================================================================
# 7. 结果输出 / Result Output
# ==============================================================================
print_result() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}        Trojan-Go Docker 部署完成 / Deployment Complete${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}项目目录 / Project Dir:${NC} ${PROJECT_DIR}"
    echo -e "  ${BOLD}配置文件 / Config File:${NC} ${PROJECT_DIR}/config.json"
    echo ""
    if [[ "$IS_MASTER" == "true" ]]; then
        echo -e "  ${BOLD}节点类型 / Node Type:${NC} ${GREEN}主节点 / Master${NC}"
        echo -e "  ${BOLD}主节点域名 / Master Domain:${NC} ${MASTER}"
    else
        echo -e "  ${BOLD}节点类型 / Node Type:${NC} ${YELLOW}从节点 / Worker${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}常用命令 / Common Commands (需在 / run in ${PROJECT_DIR}):${NC}"
    echo "  ──────────────────────────────────"
    echo "  启动/Start:   ${COMPOSE_CMD} up -d"
    echo "  停止/Stop:    ${COMPOSE_CMD} down"
    echo "  重启/Restart: ${COMPOSE_CMD} restart"
    echo "  日志/Logs:    docker logs -f trojan-go"
    echo "  状态/Status:  ${COMPOSE_CMD} ps"
    echo "  更新/Update:  ${COMPOSE_CMD} pull && ${COMPOSE_CMD} up -d"
    echo "  ──────────────────────────────────"
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# ==============================================================================
# 卸载 / Uninstall
# ==============================================================================
uninstall() {
    header "卸载 Trojan-Go Docker / Uninstall Trojan-Go Docker"

    # 查找项目目录 / Find project directory
    local project_dir=""
    if [[ -d "$DEFAULT_DIR" ]]; then
        project_dir="$DEFAULT_DIR"
    else
        prompt_bilingual "查找项目目录... / Finding project directory..."
        read -rp " 项目目录 [${DEFAULT_DIR}] / Project dir [${DEFAULT_DIR}]: " project_dir
        project_dir="${project_dir:-$DEFAULT_DIR}"
    fi

    if [[ ! -d "$project_dir" ]]; then
        warn "项目目录不存在 / Project directory not found: $project_dir"
        info "可能已卸载 / May already be uninstalled"
        exit 0
    fi

    echo ""
    read -rp "确认卸载? [y/N] / Confirm uninstall? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "取消卸载 / Uninstall cancelled"
        exit 0
    fi

    # 停止容器 / Stop containers
    if [[ -f "${project_dir}/docker-compose.yml" ]]; then
        cd "$project_dir"
        info "停止并删除容器... / Stopping and removing containers..."
        docker compose down -v 2>/dev/null || docker-compose down -v 2>/dev/null || true
    fi

    echo ""
    read -rp "是否删除项目目录 / Delete project directory ${project_dir}? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -rf "$project_dir"
        info "项目目录已删除 / Project directory deleted"
    else
        info "项目目录已保留 / Project directory kept: $project_dir"
    fi

    echo ""
    info "卸载完成 / Uninstall complete"
}

# ==============================================================================
# 主流程 / Main Process
# ==============================================================================
main() {
    # 初始化日志 / Initialize log
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "===== Trojan-Go Docker 安装日志 / Install Log $(date) =====" >> "$LOG_FILE"

    # 卸载模式 / Uninstall mode
    if [[ "${1:-}" == "--uninstall" ]]; then
        uninstall
        exit 0
    fi

    preflight_check
    check_docker
    check_compose
    init_project
    init_config
    generate_compose
    start_service
    print_result
}

main "$@"
