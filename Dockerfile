FROM golang:alpine AS builder
RUN apk add --no-cache git make wget

# 准备编译环境并拷贝本地源码
WORKDIR /app
COPY . .

# 执行编译
RUN make

# 下载最新的 Geodata 规则文件
RUN mkdir -p /geodata && \
    wget https://github.com/v2fly/domain-list-community/raw/release/dlc.dat -O /geodata/geosite.dat && \
    wget https://github.com/v2fly/geoip/raw/release/geoip.dat -O /geodata/geoip.dat && \
    wget https://github.com/v2fly/geoip/raw/release/geoip-only-cn-private.dat -O /geodata/geoip-only-cn-private.dat

FROM alpine
WORKDIR /
RUN apk add --no-cache tzdata ca-certificates wget

# 从编译阶段拷贝核心二进制和 CLI 管理工具
COPY --from=builder /app/build/linux-amd64/trojan-go /usr/local/bin/trojan-go
COPY --from=builder /app/build/linux-amd64/trojan /usr/local/bin/trojan

# 下载 Hysteria2 服务端二进制（QUIC/UDP 主力协议，配套 trojan-go 使用）
ARG HYSTERIA_VERSION=v2.6.1
RUN wget -qO /usr/local/bin/hysteria \
    https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VERSION}/hysteria-linux-amd64 \
    && chmod +x /usr/local/bin/hysteria

# 从编译阶段拷贝地理路由规则文件到 /usr/share/trojan-go 目录
COPY --from=builder /geodata /usr/share/trojan-go

# 拷贝默认服务端配置文件
COPY --from=builder /app/example/server.json /etc/trojan-go/config.json

# 默认以配置文件模式运行
ENTRYPOINT ["/usr/local/bin/trojan-go", "-config"]
CMD ["/etc/trojan-go/config.json"]

