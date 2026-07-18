NAME := trojan-go
CTL  := trojan
PACKAGE_NAME := github.com/voidluo/trojan-go
VERSION := $(shell git describe --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")

BUILD_DIR := build
LDFLAGS := -s -w -buildid= -X $(PACKAGE_NAME)/version.Version=$(VERSION) -X $(PACKAGE_NAME)/version.Commit=$(COMMIT)
GOBUILD := CGO_ENABLED=0 go build -tags "full" -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all trojan-go trojan clean install test test-race test-cover test-scenario

all: trojan-go trojan

clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# ========== 测试 ==========

test:
	go test -count=1 ./...

test-race:
	CGO_ENABLED=1 go test -race -count=1 ./...

test-cover:
	go test -count=1 -coverprofile=coverage.out -coverpkg=./... ./...
	go tool cover -func=coverage.out | grep total
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage HTML: coverage.html"

test-scenario:
	go test -count=1 -v ./test/scenario/...

# ========== 编译 ==========
trojan-go:
	mkdir -p $(BUILD_DIR)/linux-amd64
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/linux-amd64/$(NAME) ./cmd/trojan-go

# 编译纯 CLI 管理控制台
trojan:
	mkdir -p $(BUILD_DIR)/linux-amd64
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/linux-amd64/$(CTL) ./cmd/trojan

# 打包发布 (含二进制文件、示例配置和路由规则)
release: all
	mkdir -p $(BUILD_DIR)/linux-amd64
	cp example_config.yaml $(BUILD_DIR)/linux-amd64/config.yaml.example
	cp routes.json $(BUILD_DIR)/linux-amd64/routes.json.example
	# 打包为 zip 文件
	cd $(BUILD_DIR)/linux-amd64 && zip -r ../trojan-go-linux-amd64.zip .
	@echo "发布包已生成: $(BUILD_DIR)/trojan-go-linux-amd64.zip"

# 一键构建并打包
dist: clean release

# 安装到系统
install: all
	mkdir -p /etc/trojan-go
	cp $(BUILD_DIR)/linux-amd64/$(NAME) /usr/bin/$(NAME)
	cp $(BUILD_DIR)/linux-amd64/$(CTL) /usr/bin/$(CTL)
	cp example_config.yaml /etc/trojan-go/config.yaml.example
	cp routes.json /etc/trojan-go/routes.json.example
	@echo "安装完成！"
	@echo "  配置文件示例已放置于: /etc/trojan-go/"
	@echo "  启动服务: trojan-go -config /etc/trojan-go/config.yaml"
	@echo "  管理控制台直接运行: trojan"
