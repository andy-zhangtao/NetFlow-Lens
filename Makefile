# NetFlow Lens Makefile

# 变量定义
APP_NAME = netflow-lens
CMD_DIR = ./cmd/$(APP_NAME)
BUILD_DIR = ./build
BINARY = $(BUILD_DIR)/$(APP_NAME)

# Go 相关变量
GO = go
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# 版本信息
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME = $(shell date +%Y-%m-%d\ %H:%M:%S)
GIT_COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 编译标志
LDFLAGS = -ldflags "-X 'main.Version=$(VERSION)' -X 'main.BuildTime=$(BUILD_TIME)' -X 'main.GitCommit=$(GIT_COMMIT)'"

.PHONY: all build run clean test fmt vet deps dev help

# 默认目标
all: clean build

# 构建应用
build:
	@echo "构建 $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BINARY) $(CMD_DIR)
	@echo "构建完成: $(BINARY)"

# 快速构建（当前目录）
build-local:
	@echo "快速构建 $(APP_NAME)..."
	$(GO) build $(LDFLAGS) -o $(APP_NAME) $(CMD_DIR)
	@echo "构建完成: ./$(APP_NAME)"

# 运行应用
run: build-local
	@echo "启动 $(APP_NAME)..."
	./$(APP_NAME) $(ARGS)

# 开发模式（热重载需要额外工具）
dev:
	@echo "开发模式启动..."
	$(GO) run $(CMD_DIR) $(ARGS)

# 清理构建文件
clean:
	@echo "清理构建文件..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(APP_NAME)
	@echo "清理完成"

# 运行测试
test:
	@echo "运行测试..."
	$(GO) test -v ./...

# 运行基准测试
bench:
	@echo "运行基准测试..."
	$(GO) test -bench=. -benchmem ./...

# 代码格式化
fmt:
	@echo "格式化代码..."
	$(GO) fmt ./...

# 代码检查
vet:
	@echo "检查代码..."
	$(GO) vet ./...

# 安装依赖
deps:
	@echo "安装依赖..."
	$(GO) mod tidy
	$(GO) mod download

# 更新依赖
deps-update:
	@echo "更新依赖..."
	$(GO) get -u ./...
	$(GO) mod tidy

# 生成文档
docs:
	@echo "生成文档..."
	$(GO) doc -all > docs/api.md

# 交叉编译
build-linux:
	@echo "构建 Linux 版本..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(CMD_DIR)

build-windows:
	@echo "构建 Windows 版本..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(CMD_DIR)

build-darwin:
	@echo "构建 macOS 版本..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 $(CMD_DIR)

# 构建所有平台
build-all: build-linux build-windows build-darwin
	@echo "所有平台构建完成"

# Docker 相关
docker-build:
	@echo "构建 Docker 镜像..."
	docker build -t $(APP_NAME):$(VERSION) .

docker-run: docker-build
	@echo "运行 Docker 容器..."
	docker run -p 8080:8080 $(APP_NAME):$(VERSION)

# 安装到系统
install: build
	@echo "安装到系统..."
	sudo cp $(BINARY) /usr/local/bin/

# 卸载
uninstall:
	@echo "从系统卸载..."
	sudo rm -f /usr/local/bin/$(APP_NAME)

# 检查代码质量
lint: fmt vet
	@echo "代码质量检查完成"

# 完整检查（格式化 + 检查 + 测试 + 构建）
check: lint test build
	@echo "完整检查完成"

# 发布准备
release: clean check build-all
	@echo "发布包准备完成"

# 显示版本信息
version:
	@echo "版本: $(VERSION)"
	@echo "构建时间: $(BUILD_TIME)"
	@echo "Git提交: $(GIT_COMMIT)"

# 显示帮助信息
help:
	@echo "NetFlow Lens Makefile 使用说明:"
	@echo ""
	@echo "基础命令:"
	@echo "  make build        - 构建应用到 build/ 目录"
	@echo "  make build-local  - 快速构建到当前目录"
	@echo "  make run          - 构建并运行应用 (默认8080端口)"
	@echo "  make dev          - 开发模式运行 (默认8080端口)"
	@echo "  make clean        - 清理构建文件"
	@echo ""
	@echo "端口参数示例:"
	@echo "  make run ARGS='-port 9090'     - 使用9090端口运行"
	@echo "  make dev ARGS='-port 8888'     - 开发模式使用8888端口"
	@echo "  ./netflow-lens -port 3000      - 直接运行指定端口"
	@echo "  ./netflow-lens -help           - 查看所有命令行选项"
	@echo ""
	@echo "测试和检查:"
	@echo "  make test         - 运行测试"
	@echo "  make bench        - 运行基准测试"
	@echo "  make fmt          - 格式化代码"
	@echo "  make vet          - 代码检查"
	@echo "  make lint         - 代码质量检查 (fmt + vet)"
	@echo "  make check        - 完整检查 (lint + test + build)"
	@echo ""
	@echo "依赖管理:"
	@echo "  make deps         - 安装依赖"
	@echo "  make deps-update  - 更新依赖"
	@echo ""
	@echo "交叉编译:"
	@echo "  make build-linux  - 构建 Linux 版本"
	@echo "  make build-windows- 构建 Windows 版本"
	@echo "  make build-darwin - 构建 macOS 版本"
	@echo "  make build-all    - 构建所有平台版本"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build - 构建 Docker 镜像"
	@echo "  make docker-run   - 运行 Docker 容器"
	@echo ""
	@echo "系统安装:"
	@echo "  make install      - 安装到系统 (/usr/local/bin)"
	@echo "  make uninstall    - 从系统卸载"
	@echo ""
	@echo "其他:"
	@echo "  make version      - 显示版本信息"
	@echo "  make release      - 发布准备 (完整检查 + 多平台构建)"
	@echo "  make help         - 显示此帮助信息"