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
	@echo "$(BLUE)构建 $(APP_NAME)...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BINARY) $(CMD_DIR)
	@echo "$(GREEN)✓ 构建完成: $(BINARY)$(RESET)"

# 快速构建（当前目录）
build-local:
	@echo "$(BLUE)快速构建 $(APP_NAME)...$(RESET)"
	$(GO) build $(LDFLAGS) -o $(APP_NAME) $(CMD_DIR)
	@echo "$(GREEN)✓ 构建完成: ./$(APP_NAME)$(RESET)"

# 运行应用
run: build-local
	@echo "$(BLUE)启动 $(APP_NAME)...$(RESET)"
	@echo "$(YELLOW)访问 http://localhost:8080 体验TCP状态图可视化功能$(RESET)"
	./$(APP_NAME) $(ARGS)

# 开发模式（热重载需要额外工具）
dev:
	@echo "$(BLUE)开发模式启动...$(RESET)"
	@echo "$(YELLOW)访问 http://localhost:8080 体验TCP状态图功能$(RESET)"
	$(GO) run $(CMD_DIR) $(ARGS)

# 清理构建文件
clean:
	@echo "$(BLUE)清理构建文件...$(RESET)"
	@rm -rf $(BUILD_DIR)
	@rm -f $(APP_NAME)
	@echo "$(GREEN)✓ 清理完成$(RESET)"

# 运行测试
test:
	@echo "$(BLUE)运行测试...$(RESET)"
	$(GO) test -v ./...
	@echo "$(GREEN)✓ 测试完成$(RESET)"

# 运行测试带覆盖率
test-coverage:
	@echo "运行测试并生成覆盖率报告..."
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"

# 运行单个模块测试
test-models:
	@echo "测试 models 模块..."
	$(GO) test -v ./pkg/models

test-analyzer:
	@echo "测试 analyzer 模块..."
	$(GO) test -v ./internal/analyzer

test-capture:
	@echo "测试 capture 模块..."
	$(GO) test -v ./internal/capture

test-server:
	@echo "测试 server 模块..."
	$(GO) test -v ./internal/server

# 运行基准测试
bench:
	@echo "运行基准测试..."
	$(GO) test -bench=. -benchmem ./...

# 运行性能测试
test-performance: bench
	@echo "性能测试完成"

# 运行集成测试
test-integration:
	@echo "运行集成测试..."
	$(GO) test -v ./tests/...

# 运行所有测试（单元测试 + 集成测试）
test-all: test test-integration
	@echo "所有测试完成"

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

# 持续集成检查
ci: lint test test-coverage
	@echo "持续集成检查完成"

# 发布准备
release: clean check build-all
	@echo "发布包准备完成"

# 显示版本信息
version:
	@echo "版本: $(VERSION)"
	@echo "构建时间: $(BUILD_TIME)"
	@echo "Git提交: $(GIT_COMMIT)"

# 颜色定义
RED = \033[31m
GREEN = \033[32m
YELLOW = \033[33m
BLUE = \033[34m
PURPLE = \033[35m
CYAN = \033[36m
RESET = \033[0m

# 显示帮助信息
help:
	@echo "$(BLUE)NetFlow Lens - 网络流量可视化学习工具$(RESET)"
	@echo "$(PURPLE)现已支持TCP状态图可视化和交互功能！$(RESET)"
	@echo ""
	@echo "$(YELLOW)🚀 快速开始:$(RESET)"
	@echo "  $(GREEN)make run$(RESET)             - 一键构建并运行"
	@echo "  $(GREEN)make dev$(RESET)             - 开发模式运行"
	@echo "  $(GREEN)make test$(RESET)            - 运行所有测试"
	@echo ""
	@echo "$(YELLOW)📦 构建命令:$(RESET)"
	@echo "  $(GREEN)make build$(RESET)           - 构建应用到 build/ 目录"
	@echo "  $(GREEN)make build-local$(RESET)     - 快速构建到当前目录"
	@echo "  $(GREEN)make clean$(RESET)           - 清理构建文件"
	@echo ""
	@echo "$(YELLOW)🔧 开发工具:$(RESET)"
	@echo "  $(GREEN)make fmt$(RESET)             - 格式化代码"
	@echo "  $(GREEN)make vet$(RESET)             - 代码检查"
	@echo "  $(GREEN)make lint$(RESET)            - 代码质量检查 (fmt + vet)"
	@echo "  $(GREEN)make check$(RESET)           - 完整检查 (lint + test + build)"
	@echo ""
	@echo "$(YELLOW)🧪 测试命令:$(RESET)"
	@echo "  $(GREEN)make test$(RESET)            - 运行单元测试"
	@echo "  $(GREEN)make test-coverage$(RESET)   - 运行测试并生成覆盖率报告"
	@echo "  $(GREEN)make test-integration$(RESET) - 运行集成测试"
	@echo "  $(GREEN)make test-all$(RESET)        - 运行所有测试"
	@echo "  $(GREEN)make bench$(RESET)           - 运行基准测试"
	@echo ""
	@echo "$(YELLOW)📋 模块测试:$(RESET)"
	@echo "  $(GREEN)make test-models$(RESET)     - 测试数据模型"
	@echo "  $(GREEN)make test-analyzer$(RESET)   - 测试数据包分析器"
	@echo "  $(GREEN)make test-capture$(RESET)    - 测试数据包捕获"
	@echo "  $(GREEN)make test-server$(RESET)     - 测试HTTP服务器"
	@echo ""
	@echo "$(YELLOW)🌍 交叉编译:$(RESET)"
	@echo "  $(GREEN)make build-linux$(RESET)     - 构建 Linux 版本"
	@echo "  $(GREEN)make build-windows$(RESET)   - 构建 Windows 版本"
	@echo "  $(GREEN)make build-darwin$(RESET)    - 构建 macOS 版本"
	@echo "  $(GREEN)make build-all$(RESET)       - 构建所有平台版本"
	@echo ""
	@echo "$(YELLOW)🐳 Docker:$(RESET)"
	@echo "  $(GREEN)make docker-build$(RESET)    - 构建 Docker 镜像"
	@echo "  $(GREEN)make docker-run$(RESET)      - 运行 Docker 容器"
	@echo ""
	@echo "$(YELLOW)📦 依赖管理:$(RESET)"
	@echo "  $(GREEN)make deps$(RESET)            - 安装依赖"
	@echo "  $(GREEN)make deps-update$(RESET)     - 更新依赖"
	@echo ""
	@echo "$(YELLOW)💾 系统安装:$(RESET)"
	@echo "  $(GREEN)make install$(RESET)         - 安装到系统 (/usr/local/bin)"
	@echo "  $(GREEN)make uninstall$(RESET)       - 从系统卸载"
	@echo ""
	@echo "$(YELLOW)🎯 TCP状态图功能:$(RESET)"
	@echo "  访问 $(CYAN)http://localhost:8080$(RESET) 查看TCP状态可视化"
	@echo "  - 点击状态节点查看详细信息"
	@echo "  - 鼠标悬停显示状态说明"
	@echo "  - 实时状态转换动画效果"
	@echo ""
	@echo "$(YELLOW)📱 端口参数示例:$(RESET)"
	@echo "  $(GREEN)make run ARGS='-port 9090'$(RESET)      - 使用9090端口运行"
	@echo "  $(GREEN)make dev ARGS='-port 8888'$(RESET)      - 开发模式使用8888端口"
	@echo "  $(GREEN)./netflow-lens -port 3000$(RESET)       - 直接运行指定端口"
	@echo ""
	@echo "$(YELLOW)🔧 实用工具:$(RESET)"
	@echo "  $(GREEN)make status$(RESET)          - 显示项目状态"
	@echo "  $(GREEN)make stats$(RESET)           - 代码统计信息"
	@echo "  $(GREEN)make health-check$(RESET)    - 运行健康检查"
	@echo "  $(GREEN)make clean-all$(RESET)       - 深度清理(包含缓存)"
	@echo "  $(GREEN)make security-check$(RESET)  - 安全漏洞检查"
	@echo "  $(GREEN)make report$(RESET)          - 生成项目报告"
	@echo ""
	@echo "$(YELLOW)ℹ️  其他:$(RESET)"
	@echo "  $(GREEN)make version$(RESET)         - 显示版本信息"
	@echo "  $(GREEN)make release$(RESET)         - 发布准备 (完整检查 + 多平台构建)"
	@echo "  $(GREEN)make quick-demo$(RESET)      - 快速演示模式"

# 项目状态显示
status:
	@echo "$(BLUE)NetFlow Lens 项目状态:$(RESET)"
	@echo "  项目名称: $(GREEN)$(APP_NAME)$(RESET)"
	@echo "  构建目录: $(GREEN)$(BUILD_DIR)$(RESET)"
	@echo "  二进制文件: $(GREEN)$(BINARY)$(RESET)"
	@echo "  Go 版本: $(GREEN)$(shell $(GO) version)$(RESET)"
	@if [ -f $(BINARY) ]; then \
		echo "  构建状态: $(GREEN)已构建$(RESET)"; \
		echo "  文件大小: $(GREEN)$(shell ls -lh $(BINARY) 2>/dev/null | awk '{print $$5}' || echo 'N/A')$(RESET)"; \
	else \
		echo "  构建状态: $(RED)未构建$(RESET)"; \
	fi
	@if [ -f ./$(APP_NAME) ]; then \
		echo "  本地构建: $(GREEN)存在$(RESET)"; \
	else \
		echo "  本地构建: $(RED)不存在$(RESET)"; \
	fi

# 快速演示模式
quick-demo: build-local
	@echo "$(PURPLE)🎬 NetFlow Lens 演示模式$(RESET)"
	@echo "$(YELLOW)TCP状态图可视化功能演示:$(RESET)"
	@echo "  1. 点击任意TCP状态节点查看详细信息"
	@echo "  2. 鼠标悬停在状态节点上查看说明"
	@echo "  3. 上传PCAP文件查看实际网络流量"
	@echo "  4. 观察实时状态转换动画效果"
	@echo ""
	@echo "$(CYAN)正在启动演示服务器...$(RESET)"
	@echo "$(GREEN)访问 http://localhost:8080 开始演示$(RESET)"
	./$(APP_NAME) $(ARGS)

# 健康检查
health-check: build-local
	@echo "$(BLUE)运行健康检查...$(RESET)"
	@./$(APP_NAME) -help > /dev/null 2>&1 && echo "$(GREEN)✓ 应用可执行文件正常$(RESET)" || echo "$(RED)✗ 应用可执行文件异常$(RESET)"
	@$(GO) version > /dev/null 2>&1 && echo "$(GREEN)✓ Go 环境正常$(RESET)" || echo "$(RED)✗ Go 环境异常$(RESET)"
	@git --version > /dev/null 2>&1 && echo "$(GREEN)✓ Git 环境正常$(RESET)" || echo "$(YELLOW)⚠ Git 未安装$(RESET)"

# 清理所有构建产物和缓存
clean-all: clean
	@echo "$(BLUE)深度清理...$(RESET)"
	@rm -f coverage.out coverage.html
	@$(GO) clean -cache
	@$(GO) clean -modcache -i
	@echo "$(GREEN)✓ 深度清理完成$(RESET)"

# 代码统计
stats:
	@echo "$(BLUE)NetFlow Lens 代码统计:$(RESET)"
	@echo "  Go 文件数: $(GREEN)$(shell find . -name '*.go' | wc -l | tr -d ' ')$(RESET)"
	@echo "  总行数: $(GREEN)$(shell find . -name '*.go' -exec cat {} \; | wc -l | tr -d ' ')$(RESET)"
	@echo "  测试文件数: $(GREEN)$(shell find . -name '*_test.go' | wc -l | tr -d ' ')$(RESET)"
	@echo "  包数量: $(GREEN)$(shell $(GO) list ./... | wc -l | tr -d ' ')$(RESET)"

# 依赖安全检查
security-check:
	@echo "$(BLUE)运行安全检查...$(RESET)"
	@if command -v govulncheck > /dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "$(YELLOW)govulncheck 未安装，跳过漏洞检查$(RESET)"; \
		echo "$(CYAN)可通过以下命令安装: go install golang.org/x/vuln/cmd/govulncheck@latest$(RESET)"; \
	fi

# 生成项目报告
report: status stats
	@echo "$(BLUE)生成项目报告...$(RESET)"
	@echo "========================================" > project-report.txt
	@echo "NetFlow Lens 项目报告" >> project-report.txt
	@echo "生成时间: $(shell date)" >> project-report.txt
	@echo "========================================" >> project-report.txt
	@echo "" >> project-report.txt
	@make status | sed 's/\x1b\[[0-9;]*m//g' >> project-report.txt
	@echo "" >> project-report.txt
	@make stats | sed 's/\x1b\[[0-9;]*m//g' >> project-report.txt
	@echo "" >> project-report.txt
	@echo "Git 信息:" >> project-report.txt
	@echo "  当前分支: $(shell git branch --show-current 2>/dev/null || echo 'unknown')" >> project-report.txt
	@echo "  最近提交: $(shell git log -1 --oneline 2>/dev/null || echo 'unknown')" >> project-report.txt
	@echo "$(GREEN)✓ 项目报告已生成: project-report.txt$(RESET)"

# 更新 .PHONY 声明
.PHONY: all build run clean test fmt vet deps dev help status quick-demo health-check clean-all stats security-check report