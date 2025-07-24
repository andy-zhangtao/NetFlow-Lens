# 🌐 NetFlow Lens

> 专业级网络流量可视化学习工具 - 现已支持实时性能分析！

[![Go Version](https://img.shields.io/badge/Go-1.24.0-blue.svg)](https://golang.org/)
[![Build Status](https://img.shields.io/badge/Build-Passing-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]()

## ✨ 核心特性

### 🚀 网络性能分析
- **延迟分析**: RTT计算、握手延迟跟踪、网络抖动检测
- **吞吐量监控**: 实时带宽监控、峰值记录、历史趋势分析  
- **丢包率分析**: 重传检测、乱序包识别、序列号跟踪
- **质量评估**: 0-100分连接质量评分系统，智能性能建议

### 📊 可视化界面
- **实时指标卡片**: 延迟、吞吐量、丢包率、活跃连接数
- **趋势图表**: Canvas绘制的性能趋势可视化
- **TCP状态图**: 交互式TCP状态转换可视化
- **连接排行**: 按性能问题排序的连接列表

### ⚡ 实时数据推送
- **WebSocket推送**: TCP状态和性能数据实时更新
- **自动重连**: 连接断开时自动重连和状态指示
- **回退机制**: WebSocket失败时自动切换HTTP轮询

### 📋 数据导出与报告
- **多格式导出**: CSV/JSON格式的性能数据导出
- **综合报告**: 执行摘要、关键指标、问题分析
- **智能建议**: 基于分析结果的自动优化建议

### 🔧 数据处理能力
- **实时捕获**: 从网络接口实时捕获数据包
- **PCAP分析**: 支持上传和分析PCAP文件
- **BPF过滤**: 灵活的数据包过滤功能

## 🏗️ 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Interface │    │  WebSocket API  │    │   REST API      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   HTTP Server   │
                    └─────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Analyzer     │    │    Capturer     │    │ Performance     │
│   - TCP分析     │    │   - 实时捕获    │    │   - 延迟分析    │
│   - 状态跟踪    │    │   - PCAP处理    │    │   - 吞吐量统计  │
│   - 连接管理    │    │   - BPF过滤     │    │   - 质量评估    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 快速开始

### 环境要求
- Go 1.24.0 或更高版本
- 支持原始套接字的操作系统权限

### 安装和运行

```bash
# 克隆项目
git clone https://github.com/andy-zhangtao/NetFlow-Lens.git
cd NetFlow-Lens

# 构建项目
make build

# 运行服务
make run

# 或者使用开发模式
make dev
```

访问 [http://localhost:8080](http://localhost:8080) 开始使用！

### Docker 运行

```bash
# 构建Docker镜像
make docker-build

# 运行Docker容器
make docker-run
```

## 📖 使用指南

### 1. 实时网络监控
- 选择网络接口开始实时捕获
- 观察TCP状态转换和性能指标
- 查看连接质量评分和建议

### 2. PCAP文件分析
- 上传PCAP文件进行离线分析
- 查看历史网络行为模式
- 生成详细的性能报告

### 3. 性能分析报告
- 点击"生成报告"获取综合分析
- 导出CSV/JSON格式的性能数据
- 获取针对性的优化建议

## 🔌 API 文档

### 性能分析 API

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/performance` | GET | 获取完整性能数据 |
| `/api/performance/connection/{id}` | GET | 获取特定连接性能 |
| `/api/performance/export?format=csv\|json` | GET | 导出性能数据 |
| `/api/performance/report` | GET | 生成综合性能报告 |

### WebSocket 接口

```javascript
// 连接WebSocket
const ws = new WebSocket('ws://localhost:8080/ws');

// 接收实时数据
ws.onmessage = function(event) {
    const message = JSON.parse(event.data);
    if (message.type === 'performance_update') {
        // 处理性能数据更新
        updatePerformanceUI(message.data);
    }
};
```

## 🛠️ 开发指南

### 项目结构

```
NetFlow-Lens/
├── cmd/netflow-lens/        # 主程序入口
├── internal/
│   ├── analyzer/            # 数据包分析和性能分析
│   ├── capture/             # 数据包捕获
│   └── server/              # HTTP服务器和WebSocket
├── pkg/models/              # 数据模型定义
├── web/static/              # 静态资源
├── tests/                   # 测试文件
└── Makefile                 # 构建脚本
```

### 开发命令

```bash
# 代码格式化和检查
make lint

# 运行测试
make test

# 运行测试并生成覆盖率报告
make test-coverage

# 交叉编译
make build-all
```

## 📊 性能特性

- **实时分析**: 每个数据包都进行实时性能分析
- **内存优化**: 环形缓冲区限制内存使用
- **并发安全**: 使用mutex保护共享数据结构
- **智能评分**: 基于延迟、丢包、抖动的综合评分算法

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [gopacket](https://github.com/google/gopacket) - 强大的Go网络包处理库
- [gorilla/websocket](https://github.com/gorilla/websocket) - 高质量的WebSocket实现

---

⭐ 如果这个项目对你有帮助，请给它一个星标!