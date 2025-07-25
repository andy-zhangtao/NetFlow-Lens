package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/internal/analyzer"
	"github.com/andy-zhangtao/NetFlow-Lens/internal/capture"
	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
	"github.com/gorilla/websocket"
)

// WebSocket客户端连接
type WSClient struct {
	conn   *websocket.Conn
	send   chan []byte
	server *Server
	id     string
}

// WebSocket消息类型
type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type Server struct {
	mux         *http.ServeMux
	capturer    *capture.Capturer
	analyzer    *analyzer.Analyzer
	pcapFiles   map[string]*models.PCAPFileInfo
	pcapMutex   sync.RWMutex
	uploadDir   string
	
	// WebSocket相关
	upgrader    websocket.Upgrader
	clients     map[string]*WSClient
	clientMutex sync.RWMutex
	broadcast   chan []byte
}

func NewServer() *Server {
	// 创建上传目录
	uploadDir := "uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Printf("创建上传目录失败: %v", err)
	}

	s := &Server{
		mux:       http.NewServeMux(),
		capturer:  capture.NewCapturer(),
		analyzer:  analyzer.NewAnalyzer(),
		pcapFiles: make(map[string]*models.PCAPFileInfo),
		uploadDir: uploadDir,
		
		// WebSocket初始化
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许所有来源，生产环境应该更严格
			},
		},
		clients:   make(map[string]*WSClient),
		broadcast: make(chan []byte, 256),
	}
	s.setupRoutes()

	// 设置TCP状态变化回调
	s.analyzer.SetTCPStateChangeCallback(s.broadcastTCPStateUpdate)
	
	// 设置性能数据更新回调
	s.analyzer.SetPerformanceUpdateCallback(s.broadcastPerformanceUpdate)

	// 启动后台任务
	go s.startPacketProcessing()
	go s.startWebSocketHub()

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) setupRoutes() {
	// 基础路由
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/api/status", s.handleAPIStatus)
	s.mux.HandleFunc("/api/connections", s.handleConnections)
	s.mux.HandleFunc("/api/packets", s.handlePackets)

	// 数据包捕获相关
	s.mux.HandleFunc("/api/capture/start", s.handleStartCapture)
	s.mux.HandleFunc("/api/capture/stop", s.handleStopCapture)
	s.mux.HandleFunc("/api/capture/status", s.handleCaptureStatus)
	s.mux.HandleFunc("/api/interfaces", s.handleListInterfaces)

	// PCAP文件相关
	s.mux.HandleFunc("/api/pcap/upload", s.handlePCAPUpload)
	s.mux.HandleFunc("/api/pcap/list", s.handlePCAPList)
	s.mux.HandleFunc("/api/pcap/load", s.handlePCAPLoad)
	s.mux.HandleFunc("/api/pcap/info", s.handlePCAPInfo)

	// BPF过滤器相关
	s.mux.HandleFunc("/api/filters", s.handleFilters)
	s.mux.HandleFunc("/api/filters/validate", s.handleValidateFilter)
	s.mux.HandleFunc("/api/filters/presets", s.handleFilterPresets)
	s.mux.HandleFunc("/api/filters/active", s.handleActiveFilter)
	s.mux.HandleFunc("/api/filters/stats", s.handleFilterStats)

	// TCP状态可视化相关
	s.mux.HandleFunc("/api/tcp/visualization", s.handleTCPVisualization)
	s.mux.HandleFunc("/api/tcp/connection/", s.handleTCPConnectionState)

	// 网络性能分析相关
	s.mux.HandleFunc("/api/performance", s.handlePerformanceData)
	s.mux.HandleFunc("/api/performance/connection/", s.handleConnectionPerformance)
	s.mux.HandleFunc("/api/performance/export", s.handlePerformanceExport)
	s.mux.HandleFunc("/api/performance/report", s.handlePerformanceReport)
	
	// 教育功能相关
	s.mux.HandleFunc("/api/education/layers", s.handleLayerModel)
	s.mux.HandleFunc("/api/education/packet-journey", s.handlePacketJourney)

	// WebSocket相关
	s.mux.HandleFunc("/ws", s.handleWebSocket)
	s.mux.HandleFunc("/api/ws/status", s.handleWSStatus)

	// 静态文件服务
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static/"))))
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NetFlow Lens</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 40px; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card { background: white; padding: 25px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #0056b3; }
        .btn-secondary { background: #6c757d; }
        .btn-success { background: #28a745; }
        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .status-running { background: #28a745; }
        .status-stopped { background: #dc3545; }
        .upload-area { border: 2px dashed #ddd; padding: 40px; text-align: center; border-radius: 8px; margin: 20px 0; }
        .upload-area:hover { border-color: #007bff; background: #f8f9fa; }
        input[type="file"] { display: none; }
        .file-info { background: #f8f9fa; padding: 15px; border-radius: 6px; margin: 10px 0; }

        /* TCP状态可视化样式 */
        .tcp-visualization { position: relative; width: 100%; height: 400px; border: 1px solid #ddd; border-radius: 8px; background: #fff; overflow: hidden; }
        .state-node { cursor: pointer; transition: all 0.3s ease; opacity: 0.3; }
        .state-node:hover { opacity: 1 !important; }
        .state-arrow { stroke: #666; stroke-width: 2; fill: none; }
        .state-label { font-size: 10px; font-weight: bold; text-anchor: middle; fill: #333; }
        
        /* TCP状态颜色 */
        .state-closed { background: #6c757d; }
        .state-syn-sent { background: #ffc107; }
        .state-syn-received { background: #fd7e14; }
        .state-established { background: #28a745; }
        .state-fin-wait { background: #dc3545; }
        .state-reset { background: #e83e8c; }
        .state-active { background: #17a2b8; }
        .state-unknown { background: #6c757d; }

        .tcp-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 20px; }
        .stat-item { text-align: center; padding: 10px; background: #f8f9fa; border-radius: 6px; }
        .stat-number { font-size: 24px; font-weight: bold; color: #007bff; }
        .stat-label { font-size: 12px; color: #666; }

        .connection-list { max-height: 300px; overflow-y: auto; }
        .connection-item { padding: 10px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .connection-info { flex: 1; }
        .connection-state { padding: 4px 8px; border-radius: 4px; font-size: 11px; color: white; }

        /* 交互功能样式 */
        .tooltip { position: absolute; background: rgba(0,0,0,0.9); color: white; padding: 8px 12px; border-radius: 6px; font-size: 12px; pointer-events: none; z-index: 1000; max-width: 250px; box-shadow: 0 2px 8px rgba(0,0,0,0.3); }
        .tooltip::after { content: ''; position: absolute; top: 100%; left: 50%; margin-left: -5px; border: 5px solid transparent; border-top-color: rgba(0,0,0,0.9); }
        
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }
        .modal-content { background-color: #fefefe; margin: 10% auto; padding: 20px; border-radius: 8px; width: 80%; max-width: 600px; max-height: 70vh; overflow-y: auto; }
        .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: black; }
        
        .state-detail { margin: 15px 0; }
        .state-detail h4 { margin: 10px 0 5px 0; color: #333; }
        .state-detail .connection-item { background: #f8f9fa; margin: 5px 0; border-radius: 4px; }
        
        .transition-info { background: #e3f2fd; padding: 10px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #2196f3; }
        .transition-conditions { font-size: 11px; color: #666; margin-top: 5px; }
        
        .state-node.selected { stroke: #ff6b35; stroke-width: 3; filter: drop-shadow(0 0 8px rgba(255,107,53,0.6)); }
        .state-node.pulse { animation: pulse 2s infinite; }
        
        @keyframes pulse { 0% { opacity: 0.3; } 50% { opacity: 1; } 100% { opacity: 0.3; } }
        @keyframes stateTransition { 0% { transform: scale(1); } 50% { transform: scale(1.3); } 100% { transform: scale(1); } }
        
        /* 性能分析样式 */
        .performance-actions { margin-bottom: 20px; text-align: right; }
        .performance-actions button { margin-left: 10px; }
        .performance-overview { margin-bottom: 20px; }
        .performance-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .metric-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; position: relative; transition: all 0.3s ease; }
        .metric-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .metric-value { font-size: 28px; font-weight: bold; color: #007bff; margin-bottom: 5px; }
        .metric-label { font-size: 14px; color: #666; margin-bottom: 8px; }
        .metric-trend { font-size: 12px; font-weight: bold; position: absolute; top: 10px; right: 10px; padding: 2px 6px; border-radius: 4px; }
        .metric-trend.positive { background: #d4edda; color: #155724; }
        .metric-trend.negative { background: #f8d7da; color: #721c24; }
        .metric-trend.neutral { background: #e2e3e5; color: #383d41; }
        
        .performance-charts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .chart-container { background: #f8f9fa; padding: 15px; border-radius: 8px; }
        .chart-container h4 { margin: 0 0 10px 0; color: #333; font-size: 16px; }
        .chart-container canvas { width: 100%; height: 150px; }
        
        .performance-alerts { margin-bottom: 20px; }
        .alert-item { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 4px solid #f39c12; }
        .alert-item.critical { background: #f8d7da; border-color: #f5c6cb; border-left-color: #dc3545; }
        .alert-item.warning { background: #fff3cd; border-color: #ffeaa7; border-left-color: #f39c12; }
        .alert-item.info { background: #d1ecf1; border-color: #bee5eb; border-left-color: #17a2b8; }
        
        .performance-table { overflow-x: auto; }
        .performance-table table { width: 100%; border-collapse: collapse; }
        .performance-table th, .performance-table td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .performance-table th { background: #f8f9fa; font-weight: bold; }
        .performance-table tr:hover { background: #f8f9fa; }
        
        .grade-a { color: #28a745; font-weight: bold; }
        .grade-b { color: #6f42c1; font-weight: bold; }
        .grade-c { color: #fd7e14; font-weight: bold; }
        .grade-d { color: #dc3545; font-weight: bold; }
        .grade-f { color: #dc3545; font-weight: bold; background: #f8d7da; padding: 2px 4px; border-radius: 3px; }
        
        .status-good { color: #28a745; }
        .status-warning { color: #fd7e14; }
        .status-critical { color: #dc3545; }
        
        /* 性能报告样式 */
        .report-metadata { background: #f8f9fa; padding: 15px; border-radius: 6px; margin-bottom: 20px; }
        .executive-summary { margin-bottom: 20px; }
        .summary-grid, .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 10px 0; }
        .summary-item, .metric-item { background: #e9ecef; padding: 8px; border-radius: 4px; }
        .health-excellent { color: #28a745; font-weight: bold; }
        .health-good { color: #17a2b8; font-weight: bold; }
        .health-fair { color: #ffc107; font-weight: bold; }
        .health-poor { color: #dc3545; font-weight: bold; }
        .health-unknown { color: #6c757d; font-weight: bold; }
        .top-issues, .recommendations, .quality-distribution { margin-bottom: 20px; }
        .grade-breakdown { display: flex; flex-wrap: wrap; gap: 10px; }
        .grade-item { padding: 8px 12px; border-radius: 20px; font-size: 12px; }
        
        /* 网络分层模型样式 */
        .layer-model-controls { margin-bottom: 20px; text-align: center; }
        .layer-model-controls button { margin: 0 10px; }
        .layer-model-visualization { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .layer-model { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        .packet-journey { background: #e3f2fd; padding: 20px; border-radius: 8px; }
        
        .layer-item { 
            background: #fff; 
            margin: 10px 0; 
            padding: 15px; 
            border-radius: 6px; 
            border-left: 4px solid #007bff;
            position: relative;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .layer-item:hover { transform: translateX(5px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .layer-item.active { 
            border-left-color: #28a745; 
            background: #e8f5e8;
            animation: layerPulse 2s infinite;
        }
        .layer-item.processing { 
            border-left-color: #ffc107; 
            background: #fff3cd;
        }
        
        .layer-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .layer-name { font-weight: bold; color: #333; }
        .layer-level { background: #007bff; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
        .layer-description { font-size: 14px; color: #666; margin-bottom: 10px; }
        .layer-protocols { display: flex; flex-wrap: wrap; gap: 5px; }
        .protocol-tag { 
            background: #e9ecef; 
            padding: 2px 6px; 
            border-radius: 4px; 
            font-size: 11px; 
            color: #495057;
        }
        .protocol-tag.encrypted { background: #d4edda; color: #155724; }
        
        .layer-stats { 
            display: grid; 
            grid-template-columns: repeat(3, 1fr); 
            gap: 10px; 
            margin-top: 10px; 
            padding-top: 10px; 
            border-top: 1px solid #dee2e6;
        }
        .layer-stat { text-align: center; }
        .layer-stat-value { font-weight: bold; color: #007bff; }
        .layer-stat-label { font-size: 11px; color: #666; }
        
        .packet-flow { margin: 20px 0; }
        .packet-flow-step { 
            background: #fff; 
            margin: 10px 0; 
            padding: 12px; 
            border-radius: 4px; 
            border-left: 3px solid #28a745;
            position: relative;
        }
        .packet-flow-step.current { 
            border-left-color: #ffc107; 
            background: #fff3cd;
            animation: stepHighlight 1s ease-in-out;
        }
        .packet-flow-step.completed { 
            border-left-color: #6c757d; 
            background: #f8f9fa; 
            opacity: 0.7;
        }
        
        .step-header { font-weight: bold; margin-bottom: 5px; }
        .step-operation { font-size: 13px; color: #666; margin: 3px 0; }
        .step-result { font-size: 12px; color: #28a745; background: #d4edda; padding: 2px 6px; border-radius: 3px; display: inline-block; }
        .step-duration { font-size: 11px; color: #999; float: right; }
        
        .encapsulation-view { margin: 20px 0; }
        .encapsulation-step { 
            background: #fff; 
            margin: 15px 0; 
            padding: 15px; 
            border-radius: 6px; 
            border: 1px solid #dee2e6;
        }
        .encapsulation-before, .encapsulation-after { 
            background: #f8f9fa; 
            padding: 10px; 
            border-radius: 4px; 
            margin: 5px 0; 
            font-family: monospace; 
            font-size: 12px;
        }
        .encapsulation-arrow { 
            text-align: center; 
            margin: 10px 0; 
            font-size: 20px; 
            color: #007bff;
        }
        
        .header-fields { margin: 10px 0; }
        .header-field { 
            display: inline-block; 
            background: #e9ecef; 
            padding: 4px 8px; 
            margin: 2px; 
            border-radius: 4px; 
            font-size: 11px;
        }
        .header-field.important { background: #fff3cd; border: 1px solid #ffc107; }
        
        @keyframes layerPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        @keyframes stepHighlight {
            0% { background: #fff3cd; }
            100% { background: #fff; }
        }
        
        .animation-controls { text-align: center; margin: 20px 0; }
        .animation-speed { margin: 0 10px; }
        
        @media (max-width: 768px) {
            .performance-charts { grid-template-columns: 1fr; }
            .performance-metrics { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
            .summary-grid, .metrics-grid { grid-template-columns: 1fr; }
            .layer-model-visualization { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 NetFlow Lens</h1>
            <p>网络流量可视化学习工具 - 现在支持真实数据包分析！</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>📊 系统状态</h3>
                <p><span class="status-indicator status-running"></span>服务器运行正常</p>
                <p><span class="status-indicator status-stopped" id="ws-status-indicator"></span>WebSocket连接状态</p>
                <p><a href="/api/status" class="btn">查看API状态</a></p>
                <p><a href="/api/connections" class="btn btn-secondary">查看连接</a></p>
            </div>
            
            <div class="card">
                <h3>🔍 实时捕获</h3>
                <p>从网络接口实时捕获数据包</p>
                <button class="btn btn-success" onclick="startCapture()">开始捕获</button>
                <button class="btn" onclick="stopCapture()">停止捕获</button>
                <div id="capture-status"></div>
            </div>
            
            <div class="card">
                <h3>📁 PCAP文件分析</h3>
                <p>上传并分析PCAP文件</p>
                <div class="upload-area" onclick="document.getElementById('pcap-file').click()">
                    <p>点击选择PCAP文件或拖拽到此处</p>
                    <input type="file" id="pcap-file" accept=".pcap,.cap,.pcapng" onchange="uploadPCAP(this)">
                </div>
                <div id="file-list"></div>
            </div>
        </div>
        
        <div class="card">
            <h3>🔗 TCP状态可视化</h3>
            <div class="tcp-visualization" id="tcp-state-diagram">
                <svg width="100%" height="100%" id="tcp-state-svg">
                    <!-- TCP状态节点 -->
                    <g id="state-nodes">
                        <circle cx="100" cy="60" r="30" class="state-node state-closed" id="closed-state"/>
                        <text x="100" y="66" class="state-label">CLOSED</text>
                        
                        <circle cx="250" cy="60" r="30" class="state-node state-syn-sent" id="syn-sent-state"/>
                        <text x="250" y="66" class="state-label">SYN_SENT</text>
                        
                        <circle cx="400" cy="60" r="30" class="state-node state-syn-received" id="syn-received-state"/>
                        <text x="400" y="66" class="state-label">SYN_RECV</text>
                        
                        <circle cx="550" cy="60" r="30" class="state-node state-established" id="established-state"/>
                        <text x="550" y="66" class="state-label">ESTAB</text>
                        
                        <circle cx="400" cy="200" r="30" class="state-node state-fin-wait" id="fin-wait-state"/>
                        <text x="400" y="206" class="state-label">FIN_WAIT</text>
                        
                        <circle cx="250" cy="200" r="30" class="state-node state-reset" id="reset-state"/>
                        <text x="250" y="206" class="state-label">RESET</text>
                    </g>
                    
                    <!-- 状态转换箭头 -->
                    <g id="state-arrows">
                        <path d="M 130 60 Q 190 40 220 60" class="state-arrow" marker-end="url(#arrowhead)"/>
                        <path d="M 280 60 Q 340 40 370 60" class="state-arrow" marker-end="url(#arrowhead)"/>
                        <path d="M 430 60 Q 490 40 520 60" class="state-arrow" marker-end="url(#arrowhead)"/>
                        <path d="M 550 90 Q 550 150 430 200" class="state-arrow" marker-end="url(#arrowhead)"/>
                        <path d="M 370 200 Q 310 180 280 200" class="state-arrow" marker-end="url(#arrowhead)"/>
                    </g>
                    
                    <!-- 箭头标记定义 -->
                    <defs>
                        <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                            <polygon points="0 0, 10 3.5, 0 7" fill="#666"/>
                        </marker>
                    </defs>
                </svg>
            </div>
            
            <div class="tcp-stats" id="tcp-stats">
                <div class="stat-item">
                    <div class="stat-number" id="active-connections">0</div>
                    <div class="stat-label">活跃连接</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" id="established-count">0</div>
                    <div class="stat-label">已建立</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" id="syn-sent-count">0</div>
                    <div class="stat-label">SYN发送</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" id="transitions-count">0</div>
                    <div class="stat-label">状态转换</div>
                </div>
            </div>
            
            <div class="connection-list" id="connection-list">
                <h4>活跃TCP连接</h4>
                <div id="tcp-connections">
                    <p>暂无活跃的TCP连接...</p>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>📊 网络性能分析</h3>
            <div class="performance-actions">
                <button class="btn" onclick="exportPerformanceData('csv')">导出CSV</button>
                <button class="btn btn-secondary" onclick="exportPerformanceData('json')">导出JSON</button>
                <button class="btn btn-success" onclick="generatePerformanceReport()">生成报告</button>
            </div>
            <div class="performance-overview" id="performance-overview">
                <div class="performance-metrics">
                    <div class="metric-card">
                        <div class="metric-value" id="avg-latency">0ms</div>
                        <div class="metric-label">平均延迟</div>
                        <div class="metric-trend" id="latency-trend">0%</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="avg-throughput">0 Mbps</div>
                        <div class="metric-label">平均吞吐量</div>
                        <div class="metric-trend" id="throughput-trend">0%</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="packet-loss">0%</div>
                        <div class="metric-label">丢包率</div>
                        <div class="metric-trend" id="packet-loss-trend">0%</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="active-connections-perf">0</div>
                        <div class="metric-label">活跃连接</div>
                        <div class="metric-trend" id="connections-trend">0%</div>
                    </div>
                </div>
                
                <div class="performance-charts">
                    <div class="chart-container">
                        <h4>延迟趋势</h4>
                        <canvas id="latency-chart" width="400" height="200"></canvas>
                    </div>
                    <div class="chart-container">
                        <h4>吞吐量趋势</h4>
                        <canvas id="throughput-chart" width="400" height="200"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="performance-alerts" id="performance-alerts">
                <h4>性能警告</h4>
                <div id="alert-list">
                    <p>暂无性能警告...</p>
                </div>
            </div>
            
            <div class="connection-performance" id="connection-performance">
                <h4>连接性能排行</h4>
                <div class="performance-table">
                    <table id="performance-table">
                        <thead>
                            <tr>
                                <th>连接</th>
                                <th>延迟</th>
                                <th>吞吐量</th>
                                <th>丢包率</th>
                                <th>质量评分</th>
                                <th>状态</th>
                            </tr>
                        </thead>
                        <tbody id="performance-table-body">
                            <tr>
                                <td colspan="6">暂无性能数据...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>🎓 网络分层模型学习</h3>
            <div class="layer-model-controls">
                <button class="btn" onclick="switchLayerModel('TCP_IP')">TCP/IP模型</button>
                <button class="btn btn-secondary" onclick="switchLayerModel('OSI')\">OSI模型</button>
                <button class="btn btn-success" onclick="togglePacketAnimation()">开启/关闭动画</button>
            </div>
            <div class="layer-model-visualization" id="layer-model-container">
                <div class="layer-model" id="layer-model">
                    <!-- 动态渲染网络分层模型 -->
                </div>
                <div class="packet-journey" id="packet-journey">
                    <h4>数据包处理过程</h4>
                    <div id="packet-processing-steps"></div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>📈 数据包列表</h3>
            <div id="packet-list">
                <p>开始捕获或加载PCAP文件来查看数据包...</p>
            </div>
        </div>
    </div>

    <!-- Tooltip 组件 -->
    <div id="tooltip" class="tooltip" style="display: none;"></div>

    <!-- 状态详情模态框 -->
    <div id="state-modal" class="modal">
        <div class="modal-content">
            <span class="close" id="modal-close">&times;</span>
            <div id="modal-content-body">
                <!-- 动态内容将在这里显示 -->
            </div>
        </div>
    </div>

    <script>
        async function startCapture() {
            try {
                const response = await fetch('/api/capture/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ interface: 'en0' })
                });
                const result = await response.json();
                document.getElementById('capture-status').innerHTML = 
                    '<div class="file-info">捕获状态: ' + result.message + '</div>';
                startPacketUpdates();
            } catch (error) {
                alert('启动捕获失败: ' + error.message);
            }
        }

        async function stopCapture() {
            try {
                const response = await fetch('/api/capture/stop', { method: 'POST' });
                const result = await response.json();
                document.getElementById('capture-status').innerHTML = 
                    '<div class="file-info">捕获状态: ' + result.message + '</div>';
            } catch (error) {
                alert('停止捕获失败: ' + error.message);
            }
        }

        async function uploadPCAP(input) {
            const file = input.files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append('pcap', file);

            try {
                const response = await fetch('/api/pcap/upload', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                alert('文件上传成功: ' + result.filename);
                loadPCAPList();
            } catch (error) {
                alert('文件上传失败: ' + error.message);
            }
        }

        async function loadPCAPList() {
            try {
                const response = await fetch('/api/pcap/list');
                const files = await response.json();
                let html = '<h4>已上传的PCAP文件:</h4>';
                files.forEach(file => {
                    html += '<div class="file-info">';
                    html += '<strong>' + file.filename + '</strong> ';
                    html += '(' + Math.round(file.size/1024) + 'KB, ' + file.packet_count + ' packets) ';
                    html += '<button class="btn" onclick="loadPCAP(\'' + file.filename + '\')">加载</button>';
                    html += '</div>';
                });
                document.getElementById('file-list').innerHTML = html;
            } catch (error) {
                console.error('加载文件列表失败:', error);
            }
        }

        async function loadPCAP(filename) {
            try {
                const response = await fetch('/api/pcap/load', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filename: filename })
                });
                const result = await response.json();
                alert('PCAP文件加载成功');
                startPacketUpdates();
            } catch (error) {
                alert('加载PCAP文件失败: ' + error.message);
            }
        }


        // TCP状态可视化相关函数
        async function updateTCPVisualization() {
            try {
                const response = await fetch('/api/tcp/visualization');
                const data = await response.json();
                
                // 检查状态转换动画
                checkForStateTransitions(data);
                
                // 保存当前数据
                currentTCPData = data;
                
                // 更新状态统计
                updateTCPStats(data.state_statistics);
                
                // 更新活跃连接列表
                updateTCPConnections(data.active_connections);
                
                // 更新状态节点的活跃状态
                updateStateNodes(data.state_statistics);
                
                // 更新转换计数
                document.getElementById('transitions-count').textContent = data.recent_transitions.length;
                
            } catch (error) {
                console.error('更新TCP状态可视化失败:', error);
            }
        }
        
        function updateTCPStats(stateStats) {
            const totalActive = Object.values(stateStats).reduce((sum, count) => sum + count, 0);
            document.getElementById('active-connections').textContent = totalActive;
            document.getElementById('established-count').textContent = stateStats['ESTABLISHED'] || 0;
            document.getElementById('syn-sent-count').textContent = stateStats['SYN_SENT'] || 0;
        }
        
        function updateTCPConnections(connections) {
            const container = document.getElementById('tcp-connections');
            
            if (connections.length === 0) {
                container.innerHTML = '<p>暂无活跃的TCP连接...</p>';
                return;
            }
            
            let html = '';
            connections.forEach(conn => {
                const stateClass = getStateClass(conn.current_state);
                html += '<div class="connection-item">' +
                    '<div class="connection-info">' +
                    '<strong>' + conn.connection.source_ip + ':' + conn.connection.source_port + ' → ' + conn.connection.dest_ip + ':' + conn.connection.dest_port + '</strong><br>' +
                    '<small>持续时间: ' + Math.round(conn.duration) + 's | 数据包: ' + conn.packet_count + '</small>' +
                    '</div>' +
                    '<div class="connection-state ' + stateClass + '">' + conn.current_state + '</div>' +
                    '</div>';
            });
            
            container.innerHTML = html;
        }
        
        function updateStateNodes(stateStats) {
            // 重置所有状态节点的活跃状态
            document.querySelectorAll('.state-node').forEach(node => {
                node.style.opacity = '0.3';
                node.style.transform = 'scale(1)';
            });
            
            // 根据统计数据高亮活跃状态
            Object.entries(stateStats).forEach(([state, count]) => {
                if (count > 0) {
                    const nodeId = getStateNodeId(state);
                    const node = document.getElementById(nodeId);
                    if (node) {
                        node.style.opacity = '1';
                        node.style.transform = 'scale(' + Math.min(1.5, 1 + count * 0.1) + ')';
                    }
                }
            });
        }
        
        function getStateClass(state) {
            const stateClasses = {
                'CLOSED': 'state-closed',
                'SYN_SENT': 'state-syn-sent',
                'SYN_RECEIVED': 'state-syn-received',
                'ESTABLISHED': 'state-established',
                'FIN_WAIT': 'state-fin-wait',
                'RESET': 'state-reset'
            };
            return stateClasses[state] || 'state-unknown';
        }
        
        function getStateNodeId(state) {
            const nodeIds = {
                'CLOSED': 'closed-state',
                'SYN_SENT': 'syn-sent-state',
                'SYN_RECEIVED': 'syn-received-state',
                'ESTABLISHED': 'established-state',
                'FIN_WAIT': 'fin-wait-state',
                'RESET': 'reset-state'
            };
            return nodeIds[state];
        }
        
        function startTCPVisualizationUpdates() {
            // 如果WebSocket连接正常，则不需要轮询
            setInterval(function() {
                if (!wsConnected) {
                    // 只有在WebSocket未连接时才使用HTTP轮询
                    updateTCPVisualization();
                }
            }, 2000);
        }

        function startPacketUpdates() {
            setInterval(async () => {
                try {
                    const response = await fetch('/api/packets?limit=20');
                    const packets = await response.json();
                    let html = '<table border="1" style="width:100%; border-collapse: collapse;">';
                    html += '<tr><th>时间</th><th>协议</th><th>源地址</th><th>目标地址</th><th>长度</th><th>TCP标志</th></tr>';
                    packets.forEach(packet => {
                        html += '<tr>';
                        html += '<td>' + new Date(packet.timestamp).toLocaleTimeString() + '</td>';
                        html += '<td>' + packet.protocol + '</td>';
                        html += '<td>' + packet.source_ip + ':' + (packet.source_port || '') + '</td>';
                        html += '<td>' + packet.dest_ip + ':' + (packet.dest_port || '') + '</td>';
                        html += '<td>' + packet.length + '</td>';
                        html += '<td>' + (packet.tcp_flags ? packet.tcp_flags.join(',') : '') + '</td>';
                        html += '</tr>';
                    });
                    html += '</table>';
                    document.getElementById('packet-list').innerHTML = html;
                } catch (error) {
                    console.error('更新数据包列表失败:', error);
                }
            }, 2000);
            
            // 同时启动TCP状态可视化更新
            startTCPVisualizationUpdates();
        }

        // 全局变量存储当前的TCP数据
        let currentTCPData = null;
        let lastStateTransitions = [];
        
        // WebSocket相关变量
        let ws = null;
        let wsReconnectTimer = null;
        let wsConnected = false;
        let wsReconnectAttempts = 0;
        const wsMaxReconnectAttempts = 5;
        
        // 性能分析相关变量
        let currentPerformanceData = null;
        let latencyChart = null;
        let throughputChart = null;
        let lastPerformanceUpdate = null;

        // TCP状态信息配置
        const stateInfoMap = {
            'CLOSED': {
                description: 'TCP连接的初始状态和最终状态',
                transitions: '→ SYN_SENT (发送SYN)',
                conditions: '客户端调用connect()或服务器端口关闭'
            },
            'SYN_SENT': {
                description: '客户端发送SYN后等待服务器响应',
                transitions: '→ SYN_RECEIVED (收到SYN+ACK)',
                conditions: 'SYN标志位被设置，等待SYN+ACK回应'
            },
            'SYN_RECEIVED': {
                description: '服务器收到SYN，发送SYN+ACK后的状态',
                transitions: '→ ESTABLISHED (收到ACK)',
                conditions: 'SYN和ACK标志位被设置，等待最后的ACK'
            },
            'ESTABLISHED': {
                description: 'TCP连接已建立，可以传输数据',
                transitions: '→ FIN_WAIT (发送FIN) 或 → RESET (发送RST)',
                conditions: '只有ACK标志位，可以正常传输数据'
            },
            'FIN_WAIT': {
                description: '发起关闭连接，等待对方确认',
                transitions: '→ CLOSED (收到ACK)',
                conditions: 'FIN标志位被设置，开始连接关闭流程'
            },
            'RESET': {
                description: '连接被重置，立即关闭',
                transitions: '→ CLOSED (立即)',
                conditions: 'RST标志位被设置，强制关闭连接'
            }
        };

        // Tooltip 功能
        function showTooltip(event, content) {
            const tooltip = document.getElementById('tooltip');
            tooltip.innerHTML = content;
            tooltip.style.display = 'block';
            
            // 计算位置
            const rect = event.target.getBoundingClientRect();
            tooltip.style.left = (rect.left + rect.width / 2 - tooltip.offsetWidth / 2) + 'px';
            tooltip.style.top = (rect.top - tooltip.offsetHeight - 10) + 'px';
        }

        function hideTooltip() {
            document.getElementById('tooltip').style.display = 'none';
        }

        // 状态节点点击事件
        function onStateNodeClick(state) {
            if (!currentTCPData) return;
            
            // 高亮选中的状态节点
            document.querySelectorAll('.state-node').forEach(node => {
                node.classList.remove('selected');
            });
            
            const nodeId = getStateNodeId(state);
            const selectedNode = document.getElementById(nodeId);
            if (selectedNode) {
                selectedNode.classList.add('selected');
            }
            
            // 显示状态详情模态框
            showStateDetailModal(state);
        }

        // 显示状态详情模态框
        function showStateDetailModal(state) {
            const modal = document.getElementById('state-modal');
            const modalBody = document.getElementById('modal-content-body');
            
            const stateInfo = stateInfoMap[state];
            const stateCount = currentTCPData.state_statistics[state] || 0;
            
            // 获取该状态下的连接
            const connectionsInState = currentTCPData.active_connections.filter(conn => 
                conn.current_state === state
            );
            
            // 获取相关的状态转换
            const relatedTransitions = currentTCPData.recent_transitions.filter(trans => 
                trans.from_state === state || trans.to_state === state
            ).slice(-10); // 最近10个转换
            
            let modalContent = '<h2>TCP状态详情: ' + state + '</h2>';
            
            // 状态基本信息
            if (stateInfo) {
                modalContent += '<div class="transition-info">';
                modalContent += '<h4>状态说明</h4>';
                modalContent += '<p>' + stateInfo.description + '</p>';
                modalContent += '<div class="transition-conditions">';
                modalContent += '<strong>转换条件:</strong> ' + stateInfo.conditions + '<br>';
                modalContent += '<strong>可能转换:</strong> ' + stateInfo.transitions;
                modalContent += '</div>';
                modalContent += '</div>';
            }
            
            // 当前统计
            modalContent += '<div class="state-detail">';
            modalContent += '<h4>当前统计</h4>';
            modalContent += '<p>处于 ' + state + ' 状态的连接数: <strong>' + stateCount + '</strong></p>';
            modalContent += '</div>';
            
            // 活跃连接列表
            if (connectionsInState.length > 0) {
                modalContent += '<div class="state-detail">';
                modalContent += '<h4>活跃连接 (' + connectionsInState.length + '个)</h4>';
                connectionsInState.forEach(conn => {
                    modalContent += '<div class="connection-item">';
                    modalContent += '<div class="connection-info">';
                    modalContent += '<strong>' + conn.connection.source_ip + ':' + conn.connection.source_port + 
                                   ' → ' + conn.connection.dest_ip + ':' + conn.connection.dest_port + '</strong><br>';
                    modalContent += '<small>持续时间: ' + Math.round(conn.duration) + 's | ';
                    modalContent += '数据包: ' + conn.packet_count + ' | ';
                    modalContent += '发送: ' + formatBytes(conn.bytes_sent) + ' | ';
                    modalContent += '接收: ' + formatBytes(conn.bytes_received) + '</small>';
                    modalContent += '</div>';
                    modalContent += '</div>';
                });
                modalContent += '</div>';
            }
            
            // 相关状态转换
            if (relatedTransitions.length > 0) {
                modalContent += '<div class="state-detail">';
                modalContent += '<h4>最近状态转换</h4>';
                relatedTransitions.forEach(trans => {
                    modalContent += '<div class="connection-item">';
                    modalContent += '<div class="connection-info">';
                    modalContent += '<strong>' + trans.from_state + ' → ' + trans.to_state + '</strong><br>';
                    modalContent += '<small>' + new Date(trans.timestamp).toLocaleString() + ' | ';
                    modalContent += '触发标志: ' + (trans.trigger_flags || []).join(',') + ' | ';
                    modalContent += trans.packet_info + '</small>';
                    modalContent += '</div>';
                    modalContent += '</div>';
                });
                modalContent += '</div>';
            }
            
            modalBody.innerHTML = modalContent;
            modal.style.display = 'block';
        }

        // 格式化字节数
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        // 初始化交互事件
        function initializeInteractions() {
            // 为每个状态节点添加事件监听器
            Object.keys(stateInfoMap).forEach(state => {
                const nodeId = getStateNodeId(state);
                const node = document.getElementById(nodeId);
                if (node) {
                    // Hover 事件
                    node.addEventListener('mouseenter', function(e) {
                        const stateInfo = stateInfoMap[state];
                        const count = currentTCPData ? (currentTCPData.state_statistics[state] || 0) : 0;
                        const tooltipContent = '<strong>' + state + '</strong><br>' + 
                                             stateInfo.description + '<br>' +
                                             '<small>当前连接数: ' + count + '</small>';
                        showTooltip(e, tooltipContent);
                    });
                    
                    node.addEventListener('mouseleave', hideTooltip);
                    
                    // Click 事件
                    node.addEventListener('click', function() {
                        onStateNodeClick(state);
                    });
                }
            });
            
            // 模态框关闭事件
            document.getElementById('modal-close').addEventListener('click', function() {
                document.getElementById('state-modal').style.display = 'none';
                // 清除选中状态
                document.querySelectorAll('.state-node').forEach(node => {
                    node.classList.remove('selected');
                });
            });
            
            // 点击模态框背景关闭
            document.getElementById('state-modal').addEventListener('click', function(e) {
                if (e.target === this) {
                    this.style.display = 'none';
                    document.querySelectorAll('.state-node').forEach(node => {
                        node.classList.remove('selected');
                    });
                }
            });
        }

        // 更新TCP可视化数据时检查状态转换动画
        function checkForStateTransitions(newData) {
            if (!currentTCPData) return;
            
            const newTransitions = newData.recent_transitions || [];
            const lastTransition = newTransitions[newTransitions.length - 1];
            
            if (lastTransition && 
                (!lastStateTransitions.length || 
                 lastTransition.timestamp !== lastStateTransitions[lastStateTransitions.length - 1]?.timestamp)) {
                
                // 触发状态转换动画
                animateStateTransition(lastTransition.from_state, lastTransition.to_state);
            }
            
            lastStateTransitions = [...newTransitions];
        }

        // 状态转换动画
        function animateStateTransition(fromState, toState) {
            const fromNodeId = getStateNodeId(fromState);
            const toNodeId = getStateNodeId(toState);
            
            const fromNode = document.getElementById(fromNodeId);
            const toNode = document.getElementById(toNodeId);
            
            if (fromNode && toNode) {
                // 添加脉冲动画
                fromNode.classList.add('pulse');
                toNode.classList.add('pulse');
                
                // 2秒后移除动画
                setTimeout(() => {
                    fromNode.classList.remove('pulse');
                    toNode.classList.remove('pulse');
                }, 2000);
            }
        }

        // WebSocket连接管理
        function connectWebSocket() {
            if (ws && ws.readyState === WebSocket.CONNECTING) {
                return; // 避免重复连接
            }
            
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/ws';
            
            try {
                ws = new WebSocket(wsUrl);
                
                ws.onopen = function(event) {
                    console.log('WebSocket连接已建立');
                    wsConnected = true;
                    wsReconnectAttempts = 0;
                    updateConnectionStatus(true);
                    
                    // 清除重连定时器
                    if (wsReconnectTimer) {
                        clearTimeout(wsReconnectTimer);
                        wsReconnectTimer = null;
                    }
                };
                
                ws.onmessage = function(event) {
                    try {
                        const message = JSON.parse(event.data);
                        handleWebSocketMessage(message);
                    } catch (error) {
                        console.error('解析WebSocket消息失败:', error);
                    }
                };
                
                ws.onclose = function(event) {
                    console.log('WebSocket连接已关闭:', event.code, event.reason);
                    wsConnected = false;
                    updateConnectionStatus(false);
                    
                    // 自动重连
                    if (wsReconnectAttempts < wsMaxReconnectAttempts) {
                        wsReconnectAttempts++;
                        const delay = Math.min(1000 * Math.pow(2, wsReconnectAttempts), 30000);
                        console.log('尝试重连WebSocket，延迟:', delay + 'ms', '尝试次数:', wsReconnectAttempts);
                        
                        wsReconnectTimer = setTimeout(connectWebSocket, delay);
                    } else {
                        console.error('WebSocket重连次数已达上限，停止重连');
                    }
                };
                
                ws.onerror = function(error) {
                    console.error('WebSocket连接错误:', error);
                    wsConnected = false;
                    updateConnectionStatus(false);
                };
                
            } catch (error) {
                console.error('创建WebSocket连接失败:', error);
            }
        }
        
        // 处理WebSocket消息
        function handleWebSocketMessage(message) {
            if (message.type === 'tcp_state_update') {
                // 实时更新TCP状态数据
                const newData = message.data;
                
                // 检查状态转换动画
                checkForStateTransitions(newData);
                
                // 保存当前数据
                currentTCPData = newData;
                
                // 更新可视化界面
                updateTCPStats(newData.state_statistics);
                updateTCPConnections(newData.active_connections);
                updateStateNodes(newData.state_statistics);
                document.getElementById('transitions-count').textContent = newData.recent_transitions.length;
            } else if (message.type === 'performance_update') {
                // 实时更新性能分析数据
                const performanceData = message.data;
                
                // 保存当前数据
                currentPerformanceData = performanceData;
                
                // 更新性能指标卡片
                updatePerformanceMetrics(performanceData.overall_metrics);
                
                // 更新性能图表
                updatePerformanceCharts(performanceData.historical_data);
                
                // 更新性能警告
                updatePerformanceAlerts(performanceData.alert_connections);
                
                // 更新连接性能表格
                updatePerformanceTable(performanceData.top_connections);
            }
        }
        
        // 更新连接状态指示器
        function updateConnectionStatus(connected) {
            const indicator = document.getElementById('ws-status-indicator');
            if (!indicator) return;
            
            if (connected) {
                indicator.className = 'status-indicator status-running';
                indicator.title = 'WebSocket连接正常，实时数据推送活跃';
            } else {
                indicator.className = 'status-indicator status-stopped';
                indicator.title = 'WebSocket连接断开，使用轮询模式';
            }
        }
        
        // 断开WebSocket连接
        function disconnectWebSocket() {
            if (ws) {
                ws.close();
                ws = null;
            }
            if (wsReconnectTimer) {
                clearTimeout(wsReconnectTimer);
                wsReconnectTimer = null;
            }
        }

        // 性能分析相关函数
        async function updatePerformanceAnalysis() {
            try {
                const response = await fetch('/api/performance');
                const data = await response.json();
                
                currentPerformanceData = data;
                
                // 更新性能指标卡片
                updatePerformanceMetrics(data.overall_metrics);
                
                // 更新性能图表
                updatePerformanceCharts(data.historical_data);
                
                // 更新性能警告
                updatePerformanceAlerts(data.alert_connections);
                
                // 更新连接性能表格
                updatePerformanceTable(data.top_connections);
                
            } catch (error) {
                console.error('更新性能分析失败:', error);
            }
        }
        
        function updatePerformanceMetrics(overallMetrics) {
            // 更新平均延迟
            const avgLatency = overallMetrics.avg_latency_ms || 0;
            document.getElementById('avg-latency').textContent = formatLatency(avgLatency);
            
            // 更新平均吞吐量
            const avgThroughput = overallMetrics.avg_throughput_bps || 0;
            document.getElementById('avg-throughput').textContent = formatThroughput(avgThroughput);
            
            // 更新丢包率
            const packetLoss = overallMetrics.overall_packet_loss_rate || 0;
            document.getElementById('packet-loss').textContent = packetLoss.toFixed(2) + '%';
            
            // 更新活跃连接数
            const activeConnections = overallMetrics.active_connections || 0;
            document.getElementById('active-connections-perf').textContent = activeConnections;
            
            // 计算趋势（如果有历史数据）
            if (lastPerformanceUpdate) {
                updateTrends(overallMetrics, lastPerformanceUpdate);
            }
            
            lastPerformanceUpdate = overallMetrics;
        }
        
        function updateTrends(current, previous) {
            // 延迟趋势
            const latencyTrend = calculateTrend(current.avg_latency_ms, previous.avg_latency_ms, true);
            updateTrendIndicator('latency-trend', latencyTrend);
            
            // 吞吐量趋势
            const throughputTrend = calculateTrend(current.avg_throughput_bps, previous.avg_throughput_bps);
            updateTrendIndicator('throughput-trend', throughputTrend);
            
            // 丢包率趋势
            const packetLossTrend = calculateTrend(current.overall_packet_loss_rate, previous.overall_packet_loss_rate, true);
            updateTrendIndicator('packet-loss-trend', packetLossTrend);
            
            // 连接数趋势
            const connectionsTrend = calculateTrend(current.active_connections, previous.active_connections);
            updateTrendIndicator('connections-trend', connectionsTrend);
        }
        
        function calculateTrend(current, previous, inverse = false) {
            if (!previous || previous === 0) return 0;
            
            const change = ((current - previous) / previous) * 100;
            return inverse ? -change : change; // 对于延迟和丢包率，降低是好的
        }
        
        function updateTrendIndicator(elementId, trend) {
            const element = document.getElementById(elementId);
            const trendText = (trend > 0 ? '+' : '') + trend.toFixed(1) + '%';
            
            element.textContent = trendText;
            element.className = 'metric-trend';
            
            if (trend > 5) {
                element.classList.add('positive');
            } else if (trend < -5) {
                element.classList.add('negative');
            } else {
                element.classList.add('neutral');
            }
        }
        
        function updatePerformanceCharts(historicalData) {
            if (!historicalData || historicalData.length === 0) return;
            
            // 获取最近60个数据点
            const recentData = historicalData.slice(-60);
            const labels = recentData.map(d => new Date(d.timestamp).toLocaleTimeString());
            
            // 更新延迟图表
            updateLatencyChart(labels, recentData.map(d => d.avg_latency_ms || 0));
            
            // 更新吞吐量图表
            updateThroughputChart(labels, recentData.map(d => (d.total_throughput_bps || 0) / 1000000)); // 转换为Mbps
        }
        
        function updateLatencyChart(labels, data) {
            const canvas = document.getElementById('latency-chart');
            const ctx = canvas.getContext('2d');
            
            // 清除画布
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            if (data.length === 0) return;
            
            // 绘制简单的折线图
            const maxValue = Math.max(...data) || 100;
            const width = canvas.width;
            const height = canvas.height;
            const padding = 30;
            
            ctx.strokeStyle = '#007bff';
            ctx.lineWidth = 2;
            ctx.beginPath();
            
            for (let i = 0; i < data.length; i++) {
                const x = padding + (i / (data.length - 1)) * (width - 2 * padding);
                const y = height - padding - (data[i] / maxValue) * (height - 2 * padding);
                
                if (i === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            }
            
            ctx.stroke();
            
            // 绘制坐标轴标签
            ctx.fillStyle = '#666';
            ctx.font = '10px Arial';
            ctx.fillText('0ms', 5, height - 5);
            ctx.fillText(maxValue.toFixed(0) + 'ms', 5, 15);
        }
        
        function updateThroughputChart(labels, data) {
            const canvas = document.getElementById('throughput-chart');
            const ctx = canvas.getContext('2d');
            
            // 清除画布
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            if (data.length === 0) return;
            
            // 绘制简单的柱状图
            const maxValue = Math.max(...data) || 10;
            const width = canvas.width;
            const height = canvas.height;
            const padding = 30;
            const barWidth = (width - 2 * padding) / data.length;
            
            ctx.fillStyle = '#28a745';
            
            for (let i = 0; i < data.length; i++) {
                const barHeight = (data[i] / maxValue) * (height - 2 * padding);
                const x = padding + i * barWidth;
                const y = height - padding - barHeight;
                
                ctx.fillRect(x, y, barWidth - 1, barHeight);
            }
            
            // 绘制坐标轴标签
            ctx.fillStyle = '#666';
            ctx.font = '10px Arial';
            ctx.fillText('0 Mbps', 5, height - 5);
            ctx.fillText(maxValue.toFixed(1) + ' Mbps', 5, 15);
        }
        
        function updatePerformanceAlerts(alertConnections) {
            const alertList = document.getElementById('alert-list');
            
            if (!alertConnections || alertConnections.length === 0) {
                alertList.innerHTML = '<p>暂无性能警告...</p>';
                return;
            }
            
            let html = '';
            alertConnections.forEach(conn => {
                const alertLevel = conn.quality_metrics.alert_level;
                const issues = conn.quality_metrics.issues_detected || [];
                const connectionInfo = conn.connection_id;
                
                html += '<div class="alert-item ' + alertLevel + '">';
                html += '<strong>' + connectionInfo + '</strong>';
                html += '<div>评分: ' + (conn.quality_metrics.connection_score?.toFixed(1) || 'N/A') + '/100</div>';
                if (issues.length > 0) {
                    html += '<div>问题: ' + issues.join(', ') + '</div>';
                }
                html += '</div>';
            });
            
            alertList.innerHTML = html;
        }
        
        function updatePerformanceTable(topConnections) {
            const tableBody = document.getElementById('performance-table-body');
            
            if (!topConnections || topConnections.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="6">暂无性能数据...</td></tr>';
                return;
            }
            
            let html = '';
            topConnections.forEach(conn => {
                const latency = conn.latency_metrics.avg_rtt_ms || 0;
                const throughput = (conn.throughput_metrics.upstream_bps + conn.throughput_metrics.downstream_bps) || 0;
                const packetLoss = conn.packet_loss_metrics.packet_loss_rate || 0;
                const score = conn.quality_metrics.connection_score || 0;
                const grade = conn.quality_metrics.performance_grade || 'N/A';
                const alertLevel = conn.quality_metrics.alert_level || 'good';
                
                html += '<tr>';
                html += '<td>' + conn.connection_id + '</td>';
                html += '<td>' + formatLatency(latency) + '</td>';
                html += '<td>' + formatThroughput(throughput) + '</td>';
                html += '<td>' + packetLoss.toFixed(2) + '%</td>';
                html += '<td><span class="grade-' + grade.toLowerCase() + '">' + grade + ' (' + score.toFixed(1) + ')</span></td>';
                html += '<td><span class="status-' + alertLevel + '">' + alertLevel + '</span></td>';
                html += '</tr>';
            });
            
            tableBody.innerHTML = html;
        }
        
        function formatLatency(ms) {
            if (ms < 1) return (ms * 1000).toFixed(0) + 'μs';
            if (ms < 1000) return ms.toFixed(1) + 'ms';
            return (ms / 1000).toFixed(2) + 's';
        }
        
        function formatThroughput(bps) {
            if (bps < 1000) return bps.toFixed(0) + ' bps';
            if (bps < 1000000) return (bps / 1000).toFixed(1) + ' Kbps';
            if (bps < 1000000000) return (bps / 1000000).toFixed(1) + ' Mbps';
            return (bps / 1000000000).toFixed(2) + ' Gbps';
        }
        
        function startPerformanceUpdates() {
            // 如果WebSocket连接正常，则不需要轮询
            setInterval(function() {
                if (!wsConnected) {
                    // 只有在WebSocket未连接时才使用HTTP轮询
                    updatePerformanceAnalysis();
                }
            }, 5000); // 每5秒更新一次性能数据
        }
        
        // 导出性能数据
        function exportPerformanceData(format) {
            const url = '/api/performance/export?format=' + format;
            const link = document.createElement('a');
            link.href = url;
            link.download = 'performance_report.' + format;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        
        // 生成性能报告
        async function generatePerformanceReport() {
            try {
                const response = await fetch('/api/performance/report');
                const report = await response.json();
                
                showPerformanceReport(report);
                
            } catch (error) {
                console.error('生成性能报告失败:', error);
                alert('生成性能报告失败: ' + error.message);
            }
        }
        
        // 显示性能报告模态框
        function showPerformanceReport(report) {
            const modal = document.getElementById('state-modal');
            const modalBody = document.getElementById('modal-content-body');
            
            let modalContent = '<h2>📊 网络性能分析报告</h2>';
            
            // 报告元数据
            modalContent += '<div class="report-metadata">';
            modalContent += '<p><strong>生成时间:</strong> ' + new Date(report.report_metadata.generated_at).toLocaleString() + '</p>';
            modalContent += '<p><strong>报告版本:</strong> ' + report.report_metadata.report_version + '</p>';
            modalContent += '</div>';
            
            // 执行摘要
            modalContent += '<div class="executive-summary">';
            modalContent += '<h3>📋 执行摘要</h3>';
            modalContent += '<div class="summary-grid">';
            modalContent += '<div class="summary-item"><strong>总连接数:</strong> ' + report.executive_summary.total_connections + '</div>';
            modalContent += '<div class="summary-item"><strong>问题连接:</strong> ' + report.executive_summary.problematic_connections + '</div>';
            modalContent += '<div class="summary-item"><strong>平均质量评分:</strong> ' + (report.executive_summary.average_quality_score || 0).toFixed(1) + '/100</div>';
            modalContent += '<div class="summary-item"><strong>性能趋势:</strong> ' + report.executive_summary.performance_trend + '</div>';
            modalContent += '<div class="summary-item"><strong>整体健康度:</strong> <span class="health-' + report.executive_summary.overall_health + '">' + report.executive_summary.overall_health + '</span></div>';
            modalContent += '</div>';
            modalContent += '</div>';
            
            // 关键指标
            modalContent += '<div class="key-metrics">';
            modalContent += '<h3>📈 关键指标</h3>';
            modalContent += '<div class="metrics-grid">';
            modalContent += '<div class="metric-item"><strong>平均延迟:</strong> ' + formatLatency(report.key_metrics.average_latency_ms) + '</div>';
            modalContent += '<div class="metric-item"><strong>平均吞吐量:</strong> ' + formatThroughput(report.key_metrics.average_throughput_bps) + '</div>';
            modalContent += '<div class="metric-item"><strong>丢包率:</strong> ' + (report.key_metrics.packet_loss_rate || 0).toFixed(2) + '%</div>';
            modalContent += '<div class="metric-item"><strong>活跃连接:</strong> ' + report.key_metrics.active_connections + '</div>';
            modalContent += '</div>';
            modalContent += '</div>';
            
            // 主要问题
            if (report.top_issues && report.top_issues.length > 0) {
                modalContent += '<div class="top-issues">';
                modalContent += '<h3>⚠️ 主要问题</h3>';
                modalContent += '<ul>';
                report.top_issues.forEach(issue => {
                    modalContent += '<li><strong>' + issue.issue + '</strong> (' + issue.count + '个连接)</li>';
                });
                modalContent += '</ul>';
                modalContent += '</div>';
            }
            
            // 建议
            if (report.recommendations && report.recommendations.length > 0) {
                modalContent += '<div class="recommendations">';
                modalContent += '<h3>💡 优化建议</h3>';
                modalContent += '<ul>';
                report.recommendations.forEach(rec => {
                    modalContent += '<li>' + rec + '</li>';
                });
                modalContent += '</ul>';
                modalContent += '</div>';
            }
            
            // 质量分布
            if (report.quality_distribution && Object.keys(report.quality_distribution).length > 0) {
                modalContent += '<div class="quality-distribution">';
                modalContent += '<h3>📊 质量分布</h3>';
                modalContent += '<div class="grade-breakdown">';
                Object.entries(report.quality_distribution).forEach(([grade, count]) => {
                    modalContent += '<div class="grade-item grade-' + grade.toLowerCase() + '">' + grade + ': ' + count + '个连接</div>';
                });
                modalContent += '</div>';
                modalContent += '</div>';
            }
            
            modalBody.innerHTML = modalContent;
            modal.style.display = 'block';
        }

        // 网络分层模型相关变量
        let currentLayerModel = null;
        let packetJourneys = [];
        let animationEnabled = false;
        let animationTimer = null;
        let currentModelType = 'TCP_IP';

        // 网络分层模型相关函数
        async function updateLayerModel() {
            try {
                const response = await fetch('/api/education/layers');
                const layerModel = await response.json();
                currentLayerModel = layerModel;
                renderLayerModel(layerModel);
            } catch (error) {
                console.error('更新网络分层模型失败:', error);
            }
        }

        function renderLayerModel(layerModel) {
            const container = document.getElementById('layer-model');
            if (!container || !layerModel) return;

            let html = '<h4>' + layerModel.model_type + ' 网络分层模型</h4>';
            
            // 按层级倒序排列（应用层在顶部）
            const sortedLayers = [...layerModel.layers].sort((a, b) => b.level - a.level);
            
            sortedLayers.forEach(layer => {
                const activeClass = layer.is_active ? 'active' : '';
                const throughput = layer.data_flow ? formatThroughput(layer.data_flow.throughput) : '0 bps';
                
                html += '<div class="layer-item ' + activeClass + '" onclick="showLayerDetails(\'' + layer.id + '\')">';
                html += '<div class="layer-header">';
                html += '<span class="layer-name">' + layer.name + ' (' + layer.english_name + ')</span>';
                html += '<span class="layer-level">L' + layer.level + '</span>';
                html += '</div>';
                html += '<div class="layer-description">' + layer.description + '</div>';
                
                // 协议标签
                if (layer.protocols && layer.protocols.length > 0) {
                    html += '<div class="layer-protocols">';
                    layer.protocols.forEach(protocol => {
                        const encryptedClass = protocol.is_encrypted ? 'encrypted' : '';
                        html += '<span class="protocol-tag ' + encryptedClass + '">' + protocol.name + '</span>';
                    });
                    html += '</div>';
                }
                
                // 层统计信息
                html += '<div class="layer-stats">';
                html += '<div class="layer-stat"><div class="layer-stat-value">' + throughput + '</div><div class="layer-stat-label">吞吐量</div></div>';
                html += '<div class="layer-stat"><div class="layer-stat-value">' + (layer.data_flow ? layer.data_flow.packets_in : 0) + '</div><div class="layer-stat-label">数据包</div></div>';
                html += '<div class="layer-stat"><div class="layer-stat-value">' + formatBytes(layer.data_flow ? layer.data_flow.bytes_in : 0) + '</div><div class="layer-stat-label">字节数</div></div>';
                html += '</div>';
                
                html += '</div>';
            });
            
            container.innerHTML = html;
        }

        async function updatePacketJourney() {
            try {
                const response = await fetch('/api/education/packet-journey?limit=5');
                const journeys = await response.json();
                packetJourneys = journeys;
                renderPacketJourney(journeys);
            } catch (error) {
                console.error('更新数据包处理过程失败:', error);
            }
        }

        function renderPacketJourney(journeys) {
            const container = document.getElementById('packet-processing-steps');
            if (!container || !journeys || journeys.length === 0) {
                container.innerHTML = '<p>暂无数据包处理过程...</p>';
                return;
            }

            const latestJourney = journeys[0];
            let html = '<h5>最新数据包: ' + latestJourney.packet_id + '</h5>';
            html += '<div class="packet-info">';
            html += '<strong>方向:</strong> ' + (latestJourney.direction === 'incoming' ? '接收' : '发送') + '<br>';
            html += '<strong>协议:</strong> ' + latestJourney.original_packet.protocol + '<br>';
            html += '<strong>大小:</strong> ' + latestJourney.original_packet.length + ' bytes<br>';
            html += '<strong>时间:</strong> ' + new Date(latestJourney.start_time).toLocaleTimeString();
            html += '</div>';

            // 渲染处理步骤
            html += '<div class="packet-flow">';
            latestJourney.layer_analysis.forEach((analysis, index) => {
                const currentClass = animationEnabled && index === latestJourney.current_layer - 1 ? 'current' : '';
                const completedClass = index < latestJourney.current_layer - 1 ? 'completed' : '';
                
                html += '<div class="packet-flow-step ' + currentClass + ' ' + completedClass + '">';
                html += '<div class="step-header">' + getLayerName(analysis.layer_id) + ' 处理</div>';
                
                if (analysis.operations && analysis.operations.length > 0) {
                    analysis.operations.forEach(operation => {
                        html += '<div class="step-operation">';
                        html += '🔧 ' + operation.name + ': ' + operation.description;
                        html += '<span class="step-duration">' + operation.duration_ms.toFixed(1) + 'ms</span>';
                        html += '</div>';
                        if (operation.result) {
                            html += '<div class="step-result">' + operation.result + '</div>';
                        }
                    });
                }
                
                if (analysis.header_data && analysis.header_data.length > 0) {
                    html += '<div class="header-fields">';
                    analysis.header_data.forEach(field => {
                        const importantClass = field.is_important ? 'important' : '';
                        html += '<span class="header-field ' + importantClass + '">' + field.name;
                        if (field.value) {
                            html += ': ' + field.value;
                        }
                        html += '</span>';
                    });
                    html += '</div>';
                }
                
                html += '</div>';
            });
            html += '</div>';

            // 渲染封装过程
            if (latestJourney.encapsulation && latestJourney.encapsulation.length > 0) {
                html += '<div class="encapsulation-view">';
                html += '<h5>数据封装过程</h5>';
                latestJourney.encapsulation.forEach(step => {
                    html += '<div class="encapsulation-step">';
                    html += '<strong>' + getLayerName(step.layer_id) + ' 封装</strong>';
                    html += '<div class="encapsulation-before">' + step.before.visualization + '</div>';
                    html += '<div class="encapsulation-arrow">⬇️ 添加 ' + getLayerName(step.layer_id) + ' 首部</div>';
                    html += '<div class="encapsulation-after">' + step.after.visualization + '</div>';
                    html += '</div>';
                });
                html += '</div>';
            }

            container.innerHTML = html;
        }

        function switchLayerModel(modelType) {
            currentModelType = modelType;
            // 这里可以扩展切换到OSI模型
            updateLayerModel();
        }

        function togglePacketAnimation() {
            animationEnabled = !animationEnabled;
            if (animationEnabled) {
                startPacketAnimation();
            } else {
                stopPacketAnimation();
            }
        }

        function startPacketAnimation() {
            if (animationTimer) clearInterval(animationTimer);
            animationTimer = setInterval(() => {
                updatePacketJourney();
            }, 3000); // 每3秒更新一次
        }

        function stopPacketAnimation() {
            if (animationTimer) {
                clearInterval(animationTimer);
                animationTimer = null;
            }
        }

        function showLayerDetails(layerId) {
            if (!currentLayerModel) return;
            
            const layer = currentLayerModel.layers.find(l => l.id === layerId);
            if (!layer) return;
            
            // 显示层详情的模态框
            const modal = document.getElementById('state-modal');
            const modalBody = document.getElementById('modal-content-body');
            
            let modalContent = '<h2>📚 ' + layer.name + ' 详解</h2>';
            modalContent += '<div class="layer-detail-content">';
            modalContent += '<h3>基本信息</h3>';
            modalContent += '<p><strong>英文名称:</strong> ' + layer.english_name + '</p>';
            modalContent += '<p><strong>层级:</strong> 第' + layer.level + '层</p>';
            modalContent += '<p><strong>描述:</strong> ' + layer.description + '</p>';
            
            modalContent += '<h3>主要功能</h3>';
            modalContent += '<ul>';
            layer.functions.forEach(func => {
                modalContent += '<li>' + func + '</li>';
            });
            modalContent += '</ul>';
            
            if (layer.protocols && layer.protocols.length > 0) {
                modalContent += '<h3>常用协议</h3>';
                layer.protocols.forEach(protocol => {
                    modalContent += '<div class="protocol-detail">';
                    modalContent += '<h4>' + protocol.name + ' - ' + protocol.full_name + '</h4>';
                    modalContent += '<p><strong>用途:</strong> ' + protocol.purpose + '</p>';
                    modalContent += '<p><strong>示例:</strong> ' + protocol.example + '</p>';
                    if (protocol.is_encrypted) {
                        modalContent += '<p><span class="encryption-indicator">🔒 提供加密保护</span></p>';
                    }
                    modalContent += '</div>';
                });
            }
            
            if (layer.examples && layer.examples.length > 0) {
                modalContent += '<h3>实际应用</h3>';
                modalContent += '<ul>';
                layer.examples.forEach(example => {
                    modalContent += '<li>' + example + '</li>';
                });
                modalContent += '</ul>';
            }
            
            modalContent += '</div>';
            
            modalBody.innerHTML = modalContent;
            modal.style.display = 'block';
        }

        function getLayerName(layerId) {
            const layerNames = {
                'physical': '物理层',
                'datalink': '数据链路层',
                'network': '网络层',
                'transport': '传输层',
                'application': '应用层'
            };
            return layerNames[layerId] || layerId;
        }

        function startEducationalUpdates() {
            setInterval(function() {
                if (!wsConnected) {
                    updateLayerModel();
                    if (animationEnabled) {
                        updatePacketJourney();
                    }
                }
            }, 5000); // 每5秒更新一次
        }

        // 页面加载时初始化
        window.onload = function() {
            loadPCAPList();
            // 初始加载TCP状态可视化
            updateTCPVisualization();
            // 初始化交互功能
            initializeInteractions();
            // 初始化性能分析
            updatePerformanceAnalysis();
            startPerformanceUpdates();
            // 初始化教育功能
            updateLayerModel();
            updatePacketJourney();
            startEducationalUpdates();
            // 建立WebSocket连接
            connectWebSocket();
        };
        
        // 页面卸载时断开WebSocket
        window.onbeforeunload = function() {
            disconnectWebSocket();
        };
    </script>
</body>
</html>
	`))
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	status := models.APIStatus{
		Status:  "running",
		Version: "0.2.0",
		Message: "NetFlow Lens API with gopacket integration",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	connections := s.analyzer.GetConnections()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connections)
}

func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	packets := s.analyzer.GetRecentPackets(limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(packets)
}

func (s *Server) handleStartCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Interface string `json:"interface"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Interface == "" {
		req.Interface = "en0" // 默认接口
	}

	if err := s.capturer.StartLiveCapture(req.Interface); err != nil {
		response := map[string]string{
			"status":  "error",
			"message": err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	response := map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("开始从接口 %s 捕获数据包", req.Interface),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleStopCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.capturer.Stop()

	response := map[string]interface{}{
		"status":       "success",
		"message":      "数据包捕获已停止",
		"packet_count": s.capturer.GetPacketCount(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleCaptureStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"is_running":   s.capturer.GetPacketCount() > 0,
		"packet_count": s.capturer.GetPacketCount(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleListInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces, err := s.capturer.ListInterfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(interfaces)
}

func (s *Server) handlePCAPUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析multipart form
	err := r.ParseMultipartForm(32 << 20) // 32MB max
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("pcap")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 验证文件扩展名
	filename := header.Filename
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".pcap" && ext != ".cap" && ext != ".pcapng" {
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	// 创建目标文件
	destPath := filepath.Join(s.uploadDir, filename)
	dest, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	// 复制文件内容
	_, err = io.Copy(dest, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// 获取文件信息
	fileInfo, err := capture.GetPCAPFileInfo(destPath)
	if err != nil {
		log.Printf("获取PCAP文件信息失败: %v", err)
		fileInfo = &models.PCAPFileInfo{
			Filename:     filename,
			Size:         header.Size,
			UploadTime:   time.Now(),
			Status:       "error",
			ErrorMessage: err.Error(),
		}
	}

	// 保存文件信息
	s.pcapMutex.Lock()
	s.pcapFiles[filename] = fileInfo
	s.pcapMutex.Unlock()

	response := map[string]interface{}{
		"status":   "success",
		"filename": filename,
		"size":     fileInfo.Size,
		"packets":  fileInfo.PacketCount,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handlePCAPList(w http.ResponseWriter, r *http.Request) {
	s.pcapMutex.RLock()
	defer s.pcapMutex.RUnlock()

	var files []*models.PCAPFileInfo
	for _, info := range s.pcapFiles {
		files = append(files, info)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func (s *Server) handlePCAPLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Filename string `json:"filename"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 停止当前捕获
	s.capturer.Stop()

	// 清空analyzer中的旧数据
	s.analyzer.ClearData()

	// 加载PCAP文件
	filePath := filepath.Join(s.uploadDir, req.Filename)
	if err := s.capturer.StartFileCapture(filePath); err != nil {
		response := map[string]string{
			"status":  "error",
			"message": err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	response := map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("成功加载PCAP文件: %s", req.Filename),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handlePCAPInfo(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	s.pcapMutex.RLock()
	info, exists := s.pcapFiles[filename]
	s.pcapMutex.RUnlock()

	if !exists {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (s *Server) startPacketProcessing() {
	for {
		select {
		case packet := <-s.capturer.GetPackets():
			s.analyzer.ProcessPacket(packet)
		case err := <-s.capturer.GetErrors():
			log.Printf("数据包捕获错误: %v", err)
		}
	}
}

// handleFilters handles CRUD operations for filters
func (s *Server) handleFilters(w http.ResponseWriter, r *http.Request) {
	fm := s.capturer.GetFilterManager()
	
	switch r.Method {
	case http.MethodGet:
		// 获取所有过滤器
		filters := fm.ListFilters()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(filters)
		
	case http.MethodPost:
		// 创建新过滤器
		var rule models.FilterRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		
		if err := fm.AddFilter(&rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rule)
		
	case http.MethodPut:
		// 更新过滤器
		filterID := r.URL.Query().Get("id")
		if filterID == "" {
			http.Error(w, "Filter ID required", http.StatusBadRequest)
			return
		}
		
		var updates models.FilterRule
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		
		if err := fm.UpdateFilter(filterID, &updates); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		
		updated, _ := fm.GetFilter(filterID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
		
	case http.MethodDelete:
		// 删除过滤器
		filterID := r.URL.Query().Get("id")
		if filterID == "" {
			http.Error(w, "Filter ID required", http.StatusBadRequest)
			return
		}
		
		if err := fm.DeleteFilter(filterID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		
		w.WriteHeader(http.StatusNoContent)
		
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleValidateFilter validates a BPF filter expression
func (s *Server) handleValidateFilter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var request struct {
		Expression string `json:"expression"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	fm := s.capturer.GetFilterManager()
	result := fm.ValidateFilter(request.Expression)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleFilterPresets returns preset filter templates
func (s *Server) handleFilterPresets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	fm := s.capturer.GetFilterManager()
	presets := fm.GetPresetFilters()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(presets)
}

// handleActiveFilter manages the active filter
func (s *Server) handleActiveFilter(w http.ResponseWriter, r *http.Request) {
	fm := s.capturer.GetFilterManager()
	
	switch r.Method {
	case http.MethodGet:
		// 获取当前活动过滤器
		activeFilter := fm.GetActiveFilter()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(activeFilter)
		
	case http.MethodPost:
		// 设置活动过滤器
		var request models.FilterRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		
		var response models.FilterResponse
		
		// 如果提供了直接表达式，先验证并可选保存
		if request.Expression != "" {
			validation := fm.ValidateFilter(request.Expression)
			if !validation.IsValid {
				response.Status = "error"
				response.Message = "Invalid filter expression"
				response.ErrorDetails = validation.ErrorMessage
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
				return
			}
			
			// 如果需要保存为新过滤器
			if request.SaveAs != "" {
				rule := &models.FilterRule{
					Name:        request.SaveAs,
					Expression:  request.Expression,
					Description: "Auto-created from API",
					IsActive:    true,
				}
				if err := fm.AddFilter(rule); err != nil {
					response.Status = "error"
					response.Message = "Failed to save filter"
					response.ErrorDetails = err.Error()
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(response)
					return
				}
				request.FilterID = rule.ID
			} else {
				// 创建临时过滤器
				rule := &models.FilterRule{
					ID:          "temp_" + fmt.Sprintf("%d", time.Now().UnixNano()),
					Name:        "Temporary Filter",
					Expression:  request.Expression,
					Description: "Temporary filter from API",
					IsActive:    true,
				}
				fm.AddFilter(rule)
				request.FilterID = rule.ID
			}
		}
		
		// 设置活动过滤器
		if err := fm.SetActiveFilter(request.FilterID); err != nil {
			response.Status = "error"
			response.Message = "Failed to set active filter"
			response.ErrorDetails = err.Error()
		} else {
			response.Status = "success"
			response.Message = "Filter applied successfully"
			response.AppliedRule = fm.GetActiveFilter()
			response.Stats = fm.GetStats()
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		
	case http.MethodDelete:
		// 清除活动过滤器
		fm.SetActiveFilter("")
		
		response := models.FilterResponse{
			Status:  "success",
			Message: "Active filter cleared",
			Stats:   fm.GetStats(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFilterStats returns filter statistics
func (s *Server) handleFilterStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	stats := s.capturer.GetFilterStats()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleTCPVisualization returns TCP state visualization data
func (s *Server) handleTCPVisualization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	data := s.analyzer.GetTCPVisualizationData()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// handleTCPConnectionState returns state information for a specific TCP connection
func (s *Server) handleTCPConnectionState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// 从URL路径中提取connection ID
	path := r.URL.Path
	if !strings.HasPrefix(path, "/api/tcp/connection/") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	connectionID := strings.TrimPrefix(path, "/api/tcp/connection/")
	if connectionID == "" {
		http.Error(w, "Connection ID required", http.StatusBadRequest)
		return
	}
	
	connState, err := s.analyzer.GetTCPConnectionState(connectionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connState)
}

// WebSocket处理器
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}

	// 生成客户端ID
	clientID := fmt.Sprintf("client_%d", time.Now().UnixNano())
	
	client := &WSClient{
		conn:   conn,
		send:   make(chan []byte, 256),
		server: s,
		id:     clientID,
	}

	// 注册客户端
	s.clientMutex.Lock()
	s.clients[clientID] = client
	s.clientMutex.Unlock()

	log.Printf("新的WebSocket客户端连接: %s", clientID)

	// 启动客户端goroutines
	go client.writePump()
	go client.readPump()

	// 立即发送当前TCP状态数据
	s.sendTCPDataToClient(client)
}

// WebSocket客户端写入处理
func (c *WSClient) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// 添加队列中的其他消息
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// WebSocket客户端读取处理
func (c *WSClient) readPump() {
	defer func() {
		c.server.unregisterClient(c.id)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket错误: %v", err)
			}
			break
		}
	}
}

// WebSocket Hub - 管理所有客户端连接
func (s *Server) startWebSocketHub() {
	for {
		select {
		case message := <-s.broadcast:
			s.clientMutex.RLock()
			for _, client := range s.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(s.clients, client.id)
				}
			}
			s.clientMutex.RUnlock()
		}
	}
}

// 注销客户端
func (s *Server) unregisterClient(clientID string) {
	s.clientMutex.Lock()
	defer s.clientMutex.Unlock()
	
	if client, ok := s.clients[clientID]; ok {
		close(client.send)
		delete(s.clients, clientID)
		log.Printf("WebSocket客户端断开连接: %s", clientID)
	}
}

// 向特定客户端发送TCP数据
func (s *Server) sendTCPDataToClient(client *WSClient) {
	data := s.analyzer.GetTCPVisualizationData()
	message := WSMessage{
		Type: "tcp_state_update",
		Data: data,
	}
	
	messageBytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("序列化WebSocket消息失败: %v", err)
		return
	}
	
	select {
	case client.send <- messageBytes:
	default:
		close(client.send)
		s.unregisterClient(client.id)
	}
}

// 广播TCP状态更新到所有客户端
func (s *Server) broadcastTCPStateUpdate() {
	data := s.analyzer.GetTCPVisualizationData()
	message := WSMessage{
		Type: "tcp_state_update",
		Data: data,
	}
	
	messageBytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("序列化广播消息失败: %v", err)
		return
	}
	
	select {
	case s.broadcast <- messageBytes:
	default:
		log.Println("广播通道已满，跳过本次更新")
	}
}

// 广播性能分析更新到所有客户端
func (s *Server) broadcastPerformanceUpdate() {
	data := s.analyzer.GetPerformanceData()
	message := WSMessage{
		Type: "performance_update",
		Data: data,
	}
	
	messageBytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("序列化性能分析广播消息失败: %v", err)
		return
	}
	
	select {
	case s.broadcast <- messageBytes:
	default:
		log.Println("性能分析广播通道已满，跳过本次更新")
	}
}

// 获取WebSocket连接状态
func (s *Server) getWebSocketStatus() map[string]interface{} {
	s.clientMutex.RLock()
	defer s.clientMutex.RUnlock()
	
	return map[string]interface{}{
		"connected_clients": len(s.clients),
		"client_ids":        func() []string {
			ids := make([]string, 0, len(s.clients))
			for id := range s.clients {
				ids = append(ids, id)
			}
			return ids
		}(),
	}
}

// handleWSStatus returns WebSocket connection status
func (s *Server) handleWSStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	status := s.getWebSocketStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handlePerformanceData returns network performance analysis data
func (s *Server) handlePerformanceData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	data := s.analyzer.GetPerformanceData()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// handleConnectionPerformance returns performance metrics for a specific connection
func (s *Server) handleConnectionPerformance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// 从URL路径中提取connection ID
	path := r.URL.Path
	if !strings.HasPrefix(path, "/api/performance/connection/") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	connectionID := strings.TrimPrefix(path, "/api/performance/connection/")
	if connectionID == "" {
		http.Error(w, "Connection ID required", http.StatusBadRequest)
		return
	}
	
	metrics, exists := s.analyzer.GetConnectionPerformanceMetrics(connectionID)
	if !exists {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// handlePerformanceExport exports performance data in various formats
func (s *Server) handlePerformanceExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	
	data := s.analyzer.GetPerformanceData()
	
	switch format {
	case "csv":
		s.exportPerformanceCSV(w, data)
	case "json":
		s.exportPerformanceJSON(w, data)
	default:
		http.Error(w, "Unsupported format", http.StatusBadRequest)
	}
}

func (s *Server) exportPerformanceCSV(w http.ResponseWriter, data models.NetworkPerformanceData) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=performance_report.csv")
	
	// CSV Header
	csvData := "Connection ID,Average Latency (ms),Throughput (bps),Packet Loss (%),Quality Score,Grade,Alert Level,Issues\n"
	
	// Add connection data
	for _, conn := range data.ConnectionMetrics {
		latency := conn.LatencyMetrics.AvgRTT
		throughput := conn.ThroughputMetrics.UpstreamBps + conn.ThroughputMetrics.DownstreamBps
		packetLoss := conn.PacketLossMetrics.PacketLossRate
		score := conn.QualityMetrics.ConnectionScore
		grade := conn.QualityMetrics.PerformanceGrade
		alertLevel := conn.QualityMetrics.AlertLevel
		issues := strings.Join(conn.QualityMetrics.IssuesDetected, "; ")
		
		csvData += fmt.Sprintf("%s,%.2f,%.0f,%.2f,%.1f,%s,%s,\"%s\"\n",
			conn.ConnectionID, latency, throughput, packetLoss, score, grade, alertLevel, issues)
	}
	
	w.Write([]byte(csvData))
}

func (s *Server) exportPerformanceJSON(w http.ResponseWriter, data models.NetworkPerformanceData) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=performance_report.json")
	
	json.NewEncoder(w).Encode(data)
}

// handlePerformanceReport generates a comprehensive performance report
func (s *Server) handlePerformanceReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	data := s.analyzer.GetPerformanceData()
	report := s.generatePerformanceReport(data)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func (s *Server) generatePerformanceReport(data models.NetworkPerformanceData) map[string]interface{} {
	now := time.Now()
	
	// 计算汇总统计
	totalConnections := len(data.ConnectionMetrics)
	problematicConnections := len(data.AlertConnections)
	
	// 计算质量分布
	gradeDistribution := make(map[string]int)
	avgScore := 0.0
	for _, conn := range data.ConnectionMetrics {
		grade := conn.QualityMetrics.PerformanceGrade
		gradeDistribution[grade]++
		avgScore += conn.QualityMetrics.ConnectionScore
	}
	if totalConnections > 0 {
		avgScore /= float64(totalConnections)
	}
	
	// 计算性能趋势
	var performanceTrend string
	if len(data.HistoricalData) >= 2 {
		recent := data.HistoricalData[len(data.HistoricalData)-1]
		previous := data.HistoricalData[len(data.HistoricalData)-2]
		
		if recent.AvgLatency < previous.AvgLatency && recent.PacketLossRate < previous.PacketLossRate {
			performanceTrend = "improving"
		} else if recent.AvgLatency > previous.AvgLatency || recent.PacketLossRate > previous.PacketLossRate {
			performanceTrend = "degrading"
		} else {
			performanceTrend = "stable"
		}
	} else {
		performanceTrend = "insufficient_data"
	}
	
	// 生成建议
	recommendations := s.generateRecommendations(data)
	
	report := map[string]interface{}{
		"report_metadata": map[string]interface{}{
			"generated_at":     now,
			"report_version":   "1.0",
			"analysis_period": "realtime",
		},
		"executive_summary": map[string]interface{}{
			"total_connections":        totalConnections,
			"problematic_connections":  problematicConnections,
			"average_quality_score":    avgScore,
			"performance_trend":        performanceTrend,
			"overall_health":           s.calculateOverallHealth(avgScore, float64(problematicConnections), float64(totalConnections)),
		},
		"quality_distribution": gradeDistribution,
		"key_metrics": map[string]interface{}{
			"average_latency_ms":     data.OverallMetrics.AvgLatency,
			"average_throughput_bps": data.OverallMetrics.AvgThroughput,
			"packet_loss_rate":       data.OverallMetrics.OverallPacketLoss,
			"active_connections":     data.OverallMetrics.ActiveConnections,
		},
		"top_issues": s.getTopIssues(data.AlertConnections),
		"recommendations": recommendations,
		"detailed_analysis": map[string]interface{}{
			"connection_count":     totalConnections,
			"alert_connections":    data.AlertConnections,
			"protocol_breakdown":   data.OverallMetrics.TopProtocols,
			"historical_trend":     data.HistoricalData[max(0, len(data.HistoricalData)-20):], // Last 20 data points
		},
	}
	
	return report
}

func (s *Server) calculateOverallHealth(avgScore, problematicConnections, totalConnections float64) string {
	if totalConnections == 0 {
		return "unknown"
	}
	
	problemRatio := problematicConnections / totalConnections
	
	if avgScore >= 80 && problemRatio < 0.1 {
		return "excellent"
	} else if avgScore >= 70 && problemRatio < 0.2 {
		return "good"
	} else if avgScore >= 60 && problemRatio < 0.3 {
		return "fair"
	} else {
		return "poor"
	}
}

func (s *Server) getTopIssues(alertConnections []models.PerformanceMetrics) []map[string]interface{} {
	issueCount := make(map[string]int)
	
	for _, conn := range alertConnections {
		for _, issue := range conn.QualityMetrics.IssuesDetected {
			issueCount[issue]++
		}
	}
	
	// Convert to sorted list
	type issueInfo struct {
		Issue string `json:"issue"`
		Count int    `json:"count"`
	}
	
	var issues []issueInfo
	for issue, count := range issueCount {
		issues = append(issues, issueInfo{Issue: issue, Count: count})
	}
	
	// Sort by count (descending)
	sort.Slice(issues, func(i, j int) bool {
		return issues[i].Count > issues[j].Count
	})
	
	// Return top 5 issues
	result := make([]map[string]interface{}, 0)
	for i := 0; i < min(5, len(issues)); i++ {
		result = append(result, map[string]interface{}{
			"issue": issues[i].Issue,
			"count": issues[i].Count,
		})
	}
	
	return result
}

func (s *Server) generateRecommendations(data models.NetworkPerformanceData) []string {
	var recommendations []string
	
	// 延迟相关建议
	if data.OverallMetrics.AvgLatency > 200 {
		recommendations = append(recommendations, "网络延迟较高，建议检查网络路由和带宽利用率")
	}
	
	// 丢包相关建议
	if data.OverallMetrics.OverallPacketLoss > 1 {
		recommendations = append(recommendations, "检测到数据包丢失，建议检查网络设备和链路质量")
	}
	
	// 连接质量相关建议
	problemCount := len(data.AlertConnections)
	totalCount := len(data.ConnectionMetrics)
	if totalCount > 0 && float64(problemCount)/float64(totalCount) > 0.2 {
		recommendations = append(recommendations, "超过20%的连接存在性能问题，建议进行网络优化")
	}
	
	// 协议相关建议
	for protocol, stats := range data.OverallMetrics.TopProtocols {
		if stats.PacketLoss > 5 {
			recommendations = append(recommendations, fmt.Sprintf("%s协议的丢包率较高(%.1f%%)，建议检查该协议的配置", protocol, stats.PacketLoss))
		}
	}
	
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "网络性能表现良好，建议继续监控关键指标")
	}
	
	return recommendations
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ==================== Educational API Handlers ====================

// handleLayerModel returns the network layer model for educational visualization
func (s *Server) handleLayerModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	layerModel := s.analyzer.GetLayerModel()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(layerModel)
}

// handlePacketJourney returns packet processing journey for educational purposes
func (s *Server) handlePacketJourney(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Get limit from query parameters
	limitStr := r.URL.Query().Get("limit")
	limit := 10 // default limit
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	
	journeys := s.analyzer.GetPacketJourney(limit)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(journeys)
}
