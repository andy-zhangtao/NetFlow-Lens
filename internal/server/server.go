package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

        // 页面加载时初始化
        window.onload = function() {
            loadPCAPList();
            // 初始加载TCP状态可视化
            updateTCPVisualization();
            // 初始化交互功能
            initializeInteractions();
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
