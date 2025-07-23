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
)

type Server struct {
	mux       *http.ServeMux
	capturer  *capture.Capturer
	analyzer  *analyzer.Analyzer
	pcapFiles map[string]*models.PCAPFileInfo
	pcapMutex sync.RWMutex
	uploadDir string
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
	}
	s.setupRoutes()

	// 启动后台任务处理数据包
	go s.startPacketProcessing()

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
            <h3>📈 数据包列表</h3>
            <div id="packet-list">
                <p>开始捕获或加载PCAP文件来查看数据包...</p>
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
        }

        // 页面加载时初始化
        window.onload = function() {
            loadPCAPList();
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
