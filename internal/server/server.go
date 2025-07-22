package server

import (
	"encoding/json"
	"net/http"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

type Server struct {
	mux *http.ServeMux
}

func NewServer() *Server {
	s := &Server{
		mux: http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) setupRoutes() {
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/api/status", s.handleAPIStatus)
	s.mux.HandleFunc("/api/connections", s.handleConnections)
	
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
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; margin-bottom: 40px; }
        .status { background: #f0f0f0; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>NetFlow Lens</h1>
        <p>网络流量可视化学习工具</p>
    </div>
    <div class="status">
        <h2>系统状态</h2>
        <p>服务器运行正常</p>
        <p><a href="/api/status">查看API状态</a></p>
    </div>
</body>
</html>
	`))
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	status := models.APIStatus{
		Status:  "running",
		Version: "0.1.0",
		Message: "NetFlow Lens API is running",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	connections := []models.Connection{
		{
			ID:         "conn_1",
			SourceIP:   "192.168.1.100",
			SourcePort: 12345,
			DestIP:     "93.184.216.34",
			DestPort:   80,
			Protocol:   "TCP",
			State:      "ESTABLISHED",
		},
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connections)
}