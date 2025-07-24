package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/internal/server"
	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

// TestAPIIntegration 测试API端点的集成
func TestAPIIntegration(t *testing.T) {
	// 清理测试环境
	defer os.RemoveAll("uploads")

	// 创建服务器实例
	srv := server.NewServer()
	testServer := httptest.NewServer(srv)
	defer testServer.Close()

	baseURL := testServer.URL

	t.Run("API状态检查", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/status")
		if err != nil {
			t.Fatalf("GET /api/status failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var status models.APIStatus
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			t.Fatalf("Failed to decode status response: %v", err)
		}

		if status.Status != "running" {
			t.Errorf("Expected status 'running', got '%s'", status.Status)
		}
	})

	t.Run("连接列表API", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/connections")
		if err != nil {
			t.Fatalf("GET /api/connections failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var connections []models.Connection
		if err := json.NewDecoder(resp.Body).Decode(&connections); err != nil {
			t.Fatalf("Failed to decode connections response: %v", err)
		}

		// 初始状态应该为空
		if len(connections) != 0 {
			t.Errorf("Expected 0 connections initially, got %d", len(connections))
		}
	})

	t.Run("数据包列表API", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/packets?limit=10")
		if err != nil {
			t.Fatalf("GET /api/packets failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var packets []models.Packet
		if err := json.NewDecoder(resp.Body).Decode(&packets); err != nil {
			t.Fatalf("Failed to decode packets response: %v", err)
		}

		// 初始状态应该为空
		if len(packets) != 0 {
			t.Errorf("Expected 0 packets initially, got %d", len(packets))
		}
	})

	t.Run("网络接口列表API", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/interfaces")
		if err != nil {
			t.Fatalf("GET /api/interfaces failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var interfaces []string
		if err := json.NewDecoder(resp.Body).Decode(&interfaces); err != nil {
			t.Fatalf("Failed to decode interfaces response: %v", err)
		}

		// 接口列表可能为空，但不应该是nil
		if interfaces == nil {
			t.Error("Expected interfaces array to not be nil")
		}
	})

	t.Run("PCAP文件列表API", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/pcap/list")
		if err != nil {
			t.Fatalf("GET /api/pcap/list failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var files []*models.PCAPFileInfo
		if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
			t.Fatalf("Failed to decode files response: %v", err)
		}

		// 初始状态应该为空
		if len(files) != 0 {
			t.Errorf("Expected 0 files initially, got %d", len(files))
		}
	})

	t.Run("捕获状态API", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/capture/status")
		if err != nil {
			t.Fatalf("GET /api/capture/status failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var status map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			t.Fatalf("Failed to decode capture status response: %v", err)
		}

		if _, ok := status["is_running"]; !ok {
			t.Error("Expected is_running field in capture status")
		}

		if _, ok := status["packet_count"]; !ok {
			t.Error("Expected packet_count field in capture status")
		}
	})
}

// TestDataFlowIntegration 测试数据流的完整集成
func TestDataFlowIntegration(t *testing.T) {
	defer os.RemoveAll("uploads")

	srv := server.NewServer()
	testServer := httptest.NewServer(srv)
	defer testServer.Close()

	baseURL := testServer.URL

	// 模拟数据包处理流程
	t.Run("完整数据流测试", func(t *testing.T) {
		// 1. 检查初始状态
		resp, err := http.Get(baseURL + "/api/status")
		if err != nil {
			t.Fatalf("Initial status check failed: %v", err)
		}
		resp.Body.Close()

		// 2. 检查连接列表（应该为空）
		resp, err = http.Get(baseURL + "/api/connections")
		if err != nil {
			t.Fatalf("Initial connections check failed: %v", err)
		}
		defer resp.Body.Close()

		var connections []models.Connection
		json.NewDecoder(resp.Body).Decode(&connections)
		if len(connections) != 0 {
			t.Errorf("Expected 0 connections initially, got %d", len(connections))
		}

		// 3. 检查数据包列表（应该为空）
		resp, err = http.Get(baseURL + "/api/packets")
		if err != nil {
			t.Fatalf("Initial packets check failed: %v", err)
		}
		defer resp.Body.Close()

		var packets []models.Packet
		json.NewDecoder(resp.Body).Decode(&packets)
		if len(packets) != 0 {
			t.Errorf("Expected 0 packets initially, got %d", len(packets))
		}

		// 4. 尝试开始捕获（可能会失败，因为没有权限或接口不存在）
		startReq := map[string]string{"interface": "lo"}
		jsonData, _ := json.Marshal(startReq)
		resp, err = http.Post(baseURL+"/api/capture/start", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			t.Fatalf("Start capture request failed: %v", err)
		}
		defer resp.Body.Close()

		var startResp map[string]string
		json.NewDecoder(resp.Body).Decode(&startResp)

		// 5. 停止捕获
		resp, err = http.Post(baseURL+"/api/capture/stop", "application/json", nil)
		if err != nil {
			t.Fatalf("Stop capture request failed: %v", err)
		}
		defer resp.Body.Close()

		var stopResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&stopResp)

		if stopResp["status"] != "success" {
			t.Errorf("Expected stop status 'success', got '%v'", stopResp["status"])
		}
	})
}

// TestErrorHandling 测试错误处理
func TestErrorHandling(t *testing.T) {
	defer os.RemoveAll("uploads")

	srv := server.NewServer()
	testServer := httptest.NewServer(srv)
	defer testServer.Close()

	baseURL := testServer.URL

	t.Run("无效的API端点", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/nonexistent")
		if err != nil {
			t.Fatalf("Request to nonexistent endpoint failed: %v", err)
		}
		defer resp.Body.Close()

		// 对于不存在的API端点，服务器可能返回404或其他状态
		// 主要是确保请求能正常处理，不会panic
		if resp.StatusCode < 200 || resp.StatusCode >= 500 {
			t.Errorf("Unexpected server error status %d for nonexistent endpoint", resp.StatusCode)
		}
	})

	t.Run("错误的HTTP方法", func(t *testing.T) {
		// 尝试对只接受POST的端点使用GET
		resp, err := http.Get(baseURL + "/api/capture/start")
		if err != nil {
			t.Fatalf("GET request to POST-only endpoint failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", resp.StatusCode)
		}
	})

	t.Run("无效的JSON数据", func(t *testing.T) {
		invalidJSON := bytes.NewBuffer([]byte("{invalid json}"))
		resp, err := http.Post(baseURL+"/api/capture/start", "application/json", invalidJSON)
		if err != nil {
			t.Fatalf("POST request with invalid JSON failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400 for invalid JSON, got %d", resp.StatusCode)
		}
	})

	t.Run("不存在的PCAP文件信息", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/pcap/info?filename=nonexistent.pcap")
		if err != nil {
			t.Fatalf("GET request for nonexistent file failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status 404 for nonexistent file, got %d", resp.StatusCode)
		}
	})
}

// TestPerformance 性能测试
func TestPerformance(t *testing.T) {
	defer os.RemoveAll("uploads")

	srv := server.NewServer()
	testServer := httptest.NewServer(srv)
	defer testServer.Close()

	baseURL := testServer.URL

	t.Run("并发API请求", func(t *testing.T) {
		concurrency := 10
		requests := 100

		done := make(chan bool, concurrency)

		start := time.Now()

		for i := 0; i < concurrency; i++ {
			go func() {
				defer func() { done <- true }()

				for j := 0; j < requests/concurrency; j++ {
					resp, err := http.Get(baseURL + "/api/status")
					if err != nil {
						t.Errorf("Concurrent request failed: %v", err)
						return
					}
					resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						t.Errorf("Expected status 200, got %d", resp.StatusCode)
						return
					}
				}
			}()
		}

		// 等待所有goroutine完成
		for i := 0; i < concurrency; i++ {
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("Timeout waiting for concurrent requests to complete")
			}
		}

		duration := time.Since(start)
		rps := float64(requests) / duration.Seconds()

		t.Logf("完成 %d 个并发请求，耗时 %v，RPS: %.2f", requests, duration, rps)

		// 基本性能要求：至少每秒处理100个请求
		if rps < 100 {
			t.Errorf("性能不达标：期望至少100 RPS，实际 %.2f RPS", rps)
		}
	})

	t.Run("大量数据包API响应", func(t *testing.T) {
		start := time.Now()

		// 请求大量数据包（虽然当前为空，但测试API响应时间）
		resp, err := http.Get(baseURL + "/api/packets?limit=10000")
		if err != nil {
			t.Fatalf("Large packet request failed: %v", err)
		}
		defer resp.Body.Close()

		duration := time.Since(start)

		if duration > 1*time.Second {
			t.Errorf("API响应时间过长：%v，期望小于1秒", duration)
		}

		t.Logf("大量数据包API响应时间：%v", duration)
	})
}

// TestHTTPMethodsCompliance 测试HTTP方法合规性
func TestHTTPMethodsCompliance(t *testing.T) {
	defer os.RemoveAll("uploads")

	srv := server.NewServer()
	testServer := httptest.NewServer(srv)
	defer testServer.Close()

	baseURL := testServer.URL

	// 测试各个端点的HTTP方法合规性
	testCases := []struct {
		endpoint      string
		allowedMethod string
		statusCode    int
	}{
		{"/api/status", "GET", http.StatusOK},
		{"/api/connections", "GET", http.StatusOK},
		{"/api/packets", "GET", http.StatusOK},
		{"/api/interfaces", "GET", http.StatusOK},
		{"/api/pcap/list", "GET", http.StatusOK},
		{"/api/capture/status", "GET", http.StatusOK},
		{"/api/capture/start", "POST", http.StatusOK},
		{"/api/capture/stop", "POST", http.StatusOK},
		{"/api/pcap/load", "POST", http.StatusBadRequest}, // 没有body会返回400
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s %s", tc.allowedMethod, tc.endpoint), func(t *testing.T) {
			var resp *http.Response
			var err error

			switch tc.allowedMethod {
			case "GET":
				resp, err = http.Get(baseURL + tc.endpoint)
			case "POST":
				resp, err = http.Post(baseURL+tc.endpoint, "application/json", bytes.NewBuffer([]byte("{}")))
			}

			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// 检查响应状态码在合理范围内
			if resp.StatusCode < 200 || resp.StatusCode >= 500 {
				t.Errorf("Unexpected status code %d for %s %s", resp.StatusCode, tc.allowedMethod, tc.endpoint)
			}
		})
	}
}