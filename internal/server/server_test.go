package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

func TestNewServer(t *testing.T) {
	// Clean up any existing upload directory
	os.RemoveAll("uploads")
	defer os.RemoveAll("uploads")

	server := NewServer()

	if server == nil {
		t.Fatal("NewServer returned nil")
	}

	if server.mux == nil {
		t.Error("Expected mux to be initialized")
	}

	if server.capturer == nil {
		t.Error("Expected capturer to be initialized")
	}

	if server.analyzer == nil {
		t.Error("Expected analyzer to be initialized")
	}

	if server.pcapFiles == nil {
		t.Error("Expected pcapFiles map to be initialized")
	}

	if server.uploadDir != "uploads" {
		t.Errorf("Expected uploadDir to be 'uploads', got '%s'", server.uploadDir)
	}

	// Check if upload directory was created
	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		t.Error("Expected upload directory to be created")
	}
}

func TestHandleHome(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	server.handleHome(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	expectedContentType := "text/html; charset=utf-8"
	if contentType != expectedContentType {
		t.Errorf("Expected Content-Type '%s', got '%s'", expectedContentType, contentType)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "NetFlow Lens") {
		t.Error("Expected response to contain 'NetFlow Lens'")
	}

	if !strings.Contains(bodyStr, "<!DOCTYPE html>") {
		t.Error("Expected response to contain HTML doctype")
	}
}

func TestHandleAPIStatus(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	req := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()

	server.handleAPIStatus(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	var status models.APIStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if status.Status != "running" {
		t.Errorf("Expected status 'running', got '%s'", status.Status)
	}

	if status.Version != "0.2.0" {
		t.Errorf("Expected version '0.2.0', got '%s'", status.Version)
	}

	if !strings.Contains(status.Message, "gopacket") {
		t.Error("Expected message to mention gopacket integration")
	}
}

func TestHandleConnections(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	req := httptest.NewRequest("GET", "/api/connections", nil)
	w := httptest.NewRecorder()

	server.handleConnections(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	var connections []models.Connection
	if err := json.NewDecoder(resp.Body).Decode(&connections); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	// Initially should be empty
	if len(connections) != 0 {
		t.Errorf("Expected 0 connections initially, got %d", len(connections))
	}
}

func TestHandlePackets(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	tests := []struct {
		name        string
		queryParam  string
		expectError bool
	}{
		{"no limit", "", false},
		{"valid limit", "?limit=50", false},
		{"zero limit", "?limit=0", false},
		{"invalid limit", "?limit=abc", false}, // Should use default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/packets"+tt.queryParam, nil)
			w := httptest.NewRecorder()

			server.handlePackets(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}

			var packets []models.Packet
			if err := json.NewDecoder(resp.Body).Decode(&packets); err != nil {
				t.Fatalf("Failed to decode JSON response: %v", err)
			}

			// Initially should be empty
			if len(packets) != 0 {
				t.Errorf("Expected 0 packets initially, got %d", len(packets))
			}
		})
	}
}

func TestHandleStartCapture(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	tests := []struct {
		name           string
		method         string
		body           string
		expectedStatus int
	}{
		{
			name:           "valid request",
			method:         "POST",
			body:           `{"interface": "lo"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "empty interface (should use default)",
			method:         "POST",
			body:           `{}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid json",
			method:         "POST",
			body:           `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "wrong method",
			method:         "GET",
			body:           `{}`,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/capture/start", strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			server.handleStartCapture(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]string
				if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode JSON response: %v", err)
				}

				// The response should indicate either success or error
				if response["status"] != "success" && response["status"] != "error" {
					t.Errorf("Expected status to be 'success' or 'error', got '%s'", response["status"])
				}
			}
		})
	}
}

func TestHandleStopCapture(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{"valid request", "POST", http.StatusOK},
		{"wrong method", "GET", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/capture/stop", nil)
			w := httptest.NewRecorder()

			server.handleStopCapture(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode JSON response: %v", err)
				}

				if response["status"] != "success" {
					t.Errorf("Expected status 'success', got '%v'", response["status"])
				}

				if _, ok := response["packet_count"]; !ok {
					t.Error("Expected packet_count field in response")
				}
			}
		})
	}
}

func TestHandleCaptureStatus(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	req := httptest.NewRequest("GET", "/api/capture/status", nil)
	w := httptest.NewRecorder()

	server.handleCaptureStatus(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var status map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if _, ok := status["is_running"]; !ok {
		t.Error("Expected is_running field in response")
	}

	if _, ok := status["packet_count"]; !ok {
		t.Error("Expected packet_count field in response")
	}
}

func TestHandleListInterfaces(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	req := httptest.NewRequest("GET", "/api/interfaces", nil)
	w := httptest.NewRecorder()

	server.handleListInterfaces(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var interfaces []string
	if err := json.NewDecoder(resp.Body).Decode(&interfaces); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	// Interfaces list can be empty or contain interface names
	// We just check that it's a valid array
	if interfaces == nil {
		t.Error("Expected interfaces array to not be nil")
	}
}

func TestHandlePCAPUpload(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	tests := []struct {
		name           string
		method         string
		filename       string
		content        string
		expectedStatus int
	}{
		{
			name:           "wrong method",
			method:         "GET",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid file type",
			method:         "POST",
			filename:       "test.txt",
			content:        "not a pcap file",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "valid pcap file",
			method:         "POST",
			filename:       "test.pcap",
			content:        "fake pcap content", // This will create an invalid pcap, but the upload should succeed
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.method == "GET" {
				req := httptest.NewRequest(tt.method, "/api/pcap/upload", nil)
				w := httptest.NewRecorder()

				server.handlePCAPUpload(w, req)

				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
				}
				return
			}

			// Create multipart form data
			var buf bytes.Buffer
			writer := multipart.NewWriter(&buf)

			part, err := writer.CreateFormFile("pcap", tt.filename)
			if err != nil {
				t.Fatalf("Failed to create form file: %v", err)
			}

			part.Write([]byte(tt.content))
			writer.Close()

			req := httptest.NewRequest(tt.method, "/api/pcap/upload", &buf)
			req.Header.Set("Content-Type", writer.FormDataContentType())
			w := httptest.NewRecorder()

			server.handlePCAPUpload(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode JSON response: %v", err)
				}

				if response["status"] != "success" {
					t.Errorf("Expected status 'success', got '%v'", response["status"])
				}

				if response["filename"] != tt.filename {
					t.Errorf("Expected filename '%s', got '%v'", tt.filename, response["filename"])
				}
			}
		})
	}
}

func TestHandlePCAPList(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	// Add some test files to the server's pcapFiles map
	server.pcapFiles["test1.pcap"] = &models.PCAPFileInfo{
		Filename:    "test1.pcap",
		Size:        1024,
		UploadTime:  time.Now(),
		PacketCount: 100,
		Status:      "ready",
	}

	server.pcapFiles["test2.pcap"] = &models.PCAPFileInfo{
		Filename:    "test2.pcap",
		Size:        2048,
		UploadTime:  time.Now(),
		PacketCount: 200,
		Status:      "ready",
	}

	req := httptest.NewRequest("GET", "/api/pcap/list", nil)
	w := httptest.NewRecorder()

	server.handlePCAPList(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var files []*models.PCAPFileInfo
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if len(files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(files))
	}

	// Check that the files contain the expected data
	foundTest1 := false
	foundTest2 := false
	for _, file := range files {
		if file.Filename == "test1.pcap" {
			foundTest1 = true
			if file.PacketCount != 100 {
				t.Errorf("Expected test1.pcap packet count 100, got %d", file.PacketCount)
			}
		}
		if file.Filename == "test2.pcap" {
			foundTest2 = true
			if file.PacketCount != 200 {
				t.Errorf("Expected test2.pcap packet count 200, got %d", file.PacketCount)
			}
		}
	}

	if !foundTest1 {
		t.Error("Expected to find test1.pcap in response")
	}
	if !foundTest2 {
		t.Error("Expected to find test2.pcap in response")
	}
}

func TestHandlePCAPLoad(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	// Create a test pcap file (even if invalid, just for the test)
	testFile := filepath.Join(server.uploadDir, "test.pcap")
	err := os.WriteFile(testFile, []byte("fake pcap content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name           string
		method         string
		body           string
		expectedStatus int
	}{
		{
			name:           "wrong method",
			method:         "GET",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid json",
			method:         "POST",
			body:           `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "valid request",
			method:         "POST",
			body:           `{"filename": "test.pcap"}`,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/pcap/load", strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			server.handlePCAPLoad(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]string
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode JSON response: %v", err)
				}

				// The response should indicate either success or error
				if response["status"] != "success" && response["status"] != "error" {
					t.Errorf("Expected status to be 'success' or 'error', got '%s'", response["status"])
				}
			}
		})
	}
}

func TestHandlePCAPInfo(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	// Add a test file to the server's pcapFiles map
	testInfo := &models.PCAPFileInfo{
		Filename:    "test.pcap",
		Size:        1024,
		UploadTime:  time.Now(),
		PacketCount: 100,
		Status:      "ready",
	}
	server.pcapFiles["test.pcap"] = testInfo

	tests := []struct {
		name           string
		query          string
		expectedStatus int
	}{
		{
			name:           "missing filename",
			query:          "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "nonexistent file",
			query:          "?filename=nonexistent.pcap",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "existing file",
			query:          "?filename=test.pcap",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/pcap/info"+tt.query, nil)
			w := httptest.NewRecorder()

			server.handlePCAPInfo(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var info models.PCAPFileInfo
				if err := json.NewDecoder(w.Body).Decode(&info); err != nil {
					t.Fatalf("Failed to decode JSON response: %v", err)
				}

				if info.Filename != "test.pcap" {
					t.Errorf("Expected filename 'test.pcap', got '%s'", info.Filename)
				}

				if info.PacketCount != 100 {
					t.Errorf("Expected packet count 100, got %d", info.PacketCount)
				}
			}
		})
	}
}

func TestServeHTTP(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	// Test that ServeHTTP delegates to the mux
	req := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Should return the same as handleAPIStatus
	var status models.APIStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if status.Status != "running" {
		t.Errorf("Expected status 'running', got '%s'", status.Status)
	}
}

// Benchmark tests
func BenchmarkNewServer(b *testing.B) {
	defer os.RemoveAll("uploads")

	for i := 0; i < b.N; i++ {
		server := NewServer()
		_ = server
		os.RemoveAll("uploads")
	}
}

func BenchmarkHandleAPIStatus(b *testing.B) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	req := httptest.NewRequest("GET", "/api/status", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		server.handleAPIStatus(w, req)
	}
}

func BenchmarkHandleConnections(b *testing.B) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	req := httptest.NewRequest("GET", "/api/connections", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		server.handleConnections(w, req)
	}
}