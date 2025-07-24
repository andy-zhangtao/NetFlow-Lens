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

// Filter API tests
func TestHandleFilters(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	tests := []struct {
		name           string
		method         string
		query          string
		body           string
		expectedStatus int
	}{
		{
			name:           "get all filters",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "create new filter",
			method:         "POST",
			body:           `{"name":"HTTP Filter","expression":"tcp port 80","description":"HTTP traffic filter","is_active":true}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "create filter with invalid expression",
			method:         "POST",
			body:           `{"name":"Invalid Filter","expression":"invalid syntax","is_active":true}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "create filter with invalid JSON",
			method:         "POST",
			body:           `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unsupported method",
			method:         "PATCH",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, "/api/filters"+tt.query, strings.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, "/api/filters"+tt.query, nil)
			}
			
			w := httptest.NewRecorder()
			server.handleFilters(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				contentType := w.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
				}

				if tt.method == "GET" {
					var filters []models.FilterRule
					if err := json.NewDecoder(w.Body).Decode(&filters); err != nil {
						t.Fatalf("Failed to decode JSON response: %v", err)
					}
				} else if tt.method == "POST" {
					var filter models.FilterRule
					if err := json.NewDecoder(w.Body).Decode(&filter); err != nil {
						t.Fatalf("Failed to decode JSON response: %v", err)
					}
					if filter.ID == "" {
						t.Error("Expected filter ID to be generated")
					}
				}
			}
		})
	}
}

func TestHandleFiltersUpdateDelete(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	// First create a filter to update/delete
	createReq := httptest.NewRequest("POST", "/api/filters", 
		strings.NewReader(`{"name":"Test Filter","expression":"tcp port 80","description":"Test filter","is_active":true}`))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.handleFilters(createW, createReq)

	if createW.Code != http.StatusOK {
		t.Fatalf("Failed to create test filter: status %d", createW.Code)
	}

	var createdFilter models.FilterRule
	if err := json.NewDecoder(createW.Body).Decode(&createdFilter); err != nil {
		t.Fatalf("Failed to decode create response: %v", err)
	}

	filterID := createdFilter.ID

	tests := []struct {
		name           string
		method         string
		query          string
		body           string
		expectedStatus int
	}{
		{
			name:           "update filter",
			method:         "PUT",
			query:          "?id=" + filterID,
			body:           `{"name":"Updated Filter","description":"Updated description"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "update filter without ID",
			method:         "PUT",
			body:           `{"name":"Updated Filter"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "update nonexistent filter",
			method:         "PUT",
			query:          "?id=nonexistent",
			body:           `{"name":"Updated Filter"}`,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "delete filter",
			method:         "DELETE",
			query:          "?id=" + filterID,
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "delete filter without ID",
			method:         "DELETE",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "delete nonexistent filter",
			method:         "DELETE",
			query:          "?id=nonexistent",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, "/api/filters"+tt.query, strings.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, "/api/filters"+tt.query, nil)
			}
			
			w := httptest.NewRecorder()
			server.handleFilters(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var filter models.FilterRule
				if err := json.NewDecoder(w.Body).Decode(&filter); err != nil {
					t.Fatalf("Failed to decode JSON response: %v", err)
				}
			}
		})
	}
}

func TestHandleValidateFilter(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	tests := []struct {
		name           string
		method         string
		body           string
		expectedStatus int
		expectValid    bool
	}{
		{
			name:           "wrong method",
			method:         "GET",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid JSON",
			method:         "POST",
			body:           `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "valid BPF expression",
			method:         "POST",
			body:           `{"expression":"tcp port 80"}`,
			expectedStatus: http.StatusOK,
			expectValid:    true,
		},
		{
			name:           "invalid BPF expression",
			method:         "POST",
			body:           `{"expression":"invalid syntax here"}`,
			expectedStatus: http.StatusOK,
			expectValid:    false,
		},
		{
			name:           "empty expression",
			method:         "POST",
			body:           `{"expression":""}`,
			expectedStatus: http.StatusOK,
			expectValid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, "/api/filters/validate", strings.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, "/api/filters/validate", nil)
			}
			
			w := httptest.NewRecorder()
			server.handleValidateFilter(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var result models.FilterValidationResult
				if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
					t.Fatalf("Failed to decode JSON response: %v", err)
				}

				if result.IsValid != tt.expectValid {
					t.Errorf("Expected IsValid=%v, got %v", tt.expectValid, result.IsValid)
				}

				if !tt.expectValid && result.ErrorMessage == "" {
					t.Error("Expected error message for invalid filter")
				}
			}
		})
	}
}

func TestHandleFilterPresets(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "get presets",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "wrong method",
			method:         "POST",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/filters/presets", nil)
			w := httptest.NewRecorder()
			
			server.handleFilterPresets(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var presets []models.PresetFilter
				if err := json.NewDecoder(w.Body).Decode(&presets); err != nil {
					t.Fatalf("Failed to decode JSON response: %v", err)
				}

				if len(presets) == 0 {
					t.Error("Expected at least one preset filter")
				}

				// Check for expected preset
				foundHTTP := false
				for _, preset := range presets {
					if preset.ID == "preset_http" {
						foundHTTP = true
						if preset.Expression != "tcp port 80" {
							t.Errorf("Expected HTTP preset expression 'tcp port 80', got '%s'", preset.Expression)
						}
						break
					}
				}
				if !foundHTTP {
					t.Error("Expected to find HTTP preset")
				}
			}
		})
	}
}

func TestHandleActiveFilter(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	// First create a filter to set as active
	createReq := httptest.NewRequest("POST", "/api/filters", 
		strings.NewReader(`{"name":"Active Test Filter","expression":"tcp port 443","description":"Test filter for active","is_active":true}`))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.handleFilters(createW, createReq)

	if createW.Code != http.StatusOK {
		t.Fatalf("Failed to create test filter: status %d", createW.Code)
	}

	var createdFilter models.FilterRule
	if err := json.NewDecoder(createW.Body).Decode(&createdFilter); err != nil {
		t.Fatalf("Failed to decode create response: %v", err)
	}

	tests := []struct {
		name           string
		method         string
		body           string
		expectedStatus int
	}{
		{
			name:           "get active filter (none set)",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "set active filter by ID",
			method:         "POST",
			body:           `{"filter_id":"` + createdFilter.ID + `"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "set active filter by expression",
			method:         "POST",
			body:           `{"expression":"udp port 53"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "set active filter with save",
			method:         "POST",
			body:           `{"expression":"icmp","save_as":"ICMP Filter"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "set active filter with invalid expression",
			method:         "POST",
			body:           `{"expression":"invalid syntax"}`,
			expectedStatus: http.StatusOK, // Returns error in response body
		},
		{
			name:           "invalid JSON",
			method:         "POST",
			body:           `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "clear active filter",
			method:         "DELETE",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "unsupported method",
			method:         "PUT",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, "/api/filters/active", strings.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, "/api/filters/active", nil)
			}
			
			w := httptest.NewRecorder()
			server.handleActiveFilter(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				if tt.method == "GET" {
					// Active filter response can be null or a filter rule
					var activeFilter *models.FilterRule
					if err := json.NewDecoder(w.Body).Decode(&activeFilter); err != nil {
						t.Fatalf("Failed to decode JSON response: %v", err)
					}
				} else {
					var response models.FilterResponse
					if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
						t.Fatalf("Failed to decode JSON response: %v", err)
					}

					if tt.name == "set active filter with invalid expression" {
						if response.Status != "error" {
							t.Errorf("Expected error status for invalid expression, got '%s'", response.Status)
						}
					} else if response.Status != "success" {
						t.Errorf("Expected success status, got '%s'", response.Status)
					}
				}
			}
		})
	}
}

func TestHandleFilterStats(t *testing.T) {
	server := NewServer()
	defer os.RemoveAll("uploads")

	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "get filter stats",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "wrong method",
			method:         "POST",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/filters/stats", nil)
			w := httptest.NewRecorder()
			
			server.handleFilterStats(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var stats models.FilterStats
				if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
					t.Fatalf("Failed to decode JSON response: %v", err)
				}

				// Initially stats should be zero
				if stats.TotalPackets != 0 {
					t.Errorf("Expected initial TotalPackets=0, got %d", stats.TotalPackets)
				}
			}
		})
	}
}