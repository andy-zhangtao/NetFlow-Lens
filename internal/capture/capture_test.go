package capture

import (
	"fmt"
	"os"
	"testing"
	"time"
	
	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

func TestNewCapturer(t *testing.T) {
	capturer := NewCapturer()

	if capturer == nil {
		t.Fatal("NewCapturer returned nil")
	}

	if capturer.packets == nil {
		t.Error("Expected packets channel to be initialized")
	}

	if capturer.errorChannel == nil {
		t.Error("Expected error channel to be initialized")
	}

	if capturer.isRunning {
		t.Error("Expected capturer to not be running initially")
	}

	if capturer.packetCount != 0 {
		t.Errorf("Expected initial packet count to be 0, got %d", capturer.packetCount)
	}
}

func TestSetSource(t *testing.T) {
	capturer := NewCapturer()

	tests := []struct {
		name       string
		source     string
		sourceType string
		shouldFail bool
	}{
		{"valid interface", "eth0", "interface", false},
		{"valid file", "/path/to/file.pcap", "file", false},
		{"empty source", "", "interface", false}, // Should not fail, just set empty
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := capturer.SetSource(tt.source, tt.sourceType)
			if (err != nil) != tt.shouldFail {
				t.Errorf("SetSource() error = %v, shouldFail %v", err, tt.shouldFail)
			}

			if err == nil {
				if capturer.source != tt.source {
					t.Errorf("Expected source %s, got %s", tt.source, capturer.source)
				}
				if capturer.sourceType != tt.sourceType {
					t.Errorf("Expected sourceType %s, got %s", tt.sourceType, capturer.sourceType)
				}
			}
		})
	}
}

func TestSetSourceWhileRunning(t *testing.T) {
	capturer := NewCapturer()
	capturer.isRunning = true // Simulate running state

	err := capturer.SetSource("test", "interface")
	if err == nil {
		t.Error("Expected error when setting source while capturer is running")
	}

	expectedError := "cannot change source while capturing"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestGetPackets(t *testing.T) {
	capturer := NewCapturer()

	packets := capturer.GetPackets()
	if packets == nil {
		t.Error("Expected packets channel to not be nil")
	}

	// Test that we can receive from the channel
	select {
	case <-packets:
		t.Error("Should not receive any packets from empty channel")
	default:
		// Expected: channel is empty
	}
}

func TestGetErrors(t *testing.T) {
	capturer := NewCapturer()

	errors := capturer.GetErrors()
	if errors == nil {
		t.Error("Expected error channel to not be nil")
	}

	// Test that we can receive from the channel
	select {
	case <-errors:
		t.Error("Should not receive any errors from empty channel")
	default:
		// Expected: channel is empty
	}
}

func TestGetPacketCount(t *testing.T) {
	capturer := NewCapturer()

	count := capturer.GetPacketCount()
	if count != 0 {
		t.Errorf("Expected initial packet count to be 0, got %d", count)
	}

	// Simulate processing packets
	capturer.packetCount = 42
	count = capturer.GetPacketCount()
	if count != 42 {
		t.Errorf("Expected packet count to be 42, got %d", count)
	}
}

func TestStartLiveCapture_AlreadyRunning(t *testing.T) {
	capturer := NewCapturer()
	capturer.isRunning = true

	err := capturer.StartLiveCapture("lo")
	if err == nil {
		t.Error("Expected error when starting capture while already running")
	}

	expectedError := "capture already running"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestStartFileCapture_AlreadyRunning(t *testing.T) {
	capturer := NewCapturer()
	capturer.isRunning = true

	err := capturer.StartFileCapture("/tmp/test.pcap")
	if err == nil {
		t.Error("Expected error when starting file capture while already running")
	}

	expectedError := "capture already running"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestStartFileCapture_FileNotExists(t *testing.T) {
	capturer := NewCapturer()

	nonExistentFile := "/tmp/non_existent_file_12345.pcap"
	err := capturer.StartFileCapture(nonExistentFile)
	if err == nil {
		t.Error("Expected error when trying to open non-existent file")
	}

	expectedSubstring := "pcap file does not exist"
	if !containsSubstring(err.Error(), expectedSubstring) {
		t.Errorf("Expected error to contain '%s', got '%s'", expectedSubstring, err.Error())
	}
}

func TestStop(t *testing.T) {
	capturer := NewCapturer()

	// Test stopping when not running (should not panic)
	capturer.Stop()

	// Test stopping when running
	capturer.isRunning = true
	capturer.packetCount = 100

	capturer.Stop()

	if capturer.isRunning {
		t.Error("Expected capturer to be stopped")
	}
}

func TestListInterfaces(t *testing.T) {
	capturer := NewCapturer()

	interfaces, err := capturer.ListInterfaces()
	if err != nil {
		t.Errorf("ListInterfaces() error = %v", err)
	}

	// We can't guarantee specific interfaces exist, but we can check the result structure
	if interfaces == nil {
		t.Error("Expected interfaces slice to not be nil")
	}

	// Check that all returned interfaces are non-empty strings
	for _, iface := range interfaces {
		if iface == "" {
			t.Error("Found empty interface name in list")
		}
	}
}

func TestIsValidInterface(t *testing.T) {
	// Test with loopback interface which should exist on most systems
	isValid := IsValidInterface("lo")
	// Note: We can't guarantee "lo" exists on all systems, so we just check it doesn't panic

	// Test with clearly invalid interface
	isValid = IsValidInterface("invalid_interface_name_12345")
	if isValid {
		t.Error("Expected invalid interface name to return false")
	}

	// Test with empty string
	isValid = IsValidInterface("")
	if isValid {
		t.Error("Expected empty interface name to return false")
	}
}

func TestGetPCAPFileInfo_NonExistentFile(t *testing.T) {
	nonExistentFile := "/tmp/non_existent_file_12345.pcap"
	_, err := GetPCAPFileInfo(nonExistentFile)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestGetPCAPFileInfo_InvalidFile(t *testing.T) {
	// Create a temporary non-pcap file
	tempFile, err := os.CreateTemp("", "test_invalid_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write some non-pcap content
	tempFile.WriteString("This is not a pcap file")
	tempFile.Close()

	info, err := GetPCAPFileInfo(tempFile.Name())
	if err != nil {
		t.Errorf("GetPCAPFileInfo() error = %v", err)
	}

	if info == nil {
		t.Fatal("Expected PCAPFileInfo to not be nil")
	}

	if info.Status != "error" {
		t.Errorf("Expected status to be 'error', got '%s'", info.Status)
	}

	if info.ErrorMessage == "" {
		t.Error("Expected error message to be set for invalid file")
	}

	if info.PacketCount != 0 {
		t.Errorf("Expected packet count to be 0 for invalid file, got %d", info.PacketCount)
	}
}

func TestParsePacket_NilPacket(t *testing.T) {
	capturer := NewCapturer()

	result := capturer.parsePacket(nil)
	if result != nil {
		t.Error("Expected nil result for nil packet")
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(str, substr string) bool {
	return len(substr) <= len(str) && (substr == "" || findSubstring(str, substr) >= 0)
}

func findSubstring(str, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Integration test that creates a mock pcap scenario
func TestCaptureFlow(t *testing.T) {
	capturer := NewCapturer()

	// Test the basic flow without actual network interfaces
	if capturer.GetPacketCount() != 0 {
		t.Error("Expected initial packet count to be 0")
	}

	// Test setting source
	err := capturer.SetSource("test_interface", "interface")
	if err != nil {
		t.Errorf("SetSource failed: %v", err)
	}

	if capturer.source != "test_interface" {
		t.Errorf("Expected source to be 'test_interface', got '%s'", capturer.source)
	}

	if capturer.sourceType != "interface" {
		t.Errorf("Expected sourceType to be 'interface', got '%s'", capturer.sourceType)
	}

	// Test channels are working
	packets := capturer.GetPackets()
	errors := capturer.GetErrors()

	if packets == nil {
		t.Error("Packets channel should not be nil")
	}

	if errors == nil {
		t.Error("Errors channel should not be nil")
	}
}

// Test concurrent access to capturer methods
func TestConcurrentAccess(t *testing.T) {
	capturer := NewCapturer()

	done := make(chan bool)
	numGoroutines := 10

	// Test concurrent access to read-only methods
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { done <- true }()

			// These should be safe to call concurrently
			_ = capturer.GetPacketCount()
			_ = capturer.GetPackets()
			_ = capturer.GetErrors()
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent access test")
		}
	}
}

// Benchmark tests
func BenchmarkNewCapturer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		capturer := NewCapturer()
		_ = capturer
	}
}

func BenchmarkSetSource(b *testing.B) {
	capturer := NewCapturer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		capturer.SetSource("test_interface", "interface")
	}
}

func BenchmarkGetPacketCount(b *testing.B) {
	capturer := NewCapturer()
	capturer.packetCount = 1000

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = capturer.GetPacketCount()
	}
}

// Filter integration tests
func TestNewCapturerWithFilterManager(t *testing.T) {
	capturer := NewCapturer()
	
	if capturer.filterManager == nil {
		t.Error("Expected filter manager to be initialized")
	}
	
	// Test that filter manager has default state
	expression := capturer.filterManager.GetActiveFilterExpression()
	if expression != "" {
		t.Errorf("Expected empty active filter expression initially, got '%s'", expression)
	}
	
	presets := capturer.filterManager.GetPresetFilters()
	if len(presets) == 0 {
		t.Error("Expected preset filters to be loaded")
	}
}

func TestGetFilterManager(t *testing.T) {
	capturer := NewCapturer()
	
	fm := capturer.GetFilterManager()
	if fm == nil {
		t.Error("Expected GetFilterManager to return non-nil filter manager")
	}
	
	// Verify it's the same instance
	if fm != capturer.filterManager {
		t.Error("Expected GetFilterManager to return the same instance")
	}
}

func TestGetFilterStats(t *testing.T) {
	capturer := NewCapturer()
	
	stats := capturer.GetFilterStats()
	if stats == nil {
		t.Error("Expected GetFilterStats to return non-nil stats")
	}
	
	// Initially should be zero
	if stats.TotalPackets != 0 {
		t.Errorf("Expected initial TotalPackets=0, got %d", stats.TotalPackets)
	}
	if stats.FilteredPackets != 0 {
		t.Errorf("Expected initial FilteredPackets=0, got %d", stats.FilteredPackets)
	}
	if stats.DroppedPackets != 0 {
		t.Errorf("Expected initial DroppedPackets=0, got %d", stats.DroppedPackets)
	}
	if stats.FilterRatio != 0.0 {
		t.Errorf("Expected initial FilterRatio=0.0, got %f", stats.FilterRatio)
	}
}

func TestFilterManagerIntegration(t *testing.T) {
	capturer := NewCapturer()
	fm := capturer.GetFilterManager()
	
	// Test adding a filter
	rule := &models.FilterRule{
		Name:        "Test HTTP Filter",
		Expression:  "tcp port 80",
		Description: "Test filter for HTTP traffic",
		IsActive:    true,
	}
	
	err := fm.AddFilter(rule)
	if err != nil {
		t.Fatalf("Failed to add filter: %v", err)
	}
	
	// Test setting active filter
	err = fm.SetActiveFilter(rule.ID)
	if err != nil {
		t.Fatalf("Failed to set active filter: %v", err)
	}
	
	// Verify active filter expression
	expression := fm.GetActiveFilterExpression()
	if expression != "tcp port 80" {
		t.Errorf("Expected active filter expression 'tcp port 80', got '%s'", expression)
	}
	
	// Test clearing active filter
	err = fm.SetActiveFilter("")
	if err != nil {
		t.Fatalf("Failed to clear active filter: %v", err)
	}
	
	expression = fm.GetActiveFilterExpression()
	if expression != "" {
		t.Errorf("Expected empty expression after clearing, got '%s'", expression)
	}
}

func TestResetStats(t *testing.T) {
	capturer := NewCapturer()
	
	// Set some initial packet count
	capturer.packetCount = 100
	capturer.filteredCount = 80
	capturer.droppedCount = 5
	
	// Call resetStats (it's a private method, so we need to test indirectly)
	capturer.resetStats()
	
	// Verify stats are reset
	if capturer.packetCount != 0 {
		t.Errorf("Expected packetCount=0 after reset, got %d", capturer.packetCount)
	}
	if capturer.filteredCount != 0 {
		t.Errorf("Expected filteredCount=0 after reset, got %d", capturer.filteredCount)
	}
	if capturer.droppedCount != 0 {
		t.Errorf("Expected droppedCount=0 after reset, got %d", capturer.droppedCount)
	}
}

func TestUpdateFilterStats(t *testing.T) {
	capturer := NewCapturer()
	
	// Set some packet counts
	capturer.packetCount = 100
	capturer.filteredCount = 80
	capturer.droppedCount = 5
	
	// Update filter stats
	capturer.updateFilterStats()
	
	// Get stats from filter manager
	stats := capturer.GetFilterStats()
	
	// Verify stats were updated - updateFilterStats uses packetCount as totalPackets
	if stats.TotalPackets != 100 { // packetCount is used as total
		t.Errorf("Expected TotalPackets=100, got %d", stats.TotalPackets)
	}
	if stats.FilteredPackets != 80 {
		t.Errorf("Expected FilteredPackets=80, got %d", stats.FilteredPackets)
	}
	if stats.DroppedPackets != 5 {
		t.Errorf("Expected DroppedPackets=5, got %d", stats.DroppedPackets)
	}
}

func TestFilterValidationIntegration(t *testing.T) {
	capturer := NewCapturer()
	fm := capturer.GetFilterManager()
	
	tests := []struct {
		name        string
		expression  string
		expectValid bool
	}{
		{
			name:        "valid tcp port filter",
			expression:  "tcp port 80",
			expectValid: true,
		},
		{
			name:        "valid udp port filter", 
			expression:  "udp port 53",
			expectValid: true,
		},
		{
			name:        "valid complex filter",
			expression:  "tcp port 80 or tcp port 443",
			expectValid: true,
		},
		{
			name:        "invalid syntax",
			expression:  "invalid syntax here",
			expectValid: false,
		},
		{
			name:        "empty expression",
			expression:  "",
			expectValid: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fm.ValidateFilter(tt.expression)
			
			if result.IsValid != tt.expectValid {
				t.Errorf("ValidateFilter(%q).IsValid = %v, want %v", 
					tt.expression, result.IsValid, tt.expectValid)
			}
			
			if !tt.expectValid && result.ErrorMessage == "" {
				t.Error("Expected error message for invalid filter")
			}
		})
	}
}

func TestPresetFiltersIntegration(t *testing.T) {
	capturer := NewCapturer()
	fm := capturer.GetFilterManager()
	
	presets := fm.GetPresetFilters()
	if len(presets) == 0 {
		t.Error("Expected preset filters to be available")
	}
	
	// Test that all presets have valid expressions
	for _, preset := range presets {
		if preset.ID == "" {
			t.Error("Preset filter missing ID")
		}
		if preset.Name == "" {
			t.Error("Preset filter missing name")
		}
		if preset.Expression == "" {
			t.Error("Preset filter missing expression")
		}
		if preset.Category == "" {
			t.Error("Preset filter missing category")
		}
		
		// Validate the preset expression
		result := fm.ValidateFilter(preset.Expression)
		if !result.IsValid {
			t.Errorf("Preset filter %s has invalid expression: %s", preset.ID, result.ErrorMessage)
		}
	}
}

func TestFilterManagerConcurrentAccess(t *testing.T) {
	capturer := NewCapturer()
	fm := capturer.GetFilterManager()
	
	done := make(chan bool)
	numGoroutines := 5
	
	// Test concurrent access to filter manager methods
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			// Create a filter
			rule := &models.FilterRule{
				Name:        fmt.Sprintf("Concurrent Filter %d", id),
				Expression:  "tcp port 80",
				Description: "Concurrent test filter",
				IsActive:    true,
			}
			
			err := fm.AddFilter(rule)
			if err != nil {
				t.Errorf("Failed to add filter in goroutine %d: %v", id, err)
				return
			}
			
			// Read operations
			_ = fm.ListFilters()
			_ = fm.GetPresetFilters()
			_ = fm.GetStats()
			_ = fm.GetActiveFilterExpression()
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent filter access test")
		}
	}
	
	// Verify all filters were added
	filters := fm.ListFilters()
	if len(filters) != numGoroutines {
		t.Errorf("Expected %d filters, got %d", numGoroutines, len(filters))
	}
}

