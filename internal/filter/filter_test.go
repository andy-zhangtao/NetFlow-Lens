package filter

import (
	"reflect"
	"testing"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

func TestNewFilterManager(t *testing.T) {
	fm := NewFilterManager()
	
	if fm == nil {
		t.Fatal("NewFilterManager returned nil")
	}
	
	if fm.filters == nil {
		t.Error("filters map not initialized")
	}
	
	if fm.stats == nil {
		t.Error("stats not initialized")
	}
	
	if fm.presets == nil {
		t.Error("presets not initialized")
	}
	
	// Check that presets are loaded
	presets := fm.GetPresetFilters()
	if len(presets) == 0 {
		t.Error("no preset filters loaded")
	}
}

func TestValidateFilter(t *testing.T) {
	fm := NewFilterManager()
	
	tests := []struct {
		name       string
		expression string
		wantValid  bool
	}{
		{
			name:       "valid tcp port filter",
			expression: "tcp port 80",
			wantValid:  true,
		},
		{
			name:       "valid udp port filter",
			expression: "udp port 53",
			wantValid:  true,
		},
		{
			name:       "valid complex filter",
			expression: "tcp port 80 or tcp port 443",
			wantValid:  true,
		},
		{
			name:       "valid host filter",
			expression: "host 192.168.1.1",
			wantValid:  true,
		},
		{
			name:       "valid protocol filter",
			expression: "icmp",
			wantValid:  true,
		},
		{
			name:       "invalid syntax",
			expression: "tcp port xyz",
			wantValid:  false,
		},
		{
			name:       "empty expression",
			expression: "",
			wantValid:  false,
		},
		{
			name:       "malformed expression",
			expression: "tcp port 80 and and tcp port 443",
			wantValid:  false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fm.ValidateFilter(tt.expression)
			
			if result == nil {
				t.Fatal("ValidateFilter returned nil")
			}
			
			if result.IsValid != tt.wantValid {
				t.Errorf("ValidateFilter(%q).IsValid = %v, want %v", 
					tt.expression, result.IsValid, tt.wantValid)
				if !tt.wantValid {
					t.Logf("Error message: %s", result.ErrorMessage)
				}
			}
			
			if !tt.wantValid && result.ErrorMessage == "" {
				t.Error("Expected error message for invalid filter")
			}
		})
	}
}

func TestParseFilterExpression(t *testing.T) {
	fm := NewFilterManager()
	
	tests := []struct {
		name          string
		expression    string
		wantProtocols []string
		wantPorts     []int
		wantIPs       []string
	}{
		{
			name:          "tcp port 80",
			expression:    "tcp port 80",
			wantProtocols: []string{"TCP"},
			wantPorts:     []int{80},
			wantIPs:       []string{},
		},
		{
			name:          "udp port 53",
			expression:    "udp port 53",
			wantProtocols: []string{"UDP"},
			wantPorts:     []int{53},
			wantIPs:       []string{},
		},
		{
			name:          "host filter",
			expression:    "host 192.168.1.1",
			wantProtocols: []string{},
			wantPorts:     []int{},
			wantIPs:       []string{"192.168.1.1"},
		},
		{
			name:          "complex expression",
			expression:    "tcp port 80 or udp port 53 and host 10.0.0.1",
			wantProtocols: []string{"TCP", "UDP"},
			wantPorts:     []int{80, 53},
			wantIPs:       []string{"10.0.0.1"},
		},
		{
			name:          "multiple ports",
			expression:    "tcp port 80 or tcp port 443 or tcp port 8080",
			wantProtocols: []string{"TCP"},
			wantPorts:     []int{80, 443, 8080},
			wantIPs:       []string{},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.FilterValidationResult{}
			fm.parseFilterExpression(tt.expression, result)
			
			if !reflect.DeepEqual(result.ParsedFields.Protocols, tt.wantProtocols) {
				t.Errorf("parseFilterExpression protocols = %v, want %v", 
					result.ParsedFields.Protocols, tt.wantProtocols)
			}
			
			if !reflect.DeepEqual(result.ParsedFields.Ports, tt.wantPorts) {
				t.Errorf("parseFilterExpression ports = %v, want %v", 
					result.ParsedFields.Ports, tt.wantPorts)
			}
			
			if !reflect.DeepEqual(result.ParsedFields.IPs, tt.wantIPs) {
				t.Errorf("parseFilterExpression IPs = %v, want %v", 
					result.ParsedFields.IPs, tt.wantIPs)
			}
		})
	}
}

func TestAddFilter(t *testing.T) {
	fm := NewFilterManager()
	
	rule := &models.FilterRule{
		Name:        "Test Filter",
		Expression:  "tcp port 80",
		Description: "Test HTTP filter",
		IsActive:    true,
	}
	
	err := fm.AddFilter(rule)
	if err != nil {
		t.Fatalf("AddFilter failed: %v", err)
	}
	
	// Check that ID was generated
	if rule.ID == "" {
		t.Error("Filter ID was not generated")
	}
	
	// Check that timestamps were set
	if rule.CreatedAt.IsZero() {
		t.Error("CreatedAt timestamp not set")
	}
	if rule.UpdatedAt.IsZero() {
		t.Error("UpdatedAt timestamp not set")
	}
	
	// Check that filter was stored
	filters := fm.ListFilters()
	if len(filters) != 1 {
		t.Errorf("Expected 1 filter, got %d", len(filters))
	}
	
	// Test invalid filter
	invalidRule := &models.FilterRule{
		Name:       "Invalid Filter",
		Expression: "invalid syntax",
		IsActive:   true,
	}
	
	err = fm.AddFilter(invalidRule)
	if err == nil {
		t.Error("Expected error for invalid filter expression")
	}
}

func TestUpdateFilter(t *testing.T) {
	fm := NewFilterManager()
	
	// Add initial filter
	rule := &models.FilterRule{
		Name:        "Original Filter",
		Expression:  "tcp port 80",
		Description: "Original description",
		IsActive:    true,
	}
	
	err := fm.AddFilter(rule)
	if err != nil {
		t.Fatalf("AddFilter failed: %v", err)
	}
	
	originalID := rule.ID
	originalCreatedAt := rule.CreatedAt
	
	// Wait a bit to ensure UpdatedAt changes
	time.Sleep(time.Millisecond)
	
	// Update the filter
	updates := &models.FilterRule{
		Name:        "Updated Filter",
		Expression:  "tcp port 443",
		Description: "Updated description",
		IsActive:    false,
	}
	
	err = fm.UpdateFilter(originalID, updates)
	if err != nil {
		t.Fatalf("UpdateFilter failed: %v", err)
	}
	
	// Verify updates
	updated, err := fm.GetFilter(originalID)
	if err != nil {
		t.Fatalf("GetFilter failed: %v", err)
	}
	
	if updated.Name != "Updated Filter" {
		t.Errorf("Name not updated: got %s, want %s", updated.Name, "Updated Filter")
	}
	if updated.Expression != "tcp port 443" {
		t.Errorf("Expression not updated: got %s, want %s", updated.Expression, "tcp port 443")
	}
	if updated.Description != "Updated description" {
		t.Errorf("Description not updated: got %s, want %s", updated.Description, "Updated description")
	}
	if updated.IsActive != false {
		t.Errorf("IsActive not updated: got %v, want %v", updated.IsActive, false)
	}
	
	// Check that CreatedAt didn't change but UpdatedAt did
	if !updated.CreatedAt.Equal(originalCreatedAt) {
		t.Error("CreatedAt should not change on update")
	}
	if !updated.UpdatedAt.After(originalCreatedAt) {
		t.Error("UpdatedAt should be after CreatedAt")
	}
	
	// Test updating non-existent filter
	err = fm.UpdateFilter("nonexistent", updates)
	if err == nil {
		t.Error("Expected error for non-existent filter")
	}
	
	// Test invalid expression update
	invalidUpdates := &models.FilterRule{
		Expression: "invalid syntax",
	}
	err = fm.UpdateFilter(originalID, invalidUpdates)
	if err == nil {
		t.Error("Expected error for invalid expression")
	}
}

func TestDeleteFilter(t *testing.T) {
	fm := NewFilterManager()
	
	// Add filter
	rule := &models.FilterRule{
		Name:       "Test Filter",
		Expression: "tcp port 80",
		IsActive:   true,
	}
	
	err := fm.AddFilter(rule)
	if err != nil {
		t.Fatalf("AddFilter failed: %v", err)
	}
	
	filterID := rule.ID
	
	// Set as active filter
	err = fm.SetActiveFilter(filterID)
	if err != nil {
		t.Fatalf("SetActiveFilter failed: %v", err)
	}
	
	// Delete the filter
	err = fm.DeleteFilter(filterID)
	if err != nil {
		t.Fatalf("DeleteFilter failed: %v", err)
	}
	
	// Verify filter is deleted
	_, err = fm.GetFilter(filterID)
	if err == nil {
		t.Error("Expected error for deleted filter")
	}
	
	// Verify active filter is cleared
	activeFilter := fm.GetActiveFilter()
	if activeFilter != nil {
		t.Error("Active filter should be cleared when deleted")
	}
	
	// Test deleting non-existent filter
	err = fm.DeleteFilter("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent filter")
	}
}

func TestGetFilter(t *testing.T) {
	fm := NewFilterManager()
	
	// Add filter
	rule := &models.FilterRule{
		Name:       "Test Filter",
		Expression: "tcp port 80",
		IsActive:   true,
	}
	
	err := fm.AddFilter(rule)
	if err != nil {
		t.Fatalf("AddFilter failed: %v", err)
	}
	
	filterID := rule.ID
	
	// Get the filter
	retrieved, err := fm.GetFilter(filterID)
	if err != nil {
		t.Fatalf("GetFilter failed: %v", err)
	}
	
	if retrieved.ID != rule.ID {
		t.Errorf("ID mismatch: got %s, want %s", retrieved.ID, rule.ID)
	}
	if retrieved.Name != rule.Name {
		t.Errorf("Name mismatch: got %s, want %s", retrieved.Name, rule.Name)
	}
	
	// Test getting non-existent filter
	_, err = fm.GetFilter("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent filter")
	}
}

func TestListFilters(t *testing.T) {
	fm := NewFilterManager()
	
	// Initially should have no filters
	filters := fm.ListFilters()
	if len(filters) != 0 {
		t.Errorf("Expected 0 filters initially, got %d", len(filters))
	}
	
	// Add multiple filters
	rules := []*models.FilterRule{
		{Name: "Filter 1", Expression: "tcp port 80", IsActive: true},
		{Name: "Filter 2", Expression: "udp port 53", IsActive: false},
		{Name: "Filter 3", Expression: "icmp", IsActive: true},
	}
	
	for _, rule := range rules {
		err := fm.AddFilter(rule)
		if err != nil {
			t.Fatalf("AddFilter failed: %v", err)
		}
	}
	
	// List all filters
	filters = fm.ListFilters()
	if len(filters) != 3 {
		t.Errorf("Expected 3 filters, got %d", len(filters))
	}
	
	// Verify filters are copies (not references)
	// 找到一个特定的过滤器进行测试
	var testFilter *models.FilterRule
	for _, filter := range filters {
		if filter.Name == "Filter 1" {
			testFilter = filter
			break
		}
	}
	
	if testFilter == nil {
		t.Fatal("Could not find Filter 1 for testing")
	}
	
	originalName := testFilter.Name
	testFilter.Name = "Modified"
	
	// 获取新的列表并验证原始数据没有被修改
	newList := fm.ListFilters()
	var foundOriginal bool
	for _, filter := range newList {
		if filter.ID == testFilter.ID && filter.Name == originalName {
			foundOriginal = true
			break
		}
	}
	
	if !foundOriginal {
		t.Error("ListFilters should return copies, not references")
	}
}

func TestSetActiveFilter(t *testing.T) {
	fm := NewFilterManager()
	
	// Add filters
	rule1 := &models.FilterRule{
		Name:       "Filter 1",
		Expression: "tcp port 80",
		IsActive:   true,
	}
	rule2 := &models.FilterRule{
		Name:       "Filter 2",
		Expression: "udp port 53",
		IsActive:   false,
	}
	
	err := fm.AddFilter(rule1)
	if err != nil {
		t.Fatalf("AddFilter failed: %v", err)
	}
	err = fm.AddFilter(rule2)
	if err != nil {
		t.Fatalf("AddFilter failed: %v", err)
	}
	
	// Set active filter
	err = fm.SetActiveFilter(rule1.ID)
	if err != nil {
		t.Fatalf("SetActiveFilter failed: %v", err)
	}
	
	activeFilter := fm.GetActiveFilter()
	if activeFilter == nil {
		t.Fatal("GetActiveFilter returned nil")
	}
	if activeFilter.ID != rule1.ID {
		t.Errorf("Active filter ID mismatch: got %s, want %s", activeFilter.ID, rule1.ID)
	}
	
	// Test setting inactive filter as active
	err = fm.SetActiveFilter(rule2.ID)
	if err == nil {
		t.Error("Expected error when setting inactive filter as active")
	}
	
	// Test clearing active filter
	err = fm.SetActiveFilter("")
	if err != nil {
		t.Fatalf("SetActiveFilter(\"\") failed: %v", err)
	}
	
	activeFilter = fm.GetActiveFilter()
	if activeFilter != nil {
		t.Error("Active filter should be nil after clearing")
	}
	
	// Test setting non-existent filter
	err = fm.SetActiveFilter("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent filter")
	}
}

func TestGetActiveFilterExpression(t *testing.T) {
	fm := NewFilterManager()
	
	// Initially no active filter
	expression := fm.GetActiveFilterExpression()
	if expression != "" {
		t.Errorf("Expected empty expression, got %s", expression)
	}
	
	// Add and set active filter
	rule := &models.FilterRule{
		Name:       "Test Filter",
		Expression: "tcp port 80",
		IsActive:   true,
	}
	
	err := fm.AddFilter(rule)
	if err != nil {
		t.Fatalf("AddFilter failed: %v", err)
	}
	
	err = fm.SetActiveFilter(rule.ID)
	if err != nil {
		t.Fatalf("SetActiveFilter failed: %v", err)
	}
	
	expression = fm.GetActiveFilterExpression()
	if expression != "tcp port 80" {
		t.Errorf("Expected 'tcp port 80', got %s", expression)
	}
}

func TestUpdateStats(t *testing.T) {
	fm := NewFilterManager()
	
	// Update stats
	fm.UpdateStats(1000, 800, 20)
	
	stats := fm.GetStats()
	if stats.TotalPackets != 1000 {
		t.Errorf("TotalPackets = %d, want 1000", stats.TotalPackets)
	}
	if stats.FilteredPackets != 800 {
		t.Errorf("FilteredPackets = %d, want 800", stats.FilteredPackets)
	}
	if stats.DroppedPackets != 20 {
		t.Errorf("DroppedPackets = %d, want 20", stats.DroppedPackets)
	}
	if stats.FilterRatio != 0.8 {
		t.Errorf("FilterRatio = %f, want 0.8", stats.FilterRatio)
	}
	
	// Test zero total packets
	fm.UpdateStats(0, 0, 0)
	stats = fm.GetStats()
	if stats.FilterRatio != 0.0 {
		t.Errorf("FilterRatio with zero packets = %f, want 0.0", stats.FilterRatio)
	}
}

func TestGetPresetFilters(t *testing.T) {
	fm := NewFilterManager()
	
	presets := fm.GetPresetFilters()
	if len(presets) == 0 {
		t.Error("No preset filters returned")
	}
	
	// Check for expected presets
	presetMap := make(map[string]*models.PresetFilter)
	for _, preset := range presets {
		presetMap[preset.ID] = preset
	}
	
	expectedPresets := []string{
		"preset_http",
		"preset_https", 
		"preset_dns",
		"preset_ssh",
		"preset_tcp_only",
		"preset_udp_only",
	}
	
	for _, expectedID := range expectedPresets {
		if _, exists := presetMap[expectedID]; !exists {
			t.Errorf("Expected preset %s not found", expectedID)
		}
	}
	
	// Verify preset structure
	httpPreset := presetMap["preset_http"]
	if httpPreset != nil {
		if httpPreset.Name == "" {
			t.Error("HTTP preset name is empty")
		}
		if httpPreset.Expression == "" {
			t.Error("HTTP preset expression is empty")
		}
		if httpPreset.Category == "" {
			t.Error("HTTP preset category is empty")
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	fm := NewFilterManager()
	
	// Test concurrent add/read operations
	done := make(chan bool, 2)
	
	// Writer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			rule := &models.FilterRule{
				Name:       "Filter " + string(rune(i)),
				Expression: "tcp port 80",
				IsActive:   true,
			}
			fm.AddFilter(rule)
		}
		done <- true
	}()
	
	// Reader goroutine
	go func() {
		for i := 0; i < 10; i++ {
			fm.ListFilters()
			fm.GetStats()
		}
		done <- true
	}()
	
	// Wait for both goroutines
	<-done
	<-done
	
	// Verify final state
	filters := fm.ListFilters()
	if len(filters) != 10 {
		t.Errorf("Expected 10 filters after concurrent operations, got %d", len(filters))
	}
}

func TestGenerateFilterID(t *testing.T) {
	id1 := generateFilterID()
	// 添加一个小延迟确保纳秒时间戳不同
	time.Sleep(time.Nanosecond * 100)
	id2 := generateFilterID()
	
	if id1 == id2 {
		t.Errorf("generateFilterID should generate unique IDs, got %s and %s", id1, id2)
	}
	
	if id1 == "" || id2 == "" {
		t.Error("generateFilterID should not return empty strings")
	}
	
	// Check format
	if len(id1) < 10 {
		t.Error("Generated ID seems too short")
	}
	
	// Test multiple IDs for uniqueness
	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		id := generateFilterID()
		if ids[id] {
			t.Errorf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
		time.Sleep(time.Nanosecond * 10)
	}
}

// Benchmark tests
func BenchmarkValidateFilter(b *testing.B) {
	fm := NewFilterManager()
	expression := "tcp port 80 or udp port 53"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fm.ValidateFilter(expression)
	}
}

func BenchmarkAddFilter(b *testing.B) {
	fm := NewFilterManager()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule := &models.FilterRule{
			Name:       "Benchmark Filter",
			Expression: "tcp port 80",
			IsActive:   true,
		}
		fm.AddFilter(rule)
	}
}

func BenchmarkListFilters(b *testing.B) {
	fm := NewFilterManager()
	
	// Add some filters first
	for i := 0; i < 100; i++ {
		rule := &models.FilterRule{
			Name:       "Filter " + string(rune(i)),
			Expression: "tcp port 80",
			IsActive:   true,
		}
		fm.AddFilter(rule)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fm.ListFilters()
	}
}