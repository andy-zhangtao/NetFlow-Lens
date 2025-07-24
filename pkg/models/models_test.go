package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAPIStatus(t *testing.T) {
	tests := []struct {
		name   string
		status APIStatus
	}{
		{
			name: "basic api status",
			status: APIStatus{
				Status:  "running",
				Version: "1.0.0",
				Message: "API is running",
			},
		},
		{
			name: "empty api status",
			status: APIStatus{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.status)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled APIStatus
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare fields
			if unmarshaled.Status != tt.status.Status {
				t.Errorf("Status mismatch: got %s, want %s", unmarshaled.Status, tt.status.Status)
			}
			if unmarshaled.Version != tt.status.Version {
				t.Errorf("Version mismatch: got %s, want %s", unmarshaled.Version, tt.status.Version)
			}
			if unmarshaled.Message != tt.status.Message {
				t.Errorf("Message mismatch: got %s, want %s", unmarshaled.Message, tt.status.Message)
			}
		})
	}
}

func TestConnection(t *testing.T) {
	now := time.Now()
	
	tests := []struct {
		name       string
		connection Connection
	}{
		{
			name: "tcp connection",
			connection: Connection{
				ID:         "conn_1",
				SourceIP:   "192.168.1.100",
				SourcePort: 80,
				DestIP:     "10.0.0.1",
				DestPort:   443,
				Protocol:   "TCP",
				State:      "ESTABLISHED",
				StartTime:  now,
				EndTime:    now.Add(time.Minute),
			},
		},
		{
			name: "udp connection",
			connection: Connection{
				ID:         "conn_2",
				SourceIP:   "127.0.0.1",
				SourcePort: 53,
				DestIP:     "8.8.8.8",
				DestPort:   53,
				Protocol:   "UDP",
				State:      "ACTIVE",
				StartTime:  now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.connection)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled Connection
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare key fields
			if unmarshaled.ID != tt.connection.ID {
				t.Errorf("ID mismatch: got %s, want %s", unmarshaled.ID, tt.connection.ID)
			}
			if unmarshaled.SourceIP != tt.connection.SourceIP {
				t.Errorf("SourceIP mismatch: got %s, want %s", unmarshaled.SourceIP, tt.connection.SourceIP)
			}
			if unmarshaled.Protocol != tt.connection.Protocol {
				t.Errorf("Protocol mismatch: got %s, want %s", unmarshaled.Protocol, tt.connection.Protocol)
			}
		})
	}
}

func TestPacket(t *testing.T) {
	now := time.Now()
	payload := []byte("test payload data")

	tests := []struct {
		name   string
		packet Packet
	}{
		{
			name: "tcp packet with flags",
			packet: Packet{
				Timestamp:   now,
				Length:      64,
				Protocol:    "TCP",
				SourceIP:    "192.168.1.1",
				DestIP:      "192.168.1.2",
				SourcePort:  80,
				DestPort:    8080,
				TCPFlags:    []string{"SYN", "ACK"},
				SeqNum:      12345,
				AckNum:      67890,
				Payload:     payload,
				PayloadSize: len(payload),
			},
		},
		{
			name: "udp packet",
			packet: Packet{
				Timestamp:   now,
				Length:      32,
				Protocol:    "UDP",
				SourceIP:    "10.0.0.1",
				DestIP:      "10.0.0.2",
				SourcePort:  53,
				DestPort:    53,
				PayloadSize: 0,
			},
		},
		{
			name: "minimal packet",
			packet: Packet{
				Timestamp: now,
				Length:    20,
				Protocol:  "ICMP",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.packet)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled Packet
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare fields
			if unmarshaled.Length != tt.packet.Length {
				t.Errorf("Length mismatch: got %d, want %d", unmarshaled.Length, tt.packet.Length)
			}
			if unmarshaled.Protocol != tt.packet.Protocol {
				t.Errorf("Protocol mismatch: got %s, want %s", unmarshaled.Protocol, tt.packet.Protocol)
			}
			if unmarshaled.PayloadSize != tt.packet.PayloadSize {
				t.Errorf("PayloadSize mismatch: got %d, want %d", unmarshaled.PayloadSize, tt.packet.PayloadSize)
			}

			// Test TCP flags
			if len(unmarshaled.TCPFlags) != len(tt.packet.TCPFlags) {
				t.Errorf("TCPFlags length mismatch: got %d, want %d", len(unmarshaled.TCPFlags), len(tt.packet.TCPFlags))
			}
		})
	}
}

func TestPCAPFileInfo(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		fileInfo PCAPFileInfo
	}{
		{
			name: "successful pcap file",
			fileInfo: PCAPFileInfo{
				Filename:    "test.pcap",
				Size:        1024,
				UploadTime:  now,
				PacketCount: 100,
				Status:      "ready",
			},
		},
		{
			name: "failed pcap file",
			fileInfo: PCAPFileInfo{
				Filename:     "invalid.pcap",
				Size:         0,
				UploadTime:   now,
				PacketCount:  0,
				Status:       "error",
				ErrorMessage: "file format not supported",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.fileInfo)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled PCAPFileInfo
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare fields
			if unmarshaled.Filename != tt.fileInfo.Filename {
				t.Errorf("Filename mismatch: got %s, want %s", unmarshaled.Filename, tt.fileInfo.Filename)
			}
			if unmarshaled.Status != tt.fileInfo.Status {
				t.Errorf("Status mismatch: got %s, want %s", unmarshaled.Status, tt.fileInfo.Status)
			}
			if unmarshaled.PacketCount != tt.fileInfo.PacketCount {
				t.Errorf("PacketCount mismatch: got %d, want %d", unmarshaled.PacketCount, tt.fileInfo.PacketCount)
			}
		})
	}
}

func TestPacketTCPFlags(t *testing.T) {
	// Test various TCP flag combinations
	flagTests := []struct {
		name  string
		flags []string
	}{
		{"syn only", []string{"SYN"}},
		{"syn ack", []string{"SYN", "ACK"}},
		{"ack fin", []string{"ACK", "FIN"}},
		{"rst", []string{"RST"}},
		{"all flags", []string{"SYN", "ACK", "FIN", "RST", "PSH", "URG"}},
		{"empty flags", []string{}},
	}

	for _, tt := range flagTests {
		t.Run(tt.name, func(t *testing.T) {
			packet := Packet{
				Timestamp: time.Now(),
				Length:    64,
				Protocol:  "TCP",
				TCPFlags:  tt.flags,
			}

			// Test JSON round trip
			data, err := json.Marshal(packet)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			var unmarshaled Packet
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare flags
			if len(unmarshaled.TCPFlags) != len(tt.flags) {
				t.Errorf("Flag count mismatch: got %d, want %d", len(unmarshaled.TCPFlags), len(tt.flags))
			}

			for i, flag := range tt.flags {
				if i < len(unmarshaled.TCPFlags) && unmarshaled.TCPFlags[i] != flag {
					t.Errorf("Flag mismatch at index %d: got %s, want %s", i, unmarshaled.TCPFlags[i], flag)
				}
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkPacketMarshal(b *testing.B) {
	packet := Packet{
		Timestamp:   time.Now(),
		Length:      1500,
		Protocol:    "TCP",
		SourceIP:    "192.168.1.1",
		DestIP:      "192.168.1.2",
		SourcePort:  80,
		DestPort:    8080,
		TCPFlags:    []string{"ACK", "PSH"},
		SeqNum:      12345,
		AckNum:      67890,
		Payload:     make([]byte, 1000),
		PayloadSize: 1000,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(packet)
		if err != nil {
			b.Errorf("Marshal error: %v", err)
		}
	}
}

func BenchmarkConnectionMarshal(b *testing.B) {
	connection := Connection{
		ID:         "conn_benchmark",
		SourceIP:   "192.168.1.100",
		SourcePort: 80,
		DestIP:     "10.0.0.1",
		DestPort:   443,
		Protocol:   "TCP",
		State:      "ESTABLISHED",
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(time.Minute),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(connection)
		if err != nil {
			b.Errorf("Marshal error: %v", err)
		}
	}
}

// Filter model tests
func TestFilterRule(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		rule FilterRule
	}{
		{
			name: "tcp port filter",
			rule: FilterRule{
				ID:          "filter_1",
				Name:        "HTTP Traffic",
				Expression:  "tcp port 80",
				Description: "Captures HTTP web traffic",
				IsActive:    true,
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		},
		{
			name: "complex filter",
			rule: FilterRule{
				ID:          "filter_2",
				Name:        "Web Traffic",
				Expression:  "tcp port 80 or tcp port 443",
				Description: "Captures HTTP and HTTPS traffic",
				IsActive:    false,
				CreatedAt:   now,
				UpdatedAt:   now.Add(time.Hour),
			},
		},
		{
			name: "minimal filter",
			rule: FilterRule{
				ID:         "filter_3",
				Name:       "Test",
				Expression: "tcp",
				IsActive:   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.rule)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled FilterRule
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare fields
			if unmarshaled.ID != tt.rule.ID {
				t.Errorf("ID mismatch: got %s, want %s", unmarshaled.ID, tt.rule.ID)
			}
			if unmarshaled.Name != tt.rule.Name {
				t.Errorf("Name mismatch: got %s, want %s", unmarshaled.Name, tt.rule.Name)
			}
			if unmarshaled.Expression != tt.rule.Expression {
				t.Errorf("Expression mismatch: got %s, want %s", unmarshaled.Expression, tt.rule.Expression)
			}
			if unmarshaled.IsActive != tt.rule.IsActive {
				t.Errorf("IsActive mismatch: got %v, want %v", unmarshaled.IsActive, tt.rule.IsActive)
			}
		})
	}
}

func TestFilterStats(t *testing.T) {
	tests := []struct {
		name  string
		stats FilterStats
	}{
		{
			name: "basic stats",
			stats: FilterStats{
				TotalPackets:    1000,
				FilteredPackets: 800,
				DroppedPackets:  10,
				FilterRatio:     0.8,
			},
		},
		{
			name: "zero stats",
			stats: FilterStats{
				TotalPackets:    0,
				FilteredPackets: 0,
				DroppedPackets:  0,
				FilterRatio:     0.0,
			},
		},
		{
			name: "perfect filter",
			stats: FilterStats{
				TotalPackets:    500,
				FilteredPackets: 500,
				DroppedPackets:  0,
				FilterRatio:     1.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.stats)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled FilterStats
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare fields
			if unmarshaled.TotalPackets != tt.stats.TotalPackets {
				t.Errorf("TotalPackets mismatch: got %d, want %d", unmarshaled.TotalPackets, tt.stats.TotalPackets)
			}
			if unmarshaled.FilteredPackets != tt.stats.FilteredPackets {
				t.Errorf("FilteredPackets mismatch: got %d, want %d", unmarshaled.FilteredPackets, tt.stats.FilteredPackets)
			}
			if unmarshaled.DroppedPackets != tt.stats.DroppedPackets {
				t.Errorf("DroppedPackets mismatch: got %d, want %d", unmarshaled.DroppedPackets, tt.stats.DroppedPackets)
			}
			if unmarshaled.FilterRatio != tt.stats.FilterRatio {
				t.Errorf("FilterRatio mismatch: got %f, want %f", unmarshaled.FilterRatio, tt.stats.FilterRatio)
			}
		})
	}
}

func TestFilterValidationResult(t *testing.T) {
	tests := []struct {
		name   string
		result FilterValidationResult
	}{
		{
			name: "valid filter",
			result: FilterValidationResult{
				IsValid:      true,
				ErrorMessage: "",
				ParsedFields: struct {
					Protocols []string `json:"protocols"`
					Ports     []int    `json:"ports"`
					IPs       []string `json:"ips"`
				}{
					Protocols: []string{"TCP"},
					Ports:     []int{80, 443},
					IPs:       []string{"192.168.1.1"},
				},
			},
		},
		{
			name: "invalid filter",
			result: FilterValidationResult{
				IsValid:      false,
				ErrorMessage: "syntax error in filter expression",
				ParsedFields: struct {
					Protocols []string `json:"protocols"`
					Ports     []int    `json:"ports"`
					IPs       []string `json:"ips"`
				}{
					Protocols: []string{},
					Ports:     []int{},
					IPs:       []string{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.result)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled FilterValidationResult
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare fields
			if unmarshaled.IsValid != tt.result.IsValid {
				t.Errorf("IsValid mismatch: got %v, want %v", unmarshaled.IsValid, tt.result.IsValid)
			}
			if unmarshaled.ErrorMessage != tt.result.ErrorMessage {
				t.Errorf("ErrorMessage mismatch: got %s, want %s", unmarshaled.ErrorMessage, tt.result.ErrorMessage)
			}
		})
	}
}

func TestPresetFilter(t *testing.T) {
	tests := []struct {
		name   string
		preset PresetFilter
	}{
		{
			name: "http preset",
			preset: PresetFilter{
				ID:          "preset_http",
				Name:        "HTTP Traffic",
				Expression:  "tcp port 80",
				Description: "Captures HTTP web traffic",
				Category:    "protocol",
			},
		},
		{
			name: "dns preset",
			preset: PresetFilter{
				ID:          "preset_dns",
				Name:        "DNS Queries",
				Expression:  "udp port 53",
				Description: "Captures DNS domain resolution traffic",
				Category:    "protocol",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.preset)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled PresetFilter
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare fields
			if unmarshaled.ID != tt.preset.ID {
				t.Errorf("ID mismatch: got %s, want %s", unmarshaled.ID, tt.preset.ID)
			}
			if unmarshaled.Name != tt.preset.Name {
				t.Errorf("Name mismatch: got %s, want %s", unmarshaled.Name, tt.preset.Name)
			}
			if unmarshaled.Expression != tt.preset.Expression {
				t.Errorf("Expression mismatch: got %s, want %s", unmarshaled.Expression, tt.preset.Expression)
			}
			if unmarshaled.Category != tt.preset.Category {
				t.Errorf("Category mismatch: got %s, want %s", unmarshaled.Category, tt.preset.Category)
			}
		})
	}
}

func TestFilterRequest(t *testing.T) {
	tests := []struct {
		name    string
		request FilterRequest
	}{
		{
			name: "filter by id",
			request: FilterRequest{
				FilterID: "filter_123",
			},
		},
		{
			name: "filter by expression",
			request: FilterRequest{
				Expression: "tcp port 80",
			},
		},
		{
			name: "filter and save",
			request: FilterRequest{
				Expression: "udp port 53",
				SaveAs:     "DNS Filter",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.request)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled FilterRequest
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare fields
			if unmarshaled.FilterID != tt.request.FilterID {
				t.Errorf("FilterID mismatch: got %s, want %s", unmarshaled.FilterID, tt.request.FilterID)
			}
			if unmarshaled.Expression != tt.request.Expression {
				t.Errorf("Expression mismatch: got %s, want %s", unmarshaled.Expression, tt.request.Expression)
			}
			if unmarshaled.SaveAs != tt.request.SaveAs {
				t.Errorf("SaveAs mismatch: got %s, want %s", unmarshaled.SaveAs, tt.request.SaveAs)
			}
		})
	}
}

func TestFilterResponse(t *testing.T) {
	now := time.Now()
	
	tests := []struct {
		name     string
		response FilterResponse
	}{
		{
			name: "successful response",
			response: FilterResponse{
				Status:  "success",
				Message: "Filter applied successfully",
				AppliedRule: &FilterRule{
					ID:         "filter_1",
					Name:       "HTTP",
					Expression: "tcp port 80",
					IsActive:   true,
					CreatedAt:  now,
					UpdatedAt:  now,
				},
				Stats: &FilterStats{
					TotalPackets:    100,
					FilteredPackets: 80,
					DroppedPackets:  2,
					FilterRatio:     0.8,
				},
			},
		},
		{
			name: "error response",
			response: FilterResponse{
				Status:       "error",
				Message:      "Invalid filter expression",
				ErrorDetails: "Syntax error at position 10",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.response)
			if err != nil {
				t.Errorf("JSON marshal error: %v", err)
			}

			// Test JSON unmarshaling
			var unmarshaled FilterResponse
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("JSON unmarshal error: %v", err)
			}

			// Compare fields
			if unmarshaled.Status != tt.response.Status {
				t.Errorf("Status mismatch: got %s, want %s", unmarshaled.Status, tt.response.Status)
			}
			if unmarshaled.Message != tt.response.Message {
				t.Errorf("Message mismatch: got %s, want %s", unmarshaled.Message, tt.response.Message)
			}
			if unmarshaled.ErrorDetails != tt.response.ErrorDetails {
				t.Errorf("ErrorDetails mismatch: got %s, want %s", unmarshaled.ErrorDetails, tt.response.ErrorDetails)
			}
		})
	}
}