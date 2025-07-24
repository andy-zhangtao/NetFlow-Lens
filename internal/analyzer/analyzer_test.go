package analyzer

import (
	"testing"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

func TestNewAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()

	if analyzer == nil {
		t.Fatal("NewAnalyzer returned nil")
	}

	if analyzer.maxPackets != 1000 {
		t.Errorf("Expected maxPackets to be 1000, got %d", analyzer.maxPackets)
	}

	if len(analyzer.connections) != 0 {
		t.Errorf("Expected empty connections map, got %d connections", len(analyzer.connections))
	}

	if len(analyzer.recentPackets) != 0 {
		t.Errorf("Expected empty recentPackets slice, got %d packets", len(analyzer.recentPackets))
	}

	if analyzer.bufferIndex != 0 {
		t.Errorf("Expected bufferIndex to be 0, got %d", analyzer.bufferIndex)
	}
}

func TestClearData(t *testing.T) {
	analyzer := NewAnalyzer()

	// Add some test data
	packet := models.Packet{
		Timestamp:  time.Now(),
		Length:     64,
		Protocol:   "TCP",
		SourceIP:   "192.168.1.1",
		DestIP:     "192.168.1.2",
		SourcePort: 80,
		DestPort:   8080,
		TCPFlags:   []string{"SYN"},
	}

	analyzer.ProcessPacket(packet)

	// Verify data was added
	if len(analyzer.recentPackets) == 0 {
		t.Error("Expected packet to be added to recentPackets")
	}

	if len(analyzer.connections) == 0 {
		t.Error("Expected connection to be created")
	}

	// Clear data
	analyzer.ClearData()

	// Verify data was cleared
	if len(analyzer.recentPackets) != 0 {
		t.Errorf("Expected recentPackets to be empty after clear, got %d", len(analyzer.recentPackets))
	}

	if len(analyzer.connections) != 0 {
		t.Errorf("Expected connections to be empty after clear, got %d", len(analyzer.connections))
	}

	if analyzer.bufferIndex != 0 {
		t.Errorf("Expected bufferIndex to be reset to 0, got %d", analyzer.bufferIndex)
	}
}

func TestProcessPacket(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name   string
		packet models.Packet
	}{
		{
			name: "tcp syn packet",
			packet: models.Packet{
				Timestamp:  time.Now(),
				Length:     64,
				Protocol:   "TCP",
				SourceIP:   "192.168.1.1",
				DestIP:     "192.168.1.2",
				SourcePort: 80,
				DestPort:   8080,
				TCPFlags:   []string{"SYN"},
				SeqNum:     12345,
			},
		},
		{
			name: "udp packet",
			packet: models.Packet{
				Timestamp:  time.Now(),
				Length:     32,
				Protocol:   "UDP",
				SourceIP:   "10.0.0.1",
				DestIP:     "10.0.0.2",
				SourcePort: 53,
				DestPort:   53,
			},
		},
		{
			name: "icmp packet",
			packet: models.Packet{
				Timestamp: time.Now(),
				Length:    28,
				Protocol:  "ICMP",
				SourceIP:  "192.168.1.1",
				DestIP:    "8.8.8.8",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialPacketCount := len(analyzer.recentPackets)
			analyzer.ProcessPacket(tt.packet)

			// Check that packet was added to recent packets
			if len(analyzer.recentPackets) != initialPacketCount+1 {
				t.Errorf("Expected packet count to increase by 1, got %d", len(analyzer.recentPackets))
			}

			// Check that connection was created for TCP/UDP
			if tt.packet.Protocol == "TCP" || tt.packet.Protocol == "UDP" {
				if len(analyzer.connections) == 0 {
					t.Error("Expected connection to be created for TCP/UDP packet")
				}
			}
		})
	}
}

func TestDetermineTCPState(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name          string
		flags         []string
		expectedState string
	}{
		{"syn", []string{"SYN"}, "SYN_SENT"},
		{"syn ack", []string{"SYN", "ACK"}, "SYN_RECEIVED"},
		{"ack", []string{"ACK"}, "ESTABLISHED"},
		{"fin", []string{"FIN"}, "FIN_WAIT"},
		{"rst", []string{"RST"}, "RESET"},
		{"psh ack", []string{"PSH", "ACK"}, "ESTABLISHED"},
		{"empty", []string{}, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := models.Packet{
				Protocol: "TCP",
				TCPFlags: tt.flags,
			}

			state := analyzer.determineTCPState(packet)
			if state != tt.expectedState {
				t.Errorf("Expected state %s, got %s", tt.expectedState, state)
			}
		})
	}
}

func TestUpdateTCPConnectionState(t *testing.T) {
	analyzer := NewAnalyzer()

	// Create a connection in SYN_SENT state
	conn := &models.Connection{
		ID:       "test_conn",
		Protocol: "TCP",
		State:    "SYN_SENT",
	}

	tests := []struct {
		name          string
		flags         []string
		expectedState string
	}{
		{"syn ack response", []string{"SYN", "ACK"}, "SYN_RECEIVED"},
		{"established", []string{"ACK"}, "ESTABLISHED"},
		{"fin termination", []string{"FIN"}, "FIN_WAIT"},
		{"reset", []string{"RST"}, "RESET"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset connection state for each test
			if tt.name == "syn ack response" {
				conn.State = "SYN_SENT"
			} else if tt.name == "established" {
				conn.State = "SYN_RECEIVED"
			} else {
				conn.State = "ESTABLISHED"
			}

			packet := models.Packet{
				Protocol: "TCP",
				TCPFlags: tt.flags,
			}

			analyzer.updateTCPConnectionState(conn, packet)
			if conn.State != tt.expectedState {
				t.Errorf("Expected state %s, got %s", tt.expectedState, conn.State)
			}
		})
	}
}

func TestGetRecentPackets(t *testing.T) {
	analyzer := NewAnalyzer()

	// Add test packets
	packets := []models.Packet{
		{Timestamp: time.Now().Add(-3 * time.Second), Protocol: "TCP", Length: 64},
		{Timestamp: time.Now().Add(-2 * time.Second), Protocol: "UDP", Length: 32},
		{Timestamp: time.Now().Add(-1 * time.Second), Protocol: "TCP", Length: 128},
	}

	for _, packet := range packets {
		analyzer.ProcessPacket(packet)
	}

	tests := []struct {
		name     string
		limit    int
		expected int
	}{
		{"get all packets", 10, 3},
		{"get limited packets", 2, 2},
		{"get one packet", 1, 1},
		{"get zero packets", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.GetRecentPackets(tt.limit)
			if len(result) != tt.expected {
				t.Errorf("Expected %d packets, got %d", tt.expected, len(result))
			}

			// Verify packets are in reverse chronological order (newest first)
			if len(result) > 1 {
				for i := 0; i < len(result)-1; i++ {
					if result[i].Timestamp.Before(result[i+1].Timestamp) {
						t.Error("Packets should be in reverse chronological order")
						break
					}
				}
			}
		})
	}
}

func TestGetConnections(t *testing.T) {
	analyzer := NewAnalyzer()

	// Add test connections through packets
	packets := []models.Packet{
		{
			Timestamp:  time.Now(),
			Protocol:   "TCP",
			SourceIP:   "192.168.1.1",
			DestIP:     "192.168.1.2",
			SourcePort: 80,
			DestPort:   8080,
			TCPFlags:   []string{"SYN"},
		},
		{
			Timestamp:  time.Now(),
			Protocol:   "UDP",
			SourceIP:   "10.0.0.1",
			DestIP:     "10.0.0.2",
			SourcePort: 53,
			DestPort:   53,
		},
	}

	for _, packet := range packets {
		analyzer.ProcessPacket(packet)
	}

	connections := analyzer.GetConnections()

	if len(connections) != 2 {
		t.Errorf("Expected 2 connections, got %d", len(connections))
	}

	// Check that connections have correct protocols
	protocolCount := make(map[string]int)
	for _, conn := range connections {
		protocolCount[conn.Protocol]++
	}

	if protocolCount["TCP"] != 1 {
		t.Errorf("Expected 1 TCP connection, got %d", protocolCount["TCP"])
	}
	if protocolCount["UDP"] != 1 {
		t.Errorf("Expected 1 UDP connection, got %d", protocolCount["UDP"])
	}
}

func TestGetConnectionStats(t *testing.T) {
	analyzer := NewAnalyzer()

	// Add test packets to create connections
	packets := []models.Packet{
		{Protocol: "TCP", SourceIP: "192.168.1.1", DestIP: "192.168.1.2", SourcePort: 80, DestPort: 8080, TCPFlags: []string{"SYN"}},
		{Protocol: "TCP", SourceIP: "192.168.1.3", DestIP: "192.168.1.4", SourcePort: 443, DestPort: 8443, TCPFlags: []string{"ACK"}},
		{Protocol: "UDP", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", SourcePort: 53, DestPort: 53},
	}

	for _, packet := range packets {
		analyzer.ProcessPacket(packet)
	}

	stats := analyzer.GetConnectionStats()

	// Check total connections
	totalConnections, ok := stats["total_connections"].(int)
	if !ok || totalConnections != 3 {
		t.Errorf("Expected 3 total connections, got %v", stats["total_connections"])
	}

	// Check protocol distribution
	protocols, ok := stats["protocols"].(map[string]int)
	if !ok {
		t.Error("Expected protocols to be map[string]int")
	} else {
		if protocols["TCP"] != 2 {
			t.Errorf("Expected 2 TCP connections, got %d", protocols["TCP"])
		}
		if protocols["UDP"] != 1 {
			t.Errorf("Expected 1 UDP connection, got %d", protocols["UDP"])
		}
	}
}

func TestGenerateConnectionID(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		packet   models.Packet
		expected string
	}{
		{
			name: "tcp packet",
			packet: models.Packet{
				Protocol:   "TCP",
				SourceIP:   "192.168.1.1",
				DestIP:     "192.168.1.2",
				SourcePort: 80,
				DestPort:   8080,
			},
			expected: "192.168.1.1:80_192.168.1.2:8080_TCP",
		},
		{
			name: "udp packet",
			packet: models.Packet{
				Protocol:   "UDP",
				SourceIP:   "10.0.0.1",
				DestIP:     "10.0.0.2",
				SourcePort: 53,
				DestPort:   53,
			},
			expected: "10.0.0.1:53_10.0.0.2:53_UDP",
		},
		{
			name: "icmp packet",
			packet: models.Packet{
				Protocol: "ICMP",
				SourceIP: "192.168.1.1",
				DestIP:   "8.8.8.8",
			},
			expected: "192.168.1.1_8.8.8.8_ICMP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.generateConnectionID(tt.packet)
			if result != tt.expected {
				t.Errorf("Expected connection ID %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestConcurrentAccess(t *testing.T) {
	analyzer := NewAnalyzer()

	// Test concurrent packet processing
	done := make(chan bool)
	numGoroutines := 10
	packetsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < packetsPerGoroutine; j++ {
				packet := models.Packet{
					Timestamp:  time.Now(),
					Protocol:   "TCP",
					SourceIP:   "192.168.1.1",
					DestIP:     "192.168.1.2",
					SourcePort: 80 + id,
					DestPort:   8080 + j,
					TCPFlags:   []string{"ACK"},
				}
				analyzer.ProcessPacket(packet)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify that all packets were processed
	packets := analyzer.GetRecentPackets(numGoroutines * packetsPerGoroutine)
	if len(packets) != numGoroutines*packetsPerGoroutine {
		t.Errorf("Expected %d packets, got %d", numGoroutines*packetsPerGoroutine, len(packets))
	}

	// Verify that connections were created
	connections := analyzer.GetConnections()
	if len(connections) == 0 {
		t.Error("Expected connections to be created")
	}
}

// Benchmark tests
func BenchmarkProcessPacket(b *testing.B) {
	analyzer := NewAnalyzer()
	packet := models.Packet{
		Timestamp:  time.Now(),
		Length:     64,
		Protocol:   "TCP",
		SourceIP:   "192.168.1.1",
		DestIP:     "192.168.1.2",
		SourcePort: 80,
		DestPort:   8080,
		TCPFlags:   []string{"ACK"},
		SeqNum:     12345,
		AckNum:     67890,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.ProcessPacket(packet)
	}
}

func BenchmarkGetRecentPackets(b *testing.B) {
	analyzer := NewAnalyzer()

	// Add some test packets
	for i := 0; i < 1000; i++ {
		packet := models.Packet{
			Timestamp:  time.Now(),
			Protocol:   "TCP",
			SourceIP:   "192.168.1.1",
			DestIP:     "192.168.1.2",
			SourcePort: 80,
			DestPort:   8080 + i,
		}
		analyzer.ProcessPacket(packet)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.GetRecentPackets(100)
	}
}