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