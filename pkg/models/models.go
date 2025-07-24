package models

import "time"

// APIStatus represents the API status response
type APIStatus struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Message string `json:"message"`
}

// Connection represents a network connection
type Connection struct {
	ID         string    `json:"id"`
	SourceIP   string    `json:"source_ip"`
	SourcePort int       `json:"source_port"`
	DestIP     string    `json:"dest_ip"`
	DestPort   int       `json:"dest_port"`
	Protocol   string    `json:"protocol"`
	State      string    `json:"state"`
	StartTime  time.Time `json:"start_time,omitempty"`
	EndTime    time.Time `json:"end_time,omitempty"`
}

// Packet represents a network packet
type Packet struct {
	Timestamp   time.Time `json:"timestamp"`
	Length      int       `json:"length"`
	Protocol    string    `json:"protocol"`
	SourceIP    string    `json:"source_ip"`
	DestIP      string    `json:"dest_ip"`
	SourcePort  int       `json:"source_port,omitempty"`
	DestPort    int       `json:"dest_port,omitempty"`
	TCPFlags    []string  `json:"tcp_flags,omitempty"`
	SeqNum      uint32    `json:"seq_num,omitempty"`
	AckNum      uint32    `json:"ack_num,omitempty"`
	Payload     []byte    `json:"payload,omitempty"`
	PayloadSize int       `json:"payload_size"`
}

// PCAPFileInfo represents information about an uploaded PCAP file
type PCAPFileInfo struct {
	Filename     string    `json:"filename"`
	Size         int64     `json:"size"`
	UploadTime   time.Time `json:"upload_time"`
	PacketCount  int       `json:"packet_count"`
	Status       string    `json:"status"` // "uploading", "processing", "ready", "error"
	ErrorMessage string    `json:"error_message,omitempty"`
}

// TCPStateTransition represents a TCP state transition event
type TCPStateTransition struct {
	ConnectionID string    `json:"connection_id"`
	FromState    string    `json:"from_state"`
	ToState      string    `json:"to_state"`
	Timestamp    time.Time `json:"timestamp"`
	TriggerFlags []string  `json:"trigger_flags"`
	PacketInfo   string    `json:"packet_info"`
}

// TCPConnectionState represents the current state of a TCP connection with visualization data
type TCPConnectionState struct {
	Connection    Connection           `json:"connection"`
	StateHistory  []TCPStateTransition `json:"state_history"`
	CurrentState  string               `json:"current_state"`
	Duration      float64              `json:"duration"` // in seconds
	PacketCount   int                  `json:"packet_count"`
	BytesSent     int64                `json:"bytes_sent"`
	BytesReceived int64                `json:"bytes_received"`
	IsActive      bool                 `json:"is_active"`
}

// TCPVisualizationData represents all data needed for TCP state visualization
type TCPVisualizationData struct {
	ActiveConnections []TCPConnectionState `json:"active_connections"`
	StateStatistics   map[string]int       `json:"state_statistics"`
	RecentTransitions []TCPStateTransition `json:"recent_transitions"`
	Timestamp         time.Time            `json:"timestamp"`
}
