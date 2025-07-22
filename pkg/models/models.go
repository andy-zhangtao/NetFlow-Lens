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
	Timestamp time.Time `json:"timestamp"`
	Length    int       `json:"length"`
	Protocol  string    `json:"protocol"`
	SourceIP  string    `json:"source_ip"`
	DestIP    string    `json:"dest_ip"`
	Payload   []byte    `json:"payload,omitempty"`
}