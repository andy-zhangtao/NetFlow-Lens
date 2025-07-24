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

// PerformanceMetrics represents network performance analysis data
type PerformanceMetrics struct {
	ConnectionID       string                 `json:"connection_id"`
	LatencyMetrics     LatencyAnalysis        `json:"latency_metrics"`
	ThroughputMetrics  ThroughputAnalysis     `json:"throughput_metrics"`
	PacketLossMetrics  PacketLossAnalysis     `json:"packet_loss_metrics"`
	QualityMetrics     QualityAnalysis        `json:"quality_metrics"`
	LastUpdate         time.Time              `json:"last_update"`
}

// LatencyAnalysis represents latency-related performance metrics
type LatencyAnalysis struct {
	RTT               float64   `json:"rtt_ms"`                // Round Trip Time in milliseconds
	RTTHistory        []float64 `json:"rtt_history"`           // Historical RTT values (last 100)
	MinRTT            float64   `json:"min_rtt_ms"`            // Minimum RTT observed
	MaxRTT            float64   `json:"max_rtt_ms"`            // Maximum RTT observed
	AvgRTT            float64   `json:"avg_rtt_ms"`            // Average RTT
	RTTVariance       float64   `json:"rtt_variance"`          // RTT variance (jitter indicator)
	HandshakeLatency  float64   `json:"handshake_latency_ms"`  // TCP handshake completion time
	FirstByteLatency  float64   `json:"first_byte_latency_ms"` // Time to first data byte
	LastMeasurement   time.Time `json:"last_measurement"`
}

// ThroughputAnalysis represents throughput-related performance metrics
type ThroughputAnalysis struct {
	UpstreamBps       float64              `json:"upstream_bps"`        // Bytes per second upstream
	DownstreamBps     float64              `json:"downstream_bps"`      // Bytes per second downstream
	TotalBytesSent    int64                `json:"total_bytes_sent"`
	TotalBytesRecv    int64                `json:"total_bytes_received"`
	PacketsSent       int64                `json:"packets_sent"`
	PacketsReceived   int64                `json:"packets_received"`
	ThroughputHistory []ThroughputSnapshot `json:"throughput_history"`  // Historical throughput (last 60 seconds)
	PeakUpstream      float64              `json:"peak_upstream_bps"`
	PeakDownstream    float64              `json:"peak_downstream_bps"`
	WindowSize        int                  `json:"tcp_window_size"`     // TCP window size
	LastUpdate        time.Time            `json:"last_update"`
}

// ThroughputSnapshot represents a point-in-time throughput measurement
type ThroughputSnapshot struct {
	Timestamp     time.Time `json:"timestamp"`
	UpstreamBps   float64   `json:"upstream_bps"`
	DownstreamBps float64   `json:"downstream_bps"`
}

// PacketLossAnalysis represents packet loss and retransmission metrics
type PacketLossAnalysis struct {
	TotalPackets        int64     `json:"total_packets"`
	LostPackets         int64     `json:"lost_packets"`
	PacketLossRate      float64   `json:"packet_loss_rate"`      // Percentage
	RetransmittedPkts   int64     `json:"retransmitted_packets"`
	RetransmissionRate  float64   `json:"retransmission_rate"`   // Percentage
	OutOfOrderPackets   int64     `json:"out_of_order_packets"`
	DuplicatePackets    int64     `json:"duplicate_packets"`
	LastSeqNum          uint32    `json:"last_seq_num"`
	ExpectedSeqNums     []uint32  `json:"expected_seq_nums"`     // Track expected sequence numbers
	ReceivedSeqNums     []uint32  `json:"received_seq_nums"`     // Track received sequence numbers
	LastAnalysis        time.Time `json:"last_analysis"`
}

// QualityAnalysis represents overall connection quality metrics
type QualityAnalysis struct {
	ConnectionScore    float64   `json:"connection_score"`     // Overall score 0-100
	StabilityScore     float64   `json:"stability_score"`      // Stability indicator 0-100
	PerformanceGrade   string    `json:"performance_grade"`    // A, B, C, D, F
	Recommendations    []string  `json:"recommendations"`      // Performance improvement suggestions
	AlertLevel         string    `json:"alert_level"`          // "good", "warning", "critical"
	IssuesDetected     []string  `json:"issues_detected"`      // List of detected issues
	LastEvaluation     time.Time `json:"last_evaluation"`
}

// NetworkPerformanceData represents aggregated performance data for visualization
type NetworkPerformanceData struct {
	OverallMetrics    GlobalPerformanceMetrics `json:"overall_metrics"`
	ConnectionMetrics []PerformanceMetrics     `json:"connection_metrics"`
	TopConnections    []PerformanceMetrics     `json:"top_connections"`       // Top 10 by performance issues
	AlertConnections  []PerformanceMetrics     `json:"alert_connections"`     // Connections with issues
	HistoricalData    []PerformanceSnapshot    `json:"historical_data"`       // Last hour data points
	Timestamp         time.Time                `json:"timestamp"`
}

// GlobalPerformanceMetrics represents overall network performance
type GlobalPerformanceMetrics struct {
	TotalConnections     int                    `json:"total_connections"`
	ActiveConnections    int                    `json:"active_connections"`
	AvgLatency          float64                `json:"avg_latency_ms"`
	AvgThroughput       float64                `json:"avg_throughput_bps"`
	OverallPacketLoss   float64                `json:"overall_packet_loss_rate"`
	NetworkUtilization  float64                `json:"network_utilization"`     // Percentage
	QualityDistribution map[string]int         `json:"quality_distribution"`    // Grade distribution
	AlertSummary        map[string]int         `json:"alert_summary"`           // Alert level counts
	TopProtocols        map[string]ProtocolStats `json:"top_protocols"`
	LastUpdate          time.Time              `json:"last_update"`
}

// ProtocolStats represents protocol-specific performance statistics
type ProtocolStats struct {
	PacketCount   int64   `json:"packet_count"`
	ByteCount     int64   `json:"byte_count"`
	AvgLatency    float64 `json:"avg_latency_ms"`
	PacketLoss    float64 `json:"packet_loss_rate"`
	Connections   int     `json:"connection_count"`
}

// PerformanceSnapshot represents a point-in-time performance measurement
type PerformanceSnapshot struct {
	Timestamp         time.Time `json:"timestamp"`
	AvgLatency        float64   `json:"avg_latency_ms"`
	TotalThroughput   float64   `json:"total_throughput_bps"`
	PacketLossRate    float64   `json:"packet_loss_rate"`
	ActiveConnections int       `json:"active_connections"`
	AlertCount        int       `json:"alert_count"`
}
