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

// ==================== Network Layer Educational Models ====================

// NetworkLayer represents a layer in the OSI or TCP/IP model
type NetworkLayer struct {
	ID          string            `json:"id"`           // Layer identifier (e.g., "physical", "datalink", "network", "transport", "application")
	Name        string            `json:"name"`         // Display name (e.g., "物理层", "数据链路层")
	EnglishName string            `json:"english_name"` // English name (e.g., "Physical Layer")
	Level       int               `json:"level"`        // Layer level (1-7 for OSI, 1-5 for TCP/IP)
	Description string            `json:"description"`  // Layer description
	Functions   []string          `json:"functions"`    // Main functions of this layer
	Protocols   []LayerProtocol   `json:"protocols"`    // Protocols operating at this layer
	Examples    []string          `json:"examples"`     // Real-world examples
	Headers     []HeaderField     `json:"headers"`      // Header fields at this layer
	IsActive    bool              `json:"is_active"`    // Whether this layer is currently processing data
	DataFlow    LayerDataFlow     `json:"data_flow"`    // Current data flow information
}

// LayerProtocol represents a protocol operating at a specific layer
type LayerProtocol struct {
	Name        string `json:"name"`         // Protocol name (e.g., "HTTP", "TCP", "IP")
	FullName    string `json:"full_name"`    // Full protocol name
	Purpose     string `json:"purpose"`      // What this protocol does
	Example     string `json:"example"`      // Example usage
	IsEncrypted bool   `json:"is_encrypted"` // Whether this protocol provides encryption
}

// HeaderField represents a field in a protocol header
type HeaderField struct {
	Name        string `json:"name"`         // Field name
	Size        int    `json:"size"`         // Size in bytes
	Description string `json:"description"`  // What this field contains
	Value       string `json:"value"`        // Current value (if analyzing real packet)
	IsImportant bool   `json:"is_important"` // Whether to highlight this field
}

// LayerDataFlow represents data flow information for a layer
type LayerDataFlow struct {
	BytesIn     int64     `json:"bytes_in"`     // Bytes received
	BytesOut    int64     `json:"bytes_out"`    // Bytes sent
	PacketsIn   int64     `json:"packets_in"`   // Packets received
	PacketsOut  int64     `json:"packets_out"`  // Packets sent
	LastUpdate  time.Time `json:"last_update"`  // Last update time
	Throughput  float64   `json:"throughput"`   // Current throughput in bps
}

// NetworkLayerModel represents the complete network layer model for visualization
type NetworkLayerModel struct {
	ModelType     string         `json:"model_type"`      // "OSI" or "TCP_IP"
	Layers        []NetworkLayer `json:"layers"`          // All layers in the model
	CurrentPacket *PacketJourney `json:"current_packet"`  // Currently visualized packet
	Statistics    LayerStats     `json:"statistics"`      // Overall statistics
	Timestamp     time.Time      `json:"timestamp"`       // Last update time
}

// PacketJourney represents a packet's journey through the network layers
type PacketJourney struct {
	PacketID       string                   `json:"packet_id"`       // Unique packet identifier
	OriginalPacket Packet                   `json:"original_packet"` // The actual packet data
	LayerAnalysis  []PacketLayerAnalysis    `json:"layer_analysis"`  // Analysis at each layer
	CurrentLayer   int                      `json:"current_layer"`   // Currently highlighted layer
	Direction      string                   `json:"direction"`       // "incoming" or "outgoing"
	StartTime      time.Time                `json:"start_time"`      // When processing started
	ProcessingTime map[string]float64       `json:"processing_time"` // Time spent at each layer (ms)
	Encapsulation  []EncapsulationStep      `json:"encapsulation"`   // How data is encapsulated
}

// PacketLayerAnalysis represents how a packet is processed at a specific layer
type PacketLayerAnalysis struct {
	LayerID      string            `json:"layer_id"`      // Which layer this analysis is for
	HeaderData   []HeaderField     `json:"header_data"`   // Extracted header information
	PayloadSize  int               `json:"payload_size"`  // Size of payload at this layer
	Operations   []LayerOperation  `json:"operations"`    // Operations performed at this layer
	Decisions    []LayerDecision   `json:"decisions"`     // Routing/processing decisions made
	NextLayer    string            `json:"next_layer"`    // Which layer to process next
	IsError      bool              `json:"is_error"`      // Whether there was an error
	ErrorMessage string            `json:"error_message"` // Error details if any
}

// LayerOperation represents an operation performed at a network layer
type LayerOperation struct {
	Name        string    `json:"name"`        // Operation name (e.g., "路由查找", "校验和计算")
	Description string    `json:"description"` // What this operation does
	Result      string    `json:"result"`      // Result of the operation
	Duration    float64   `json:"duration_ms"` // How long it took (ms)
	IsSuccess   bool      `json:"is_success"`  // Whether the operation succeeded
}

// LayerDecision represents a decision made at a network layer
type LayerDecision struct {
	DecisionPoint string                 `json:"decision_point"` // What decision was made
	Options       []string               `json:"options"`        // Available options
	ChosenOption  string                 `json:"chosen_option"`  // Which option was chosen
	Reasoning     string                 `json:"reasoning"`      // Why this option was chosen
	Metadata      map[string]interface{} `json:"metadata"`       // Additional decision data
}

// EncapsulationStep represents one step in the data encapsulation process
type EncapsulationStep struct {
	LayerID     string            `json:"layer_id"`     // Which layer performed this step
	Operation   string            `json:"operation"`    // "encapsulate" or "decapsulate"
	HeaderAdded []HeaderField     `json:"header_added"` // Headers added at this step
	Before      EncapsulationData `json:"before"`       // Data before this step
	After       EncapsulationData `json:"after"`        // Data after this step
}

// EncapsulationData represents data at a point in the encapsulation process
type EncapsulationData struct {
	HeaderSize  int    `json:"header_size"`  // Size of headers (bytes)
	PayloadSize int    `json:"payload_size"` // Size of payload (bytes)
	TotalSize   int    `json:"total_size"`   // Total size (bytes)
	Visualization string `json:"visualization"` // ASCII representation for display
}

// LayerStats represents statistics for the layer model
type LayerStats struct {
	TotalPacketsProcessed int64                    `json:"total_packets_processed"`
	LayerThroughput       map[string]float64       `json:"layer_throughput"`       // Throughput per layer
	LayerErrors           map[string]int64         `json:"layer_errors"`           // Error count per layer
	ProtocolDistribution  map[string]int64         `json:"protocol_distribution"`  // Packets per protocol
	AvgProcessingTime     map[string]float64       `json:"avg_processing_time"`    // Average processing time per layer
	LastUpdate            time.Time                `json:"last_update"`
}
