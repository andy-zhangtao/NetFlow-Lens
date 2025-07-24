package analyzer

import (
	"log"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

// PerformanceAnalyzer handles network performance analysis
type PerformanceAnalyzer struct {
	connectionMetrics    map[string]*models.PerformanceMetrics
	globalMetrics        models.GlobalPerformanceMetrics
	historicalSnapshots  []models.PerformanceSnapshot
	tcpHandshakeTracker  map[string]*HandshakeTracker
	mutex                sync.RWMutex
	maxHistorySize       int
	updateCallback       func() // Callback for real-time updates
}

// HandshakeTracker tracks TCP handshake timing
type HandshakeTracker struct {
	ConnectionID string
	SynTime      time.Time
	SynAckTime   time.Time
	AckTime      time.Time
	Completed    bool
}

// NewPerformanceAnalyzer creates a new performance analyzer
func NewPerformanceAnalyzer() *PerformanceAnalyzer {
	return &PerformanceAnalyzer{
		connectionMetrics:   make(map[string]*models.PerformanceMetrics),
		tcpHandshakeTracker: make(map[string]*HandshakeTracker),
		historicalSnapshots: make([]models.PerformanceSnapshot, 0, 3600), // 1 hour of second-by-second data
		maxHistorySize:      3600,
		globalMetrics: models.GlobalPerformanceMetrics{
			QualityDistribution: make(map[string]int),
			AlertSummary:        make(map[string]int),
			TopProtocols:        make(map[string]models.ProtocolStats),
		},
	}
}

// SetUpdateCallback sets callback function for real-time updates
func (pa *PerformanceAnalyzer) SetUpdateCallback(callback func()) {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()
	pa.updateCallback = callback
}

// ProcessPacket analyzes a packet for performance metrics
func (pa *PerformanceAnalyzer) ProcessPacket(packet models.Packet, connectionID string) {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()

	// Get or create performance metrics for this connection
	perfMetrics := pa.getOrCreateMetrics(connectionID)
	
	// Update throughput metrics
	pa.updateThroughputMetrics(perfMetrics, packet)
	
	// Handle TCP-specific analysis
	if packet.Protocol == "TCP" {
		pa.processTCPPacket(perfMetrics, packet, connectionID)
	}
	
	// Update global protocol statistics
	pa.updateProtocolStats(packet)
	
	// Update quality analysis
	pa.updateQualityAnalysis(perfMetrics)
	
	perfMetrics.LastUpdate = time.Now()
	
	// Trigger update callback
	if pa.updateCallback != nil {
		go pa.updateCallback()
	}
}

// getOrCreateMetrics gets existing metrics or creates new ones for a connection
func (pa *PerformanceAnalyzer) getOrCreateMetrics(connectionID string) *models.PerformanceMetrics {
	if metrics, exists := pa.connectionMetrics[connectionID]; exists {
		return metrics
	}
	
	// Create new metrics
	metrics := &models.PerformanceMetrics{
		ConnectionID: connectionID,
		LatencyMetrics: models.LatencyAnalysis{
			RTTHistory:      make([]float64, 0, 100),
			MinRTT:          math.MaxFloat64,
			MaxRTT:          0,
			LastMeasurement: time.Now(),
		},
		ThroughputMetrics: models.ThroughputAnalysis{
			ThroughputHistory: make([]models.ThroughputSnapshot, 0, 60),
			LastUpdate:        time.Now(),
		},
		PacketLossMetrics: models.PacketLossAnalysis{
			ExpectedSeqNums: make([]uint32, 0, 1000),
			ReceivedSeqNums: make([]uint32, 0, 1000),
			LastAnalysis:    time.Now(),
		},
		QualityMetrics: models.QualityAnalysis{
			Recommendations: make([]string, 0),
			IssuesDetected:  make([]string, 0),
			AlertLevel:      "good",
			LastEvaluation:  time.Now(),
		},
		LastUpdate: time.Now(),
	}
	
	pa.connectionMetrics[connectionID] = metrics
	return metrics
}

// updateThroughputMetrics updates throughput-related metrics
func (pa *PerformanceAnalyzer) updateThroughputMetrics(metrics *models.PerformanceMetrics, packet models.Packet) {
	now := time.Now()
	throughput := &metrics.ThroughputMetrics
	
	// Update packet and byte counters
	if packet.SourceIP != "" {
		// Assume this is an outgoing packet for simplicity
		throughput.PacketsSent++
		throughput.TotalBytesSent += int64(packet.Length)
	} else {
		throughput.PacketsReceived++
		throughput.TotalBytesRecv += int64(packet.Length)
	}
	
	// Calculate instantaneous throughput if we have previous measurement
	if !throughput.LastUpdate.IsZero() {
		duration := now.Sub(throughput.LastUpdate).Seconds()
		if duration > 0 {
			// Calculate bytes per second
			bytesDiff := int64(packet.Length)
			bps := float64(bytesDiff) / duration
			
			// Update upstream/downstream based on packet direction
			// This is simplified - in reality would need more sophisticated detection
			if packet.SourcePort > packet.DestPort {
				throughput.UpstreamBps = bps
				if bps > throughput.PeakUpstream {
					throughput.PeakUpstream = bps
				}
			} else {
				throughput.DownstreamBps = bps
				if bps > throughput.PeakDownstream {
					throughput.PeakDownstream = bps
				}
			}
		}
	}
	
	// Add throughput snapshot (keep last 60 seconds)
	snapshot := models.ThroughputSnapshot{
		Timestamp:     now,
		UpstreamBps:   throughput.UpstreamBps,
		DownstreamBps: throughput.DownstreamBps,
	}
	
	throughput.ThroughputHistory = append(throughput.ThroughputHistory, snapshot)
	if len(throughput.ThroughputHistory) > 60 {
		throughput.ThroughputHistory = throughput.ThroughputHistory[1:]
	}
	
	throughput.LastUpdate = now
}

// processTCPPacket handles TCP-specific performance analysis
func (pa *PerformanceAnalyzer) processTCPPacket(metrics *models.PerformanceMetrics, packet models.Packet, connectionID string) {
	// Handle handshake timing
	pa.trackTCPHandshake(metrics, packet, connectionID)
	
	// Handle RTT calculation
	pa.calculateRTT(metrics, packet)
	
	// Handle packet loss analysis
	pa.analyzePacketLoss(metrics, packet)
}

// trackTCPHandshake tracks TCP handshake timing for latency analysis
func (pa *PerformanceAnalyzer) trackTCPHandshake(metrics *models.PerformanceMetrics, packet models.Packet, connectionID string) {
	flags := make(map[string]bool)
	for _, flag := range packet.TCPFlags {
		flags[flag] = true
	}
	
	tracker := pa.tcpHandshakeTracker[connectionID]
	if tracker == nil {
		tracker = &HandshakeTracker{ConnectionID: connectionID}
		pa.tcpHandshakeTracker[connectionID] = tracker
	}
	
	now := packet.Timestamp
	
	// Track handshake phases
	if flags["SYN"] && !flags["ACK"] && tracker.SynTime.IsZero() {
		// Initial SYN
		tracker.SynTime = now
	} else if flags["SYN"] && flags["ACK"] && tracker.SynAckTime.IsZero() {
		// SYN+ACK response
		tracker.SynAckTime = now
		if !tracker.SynTime.IsZero() {
			// Calculate server response time (part of RTT)
			serverResponseTime := now.Sub(tracker.SynTime).Seconds() * 1000 // Convert to ms
			metrics.LatencyMetrics.HandshakeLatency = serverResponseTime
		}
	} else if flags["ACK"] && !flags["SYN"] && !tracker.Completed && !tracker.SynAckTime.IsZero() {
		// Final ACK
		tracker.AckTime = now
		tracker.Completed = true
		
		if !tracker.SynTime.IsZero() {
			// Calculate complete handshake time
			handshakeTime := now.Sub(tracker.SynTime).Seconds() * 1000
			metrics.LatencyMetrics.HandshakeLatency = handshakeTime
			log.Printf("TCP握手完成 %s: %.2fms", connectionID, handshakeTime)
		}
	}
}

// calculateRTT estimates Round Trip Time from TCP packets
func (pa *PerformanceAnalyzer) calculateRTT(metrics *models.PerformanceMetrics, packet models.Packet) {
	latency := &metrics.LatencyMetrics
	
	// Simple RTT estimation based on ACK timing
	// In a real implementation, this would be more sophisticated
	// For now, we'll use a simplified approach based on packet intervals
	
	if !latency.LastMeasurement.IsZero() {
		// Estimate RTT based on time between packets
		// This is a simplified approach - real RTT calculation requires matching SYN/ACK pairs
		interval := packet.Timestamp.Sub(latency.LastMeasurement).Seconds() * 1000
		
		// Only consider reasonable RTT values (1ms to 5000ms)
		if interval >= 1 && interval <= 5000 {
			latency.RTT = interval
			
			// Update RTT statistics
			if interval < latency.MinRTT {
				latency.MinRTT = interval
			}
			if interval > latency.MaxRTT {
				latency.MaxRTT = interval
			}
			
			// Add to history
			latency.RTTHistory = append(latency.RTTHistory, interval)
			if len(latency.RTTHistory) > 100 {
				latency.RTTHistory = latency.RTTHistory[1:]
			}
			
			// Calculate average RTT
			if len(latency.RTTHistory) > 0 {
				sum := 0.0
				for _, rtt := range latency.RTTHistory {
					sum += rtt
				}
				latency.AvgRTT = sum / float64(len(latency.RTTHistory))
				
				// Calculate RTT variance (jitter)
				variance := 0.0
				for _, rtt := range latency.RTTHistory {
					diff := rtt - latency.AvgRTT
					variance += diff * diff
				}
				latency.RTTVariance = variance / float64(len(latency.RTTHistory))
			}
		}
	}
	
	latency.LastMeasurement = packet.Timestamp
}

// analyzePacketLoss analyzes packet loss and retransmission patterns
func (pa *PerformanceAnalyzer) analyzePacketLoss(metrics *models.PerformanceMetrics, packet models.Packet) {
	packetLoss := &metrics.PacketLossMetrics
	
	if packet.SeqNum == 0 {
		return // Skip packets without sequence numbers
	}
	
	packetLoss.TotalPackets++
	
	// Track sequence numbers
	packetLoss.ReceivedSeqNums = append(packetLoss.ReceivedSeqNums, packet.SeqNum)
	
	// Keep only recent sequence numbers to avoid memory issues
	if len(packetLoss.ReceivedSeqNums) > 1000 {
		packetLoss.ReceivedSeqNums = packetLoss.ReceivedSeqNums[500:]
	}
	
	// Detect out-of-order packets
	if len(packetLoss.ReceivedSeqNums) > 1 {
		prevSeq := packetLoss.ReceivedSeqNums[len(packetLoss.ReceivedSeqNums)-2]
		if packet.SeqNum < prevSeq {
			packetLoss.OutOfOrderPackets++
		}
	}
	
	// Detect duplicates (simplified)
	count := 0
	for _, seqNum := range packetLoss.ReceivedSeqNums {
		if seqNum == packet.SeqNum {
			count++
		}
	}
	if count > 1 {
		packetLoss.DuplicatePackets++
	}
	
	// Detect potential retransmissions (simplified heuristic)
	flags := make(map[string]bool)
	for _, flag := range packet.TCPFlags {
		flags[flag] = true
	}
	
	// If we see a duplicate sequence number, it might be a retransmission
	if count > 1 && !flags["SYN"] && !flags["FIN"] {
		packetLoss.RetransmittedPkts++
	}
	
	// Calculate packet loss rate
	if packetLoss.TotalPackets > 0 {
		expectedPackets := packetLoss.TotalPackets + packetLoss.LostPackets
		if expectedPackets > 0 {
			packetLoss.PacketLossRate = float64(packetLoss.LostPackets) / float64(expectedPackets) * 100
			packetLoss.RetransmissionRate = float64(packetLoss.RetransmittedPkts) / float64(packetLoss.TotalPackets) * 100
		}
	}
	
	packetLoss.LastSeqNum = packet.SeqNum
	packetLoss.LastAnalysis = time.Now()
}

// updateProtocolStats updates global protocol statistics
func (pa *PerformanceAnalyzer) updateProtocolStats(packet models.Packet) {
	protocol := packet.Protocol
	stats := pa.globalMetrics.TopProtocols[protocol]
	
	stats.PacketCount++
	stats.ByteCount += int64(packet.Length)
	
	pa.globalMetrics.TopProtocols[protocol] = stats
}

// updateQualityAnalysis performs quality analysis and generates recommendations
func (pa *PerformanceAnalyzer) updateQualityAnalysis(metrics *models.PerformanceMetrics) {
	quality := &metrics.QualityMetrics
	latency := &metrics.LatencyMetrics
	throughput := &metrics.ThroughputMetrics
	packetLoss := &metrics.PacketLossMetrics
	
	// Reset issues and recommendations
	quality.IssuesDetected = quality.IssuesDetected[:0]
	quality.Recommendations = quality.Recommendations[:0]
	
	// Calculate connection score (0-100)
	score := 100.0
	
	// Latency scoring
	if latency.AvgRTT > 0 {
		if latency.AvgRTT > 500 {
			score -= 30
			quality.IssuesDetected = append(quality.IssuesDetected, "高延迟")
			quality.Recommendations = append(quality.Recommendations, "检查网络连接质量")
		} else if latency.AvgRTT > 200 {
			score -= 15
			quality.IssuesDetected = append(quality.IssuesDetected, "中等延迟")
		}
		
		// Jitter scoring
		if latency.RTTVariance > 100 {
			score -= 20
			quality.IssuesDetected = append(quality.IssuesDetected, "网络抖动")
			quality.Recommendations = append(quality.Recommendations, "检查网络稳定性")
		}
	}
	
	// Packet loss scoring
	if packetLoss.PacketLossRate > 5 {
		score -= 40
		quality.IssuesDetected = append(quality.IssuesDetected, "严重丢包")
		quality.Recommendations = append(quality.Recommendations, "检查网络拥塞")
	} else if packetLoss.PacketLossRate > 1 {
		score -= 20
		quality.IssuesDetected = append(quality.IssuesDetected, "轻微丢包")
	}
	
	// Retransmission scoring
	if packetLoss.RetransmissionRate > 10 {
		score -= 25
		quality.IssuesDetected = append(quality.IssuesDetected, "频繁重传")
		quality.Recommendations = append(quality.Recommendations, "优化TCP窗口大小")
	}
	
	// Throughput analysis
	if len(throughput.ThroughputHistory) > 10 {
		// Check for throughput consistency
		var sum, variance float64
		for _, snapshot := range throughput.ThroughputHistory {
			totalBps := snapshot.UpstreamBps + snapshot.DownstreamBps
			sum += totalBps
		}
		avg := sum / float64(len(throughput.ThroughputHistory))
		
		for _, snapshot := range throughput.ThroughputHistory {
			totalBps := snapshot.UpstreamBps + snapshot.DownstreamBps
			diff := totalBps - avg
			variance += diff * diff
		}
		variance = variance / float64(len(throughput.ThroughputHistory))
		
		if variance > avg*0.5 { // High throughput variance
			score -= 10
			quality.IssuesDetected = append(quality.IssuesDetected, "吞吐量不稳定")
			quality.Recommendations = append(quality.Recommendations, "检查带宽利用率")
		}
	}
	
	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	
	quality.ConnectionScore = score
	quality.StabilityScore = math.Max(0, 100-latency.RTTVariance/10) // Simplified stability calculation
	
	// Assign grade
	if score >= 90 {
		quality.PerformanceGrade = "A"
		quality.AlertLevel = "good"
	} else if score >= 80 {
		quality.PerformanceGrade = "B"
		quality.AlertLevel = "good"
	} else if score >= 70 {
		quality.PerformanceGrade = "C"
		quality.AlertLevel = "warning"
	} else if score >= 60 {
		quality.PerformanceGrade = "D"
		quality.AlertLevel = "warning"
	} else {
		quality.PerformanceGrade = "F"
		quality.AlertLevel = "critical"
	}
	
	quality.LastEvaluation = time.Now()
}

// GetPerformanceData returns complete network performance data
func (pa *PerformanceAnalyzer) GetPerformanceData() models.NetworkPerformanceData {
	pa.mutex.RLock()
	defer pa.mutex.RUnlock()
	
	// Update global metrics
	pa.updateGlobalMetrics()
	
	// Get connection metrics
	connectionMetrics := make([]models.PerformanceMetrics, 0, len(pa.connectionMetrics))
	for _, metrics := range pa.connectionMetrics {
		connectionMetrics = append(connectionMetrics, *metrics)
	}
	
	// Get top connections by performance issues (lowest scores first)
	topConnections := make([]models.PerformanceMetrics, len(connectionMetrics))
	copy(topConnections, connectionMetrics)
	sort.Slice(topConnections, func(i, j int) bool {
		return topConnections[i].QualityMetrics.ConnectionScore < topConnections[j].QualityMetrics.ConnectionScore
	})
	if len(topConnections) > 10 {
		topConnections = topConnections[:10]
	}
	
	// Get alert connections
	alertConnections := make([]models.PerformanceMetrics, 0)
	for _, metrics := range connectionMetrics {
		if metrics.QualityMetrics.AlertLevel == "warning" || metrics.QualityMetrics.AlertLevel == "critical" {
			alertConnections = append(alertConnections, metrics)
		}
	}
	
	return models.NetworkPerformanceData{
		OverallMetrics:    pa.globalMetrics,
		ConnectionMetrics: connectionMetrics,
		TopConnections:    topConnections,
		AlertConnections:  alertConnections,
		HistoricalData:    pa.historicalSnapshots,
		Timestamp:         time.Now(),
	}
}

// updateGlobalMetrics calculates global performance metrics
func (pa *PerformanceAnalyzer) updateGlobalMetrics() {
	now := time.Now()
	
	totalConnections := len(pa.connectionMetrics)
	activeConnections := 0
	totalLatency := 0.0
	totalThroughput := 0.0
	totalPacketLoss := 0.0
	validLatencyCount := 0
	validThroughputCount := 0
	validPacketLossCount := 0
	
	// Reset counters
	pa.globalMetrics.QualityDistribution = make(map[string]int)
	pa.globalMetrics.AlertSummary = make(map[string]int)
	
	for _, metrics := range pa.connectionMetrics {
		// Count active connections (updated in last 5 minutes)
		if now.Sub(metrics.LastUpdate) < 5*time.Minute {
			activeConnections++
		}
		
		// Aggregate latency
		if metrics.LatencyMetrics.AvgRTT > 0 {
			totalLatency += metrics.LatencyMetrics.AvgRTT
			validLatencyCount++
		}
		
		// Aggregate throughput
		if len(metrics.ThroughputMetrics.ThroughputHistory) > 0 {
			latest := metrics.ThroughputMetrics.ThroughputHistory[len(metrics.ThroughputMetrics.ThroughputHistory)-1]
			totalThroughput += latest.UpstreamBps + latest.DownstreamBps
			validThroughputCount++
		}
		
		// Aggregate packet loss
		if metrics.PacketLossMetrics.TotalPackets > 0 {
			totalPacketLoss += metrics.PacketLossMetrics.PacketLossRate
			validPacketLossCount++
		}
		
		// Quality distribution
		grade := metrics.QualityMetrics.PerformanceGrade
		pa.globalMetrics.QualityDistribution[grade]++
		
		// Alert summary
		alertLevel := metrics.QualityMetrics.AlertLevel
		pa.globalMetrics.AlertSummary[alertLevel]++
	}
	
	// Calculate averages
	if validLatencyCount > 0 {
		pa.globalMetrics.AvgLatency = totalLatency / float64(validLatencyCount)
	}
	if validThroughputCount > 0 {
		pa.globalMetrics.AvgThroughput = totalThroughput / float64(validThroughputCount)
	}
	if validPacketLossCount > 0 {
		pa.globalMetrics.OverallPacketLoss = totalPacketLoss / float64(validPacketLossCount)
	}
	
	pa.globalMetrics.TotalConnections = totalConnections
	pa.globalMetrics.ActiveConnections = activeConnections
	pa.globalMetrics.LastUpdate = now
	
	// Add performance snapshot
	snapshot := models.PerformanceSnapshot{
		Timestamp:         now,
		AvgLatency:        pa.globalMetrics.AvgLatency,
		TotalThroughput:   pa.globalMetrics.AvgThroughput,
		PacketLossRate:    pa.globalMetrics.OverallPacketLoss,
		ActiveConnections: activeConnections,
		AlertCount:        pa.globalMetrics.AlertSummary["warning"] + pa.globalMetrics.AlertSummary["critical"],
	}
	
	pa.historicalSnapshots = append(pa.historicalSnapshots, snapshot)
	if len(pa.historicalSnapshots) > pa.maxHistorySize {
		pa.historicalSnapshots = pa.historicalSnapshots[1:]
	}
}

// GetConnectionMetrics returns performance metrics for a specific connection
func (pa *PerformanceAnalyzer) GetConnectionMetrics(connectionID string) (*models.PerformanceMetrics, bool) {
	pa.mutex.RLock()
	defer pa.mutex.RUnlock()
	
	metrics, exists := pa.connectionMetrics[connectionID]
	if !exists {
		return nil, false
	}
	
	// Return a copy
	result := *metrics
	return &result, true
}

// ClearData clears all performance data
func (pa *PerformanceAnalyzer) ClearData() {
	pa.mutex.Lock()
	defer pa.mutex.Unlock()
	
	pa.connectionMetrics = make(map[string]*models.PerformanceMetrics)
	pa.tcpHandshakeTracker = make(map[string]*HandshakeTracker)
	pa.historicalSnapshots = pa.historicalSnapshots[:0]
	pa.globalMetrics.QualityDistribution = make(map[string]int)
	pa.globalMetrics.AlertSummary = make(map[string]int)
	pa.globalMetrics.TopProtocols = make(map[string]models.ProtocolStats)
	
	log.Println("性能分析数据已清空")
}