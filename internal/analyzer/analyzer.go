package analyzer

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

// TCPStateChangeCallback is called when TCP state changes
type TCPStateChangeCallback func()

// Analyzer processes network packets and maintains connection state
type Analyzer struct {
	connections         map[string]*models.Connection
	recentPackets       []models.Packet
	mutex               sync.RWMutex
	maxPackets          int
	packetBuffer        []models.Packet
	bufferIndex         int
	stateTransitions    []models.TCPStateTransition
	connectionStats     map[string]*models.TCPConnectionState
	maxTransitions      int
	stateChangeCallback TCPStateChangeCallback
	performanceAnalyzer *PerformanceAnalyzer
	educationalAnalyzer *EducationalAnalyzer
}

// NewAnalyzer creates a new packet analyzer
func NewAnalyzer() *Analyzer {
	maxPackets := 1000
	maxTransitions := 500
	return &Analyzer{
		connections:         make(map[string]*models.Connection),
		recentPackets:       make([]models.Packet, 0, maxPackets),
		maxPackets:          maxPackets,
		packetBuffer:        make([]models.Packet, maxPackets),
		stateTransitions:    make([]models.TCPStateTransition, 0, maxTransitions),
		connectionStats:     make(map[string]*models.TCPConnectionState),
		maxTransitions:      maxTransitions,
		performanceAnalyzer: NewPerformanceAnalyzer(),
		educationalAnalyzer: NewEducationalAnalyzer(),
	}
}

// ClearData 清空所有数据，用于加载新的PCAP文件
func (a *Analyzer) ClearData() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// 清空连接数据
	a.connections = make(map[string]*models.Connection)

	// 清空数据包缓冲区
	a.recentPackets = make([]models.Packet, 0, a.maxPackets)
	a.packetBuffer = make([]models.Packet, a.maxPackets)
	a.bufferIndex = 0

	// 清空状态转换数据
	a.stateTransitions = make([]models.TCPStateTransition, 0, a.maxTransitions)
	a.connectionStats = make(map[string]*models.TCPConnectionState)

	// 清空性能分析数据
	a.performanceAnalyzer.ClearData()
	
	// 清空教育分析数据
	a.educationalAnalyzer.ClearData()

	log.Println("Analyzer数据已清空，准备处理新数据")
}

// SetTCPStateChangeCallback sets the callback function for TCP state changes
func (a *Analyzer) SetTCPStateChangeCallback(callback TCPStateChangeCallback) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.stateChangeCallback = callback
}

// ProcessPacket processes a single packet and updates connection state
func (a *Analyzer) ProcessPacket(packet models.Packet) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// 添加到最近数据包环形缓冲区
	a.packetBuffer[a.bufferIndex] = packet
	a.bufferIndex = (a.bufferIndex + 1) % a.maxPackets

	// 同时添加到recentPackets切片以便调试
	if len(a.recentPackets) >= a.maxPackets {
		// 如果切片满了，移除最老的元素
		a.recentPackets = a.recentPackets[1:]
	}
	a.recentPackets = append(a.recentPackets, packet)

	// 处理连接
	var connID string
	if packet.Protocol == "TCP" || packet.Protocol == "UDP" {
		connID = a.processConnection(packet)
		
		// 进行性能分析
		if connID != "" {
			a.performanceAnalyzer.ProcessPacket(packet, connID)
		}
		
		// 进行教育分析
		a.educationalAnalyzer.ProcessPacketForEducation(packet)
	}

	// 调试日志
	if len(a.recentPackets)%50 == 0 {
		log.Printf("Analyzer已处理 %d 个数据包，缓冲区索引: %d", len(a.recentPackets), a.bufferIndex)
	}
}

// processConnection 处理连接相关逻辑
func (a *Analyzer) processConnection(packet models.Packet) string {
	connID := a.generateConnectionID(packet)

	conn, exists := a.connections[connID]
	if !exists {
		// 创建新连接
		state := "ACTIVE"
		if packet.Protocol == "TCP" {
			state = a.determineTCPState(packet)
		}

		conn = &models.Connection{
			ID:         connID,
			SourceIP:   packet.SourceIP,
			SourcePort: packet.SourcePort,
			DestIP:     packet.DestIP,
			DestPort:   packet.DestPort,
			Protocol:   packet.Protocol,
			State:      state,
			StartTime:  packet.Timestamp,
		}
		a.connections[connID] = conn
		log.Printf("新连接检测: %s (%s)", connID, state)
	}

	// 更新连接状态和时间
	conn.EndTime = packet.Timestamp
	if packet.Protocol == "TCP" {
		a.updateTCPConnectionState(conn, packet)
	}
	
	return connID
}

// determineTCPState 根据TCP标志位确定连接状态
func (a *Analyzer) determineTCPState(packet models.Packet) string {
	if len(packet.TCPFlags) == 0 {
		return "UNKNOWN"
	}

	// 检查TCP标志位组合
	flags := make(map[string]bool)
	for _, flag := range packet.TCPFlags {
		flags[flag] = true
	}

	if flags["SYN"] && !flags["ACK"] {
		return "SYN_SENT"
	}
	if flags["SYN"] && flags["ACK"] {
		return "SYN_RECEIVED"
	}
	if flags["ACK"] && !flags["SYN"] && !flags["FIN"] && !flags["RST"] {
		return "ESTABLISHED"
	}
	if flags["FIN"] {
		return "FIN_WAIT"
	}
	if flags["RST"] {
		return "RESET"
	}

	return "ACTIVE"
}

// updateTCPConnectionState 更新TCP连接状态
func (a *Analyzer) updateTCPConnectionState(conn *models.Connection, packet models.Packet) {
	if len(packet.TCPFlags) == 0 {
		return
	}

	flags := make(map[string]bool)
	for _, flag := range packet.TCPFlags {
		flags[flag] = true
	}

	oldState := conn.State
	newState := oldState

	// 状态转换逻辑
	switch conn.State {
	case "SYN_SENT":
		if flags["SYN"] && flags["ACK"] {
			newState = "SYN_RECEIVED"
		}
	case "SYN_RECEIVED":
		if flags["ACK"] && !flags["SYN"] {
			newState = "ESTABLISHED"
		}
	case "ESTABLISHED":
		if flags["FIN"] {
			newState = "FIN_WAIT"
		} else if flags["RST"] {
			newState = "RESET"
		}
	case "FIN_WAIT":
		if flags["ACK"] {
			newState = "CLOSED"
		}
	}

	// 记录状态转换
	if oldState != newState {
		conn.State = newState
		a.recordStateTransition(conn.ID, oldState, newState, packet)
		log.Printf("TCP状态转换: %s %s -> %s", conn.ID, oldState, newState)
		
		// 触发状态变化回调
		if a.stateChangeCallback != nil {
			go a.stateChangeCallback() // 异步调用避免阻塞
		}
	}

	// 更新连接统计信息
	a.updateConnectionStats(conn, packet)
}

// GetConnections returns all active connections
func (a *Analyzer) GetConnections() []models.Connection {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	connections := make([]models.Connection, 0, len(a.connections))
	now := time.Now()

	for connID, conn := range a.connections {
		// 清理超过5分钟没有活动的连接
		if now.Sub(conn.EndTime) > 5*time.Minute {
			delete(a.connections, connID)
			continue
		}
		connections = append(connections, *conn)
	}

	return connections
}

// GetRecentPackets 返回最近的数据包
func (a *Analyzer) GetRecentPackets(limit int) []models.Packet {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if limit > len(a.recentPackets) {
		limit = len(a.recentPackets)
	}

	if limit == 0 {
		log.Printf("GetRecentPackets: 没有数据包可返回，recentPackets长度: %d", len(a.recentPackets))
		return []models.Packet{}
	}

	// 从recentPackets切片中获取最新的数据包（倒序）
	packets := make([]models.Packet, 0, limit)
	startIndex := len(a.recentPackets) - limit
	if startIndex < 0 {
		startIndex = 0
	}

	// 复制数据包，按时间倒序排列（最新的在前）
	for i := len(a.recentPackets) - 1; i >= startIndex && len(packets) < limit; i-- {
		packets = append(packets, a.recentPackets[i])
	}

	log.Printf("GetRecentPackets: 返回 %d 个数据包 (请求: %d, 可用: %d)", len(packets), limit, len(a.recentPackets))
	return packets
}

// GetConnectionStats 获取连接统计信息
func (a *Analyzer) GetConnectionStats() map[string]interface{} {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_connections": len(a.connections),
		"protocols":         make(map[string]int),
		"states":            make(map[string]int),
	}

	protocols := make(map[string]int)
	states := make(map[string]int)

	for _, conn := range a.connections {
		protocols[conn.Protocol]++
		states[conn.State]++
	}

	stats["protocols"] = protocols
	stats["states"] = states

	return stats
}

// generateConnectionID creates a unique ID for a connection
func (a *Analyzer) generateConnectionID(packet models.Packet) string {
	if packet.Protocol == "TCP" || packet.Protocol == "UDP" {
		return fmt.Sprintf("%s:%d_%s:%d_%s",
			packet.SourceIP, packet.SourcePort,
			packet.DestIP, packet.DestPort,
			packet.Protocol)
	}
	return fmt.Sprintf("%s_%s_%s", packet.SourceIP, packet.DestIP, packet.Protocol)
}

// GetTCPHandshakes 获取TCP握手过程
func (a *Analyzer) GetTCPHandshakes() []map[string]interface{} {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	var handshakes []map[string]interface{}

	// 分析最近的数据包，查找TCP握手过程
	handshakeMap := make(map[string][]models.Packet)

	// 扫描环形缓冲区查找握手序列
	for i := 0; i < a.maxPackets; i++ {
		packet := a.packetBuffer[i]
		if packet.Timestamp.IsZero() || packet.Protocol != "TCP" {
			continue
		}

		connKey := fmt.Sprintf("%s:%d_%s:%d",
			packet.SourceIP, packet.SourcePort,
			packet.DestIP, packet.DestPort)

		handshakeMap[connKey] = append(handshakeMap[connKey], packet)
	}

	// 分析握手序列
	for connKey, packets := range handshakeMap {
		if len(packets) >= 3 {
			handshake := a.analyzeHandshake(packets)
			if handshake != nil {
				handshake["connection"] = connKey
				handshakes = append(handshakes, handshake)
			}
		}
	}

	return handshakes
}

// analyzeHandshake 分析TCP三次握手
func (a *Analyzer) analyzeHandshake(packets []models.Packet) map[string]interface{} {
	if len(packets) < 3 {
		return nil
	}

	// 查找SYN, SYN+ACK, ACK序列
	var synPacket, synAckPacket, ackPacket *models.Packet

	for i := range packets {
		packet := &packets[i]
		flags := make(map[string]bool)
		for _, flag := range packet.TCPFlags {
			flags[flag] = true
		}

		if flags["SYN"] && !flags["ACK"] && synPacket == nil {
			synPacket = packet
		} else if flags["SYN"] && flags["ACK"] && synAckPacket == nil {
			synAckPacket = packet
		} else if flags["ACK"] && !flags["SYN"] && ackPacket == nil && synPacket != nil && synAckPacket != nil {
			ackPacket = packet
		}
	}

	if synPacket != nil && synAckPacket != nil && ackPacket != nil {
		return map[string]interface{}{
			"syn_time":     synPacket.Timestamp,
			"syn_ack_time": synAckPacket.Timestamp,
			"ack_time":     ackPacket.Timestamp,
			"duration":     ackPacket.Timestamp.Sub(synPacket.Timestamp).Milliseconds(),
			"status":       "complete",
		}
	}

	return nil
}

// recordStateTransition 记录TCP状态转换
func (a *Analyzer) recordStateTransition(connectionID, fromState, toState string, packet models.Packet) {
	transition := models.TCPStateTransition{
		ConnectionID: connectionID,
		FromState:    fromState,
		ToState:      toState,
		Timestamp:    packet.Timestamp,
		TriggerFlags: packet.TCPFlags,
		PacketInfo:   fmt.Sprintf("%s:%d -> %s:%d", packet.SourceIP, packet.SourcePort, packet.DestIP, packet.DestPort),
	}

	// 添加到状态转换历史
	if len(a.stateTransitions) >= a.maxTransitions {
		// 移除最老的转换记录
		a.stateTransitions = a.stateTransitions[1:]
	}
	a.stateTransitions = append(a.stateTransitions, transition)
}

// updateConnectionStats 更新连接统计信息
func (a *Analyzer) updateConnectionStats(conn *models.Connection, packet models.Packet) {
	connStat, exists := a.connectionStats[conn.ID]
	if !exists {
		connStat = &models.TCPConnectionState{
			Connection:    *conn,
			StateHistory:  []models.TCPStateTransition{},
			CurrentState:  conn.State,
			Duration:      0,
			PacketCount:   0,
			BytesSent:     0,
			BytesReceived: 0,
			IsActive:      true,
		}
		a.connectionStats[conn.ID] = connStat
	}

	// 更新统计信息
	connStat.Connection = *conn
	connStat.CurrentState = conn.State
	connStat.PacketCount++
	connStat.Duration = time.Since(conn.StartTime).Seconds()
	connStat.IsActive = (conn.State != "CLOSED" && conn.State != "RESET")

	// 简单的字节统计（基于数据包长度）
	if packet.SourceIP == conn.SourceIP {
		connStat.BytesSent += int64(packet.Length)
	} else {
		connStat.BytesReceived += int64(packet.Length)
	}

	// 更新状态历史（添加最近的转换）
	for _, transition := range a.stateTransitions {
		if transition.ConnectionID == conn.ID {
			// 检查是否已经存在这个转换
			found := false
			for _, existing := range connStat.StateHistory {
				if existing.Timestamp.Equal(transition.Timestamp) && 
				   existing.FromState == transition.FromState && 
				   existing.ToState == transition.ToState {
					found = true
					break
				}
			}
			if !found {
				connStat.StateHistory = append(connStat.StateHistory, transition)
			}
		}
	}
}

// GetTCPVisualizationData 获取TCP状态可视化数据
func (a *Analyzer) GetTCPVisualizationData() models.TCPVisualizationData {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	// 获取活动连接状态
	activeConnections := make([]models.TCPConnectionState, 0)
	for _, connStat := range a.connectionStats {
		if connStat.IsActive {
			activeConnections = append(activeConnections, *connStat)
		}
	}

	// 计算状态统计
	stateStats := make(map[string]int)
	for _, conn := range a.connections {
		stateStats[conn.State]++
	}

	// 获取最近的状态转换（最近50个）
	recentTransitions := make([]models.TCPStateTransition, 0)
	start := len(a.stateTransitions) - 50
	if start < 0 {
		start = 0
	}
	for i := start; i < len(a.stateTransitions); i++ {
		recentTransitions = append(recentTransitions, a.stateTransitions[i])
	}

	return models.TCPVisualizationData{
		ActiveConnections: activeConnections,
		StateStatistics:   stateStats,
		RecentTransitions: recentTransitions,
		Timestamp:         time.Now(),
	}
}

// GetTCPConnectionState 获取特定连接的状态信息
func (a *Analyzer) GetTCPConnectionState(connectionID string) (*models.TCPConnectionState, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	connStat, exists := a.connectionStats[connectionID]
	if !exists {
		return nil, fmt.Errorf("connection %s not found", connectionID)
	}

	// 返回副本
	result := *connStat
	return &result, nil
}

// GetPerformanceData 获取网络性能分析数据
func (a *Analyzer) GetPerformanceData() models.NetworkPerformanceData {
	return a.performanceAnalyzer.GetPerformanceData()
}

// GetConnectionPerformanceMetrics 获取特定连接的性能指标
func (a *Analyzer) GetConnectionPerformanceMetrics(connectionID string) (*models.PerformanceMetrics, bool) {
	return a.performanceAnalyzer.GetConnectionMetrics(connectionID)
}

// SetPerformanceUpdateCallback 设置性能数据更新回调
func (a *Analyzer) SetPerformanceUpdateCallback(callback func()) {
	a.performanceAnalyzer.SetUpdateCallback(callback)
}

// ==================== Educational Analysis Methods ====================

// GetLayerModel 获取网络分层模型数据
func (a *Analyzer) GetLayerModel() models.NetworkLayerModel {
	return a.educationalAnalyzer.GetLayerModel()
}

// GetPacketJourney 获取数据包处理过程
func (a *Analyzer) GetPacketJourney(limit int) []models.PacketJourney {
	return a.educationalAnalyzer.GetPacketHistory(limit)
}

// SetEducationalUpdateCallback 设置教育分析更新回调
func (a *Analyzer) SetEducationalUpdateCallback(callback func()) {
	a.educationalAnalyzer.SetUpdateCallback(callback)
}
