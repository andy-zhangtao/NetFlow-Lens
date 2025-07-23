package analyzer

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

// Analyzer processes network packets and maintains connection state
type Analyzer struct {
	connections   map[string]*models.Connection
	recentPackets []models.Packet
	mutex         sync.RWMutex
	maxPackets    int
	packetBuffer  []models.Packet
	bufferIndex   int
}

// NewAnalyzer creates a new packet analyzer
func NewAnalyzer() *Analyzer {
	maxPackets := 1000
	return &Analyzer{
		connections:   make(map[string]*models.Connection),
		recentPackets: make([]models.Packet, 0, maxPackets),
		maxPackets:    maxPackets,
		packetBuffer:  make([]models.Packet, maxPackets),
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

	log.Println("Analyzer数据已清空，准备处理新数据")
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
	if packet.Protocol == "TCP" || packet.Protocol == "UDP" {
		a.processConnection(packet)
	}

	// 调试日志
	if len(a.recentPackets)%50 == 0 {
		log.Printf("Analyzer已处理 %d 个数据包，缓冲区索引: %d", len(a.recentPackets), a.bufferIndex)
	}
}

// processConnection 处理连接相关逻辑
func (a *Analyzer) processConnection(packet models.Packet) {
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

	// 状态转换逻辑
	switch conn.State {
	case "SYN_SENT":
		if flags["SYN"] && flags["ACK"] {
			conn.State = "SYN_RECEIVED"
		}
	case "SYN_RECEIVED":
		if flags["ACK"] && !flags["SYN"] {
			conn.State = "ESTABLISHED"
		}
	case "ESTABLISHED":
		if flags["FIN"] {
			conn.State = "FIN_WAIT"
		} else if flags["RST"] {
			conn.State = "RESET"
		}
	case "FIN_WAIT":
		if flags["ACK"] {
			conn.State = "CLOSED"
		}
	}
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
