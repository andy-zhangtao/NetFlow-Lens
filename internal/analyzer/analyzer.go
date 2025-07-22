package analyzer

import (
	"log"
	"sync"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

// Analyzer processes network packets and maintains connection state
type Analyzer struct {
	connections map[string]*models.Connection
	mutex       sync.RWMutex
}

// NewAnalyzer creates a new packet analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		connections: make(map[string]*models.Connection),
	}
}

// ProcessPacket processes a single packet and updates connection state
func (a *Analyzer) ProcessPacket(packet models.Packet) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	
	connID := a.generateConnectionID(packet)
	
	conn, exists := a.connections[connID]
	if !exists {
		conn = &models.Connection{
			ID:         connID,
			SourceIP:   packet.SourceIP,
			DestIP:     packet.DestIP,
			Protocol:   packet.Protocol,
			State:      "ACTIVE",
			StartTime:  packet.Timestamp,
		}
		a.connections[connID] = conn
		log.Printf("New connection detected: %s", connID)
	}
	
	// Update connection last seen time
	conn.EndTime = packet.Timestamp
}

// GetConnections returns all active connections
func (a *Analyzer) GetConnections() []models.Connection {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	
	connections := make([]models.Connection, 0, len(a.connections))
	for _, conn := range a.connections {
		connections = append(connections, *conn)
	}
	
	return connections
}

// generateConnectionID creates a unique ID for a connection
func (a *Analyzer) generateConnectionID(packet models.Packet) string {
	return packet.SourceIP + "_" + packet.DestIP + "_" + packet.Protocol
}