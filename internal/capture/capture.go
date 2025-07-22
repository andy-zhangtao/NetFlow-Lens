package capture

import (
	"log"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

// Capturer handles network packet capture
type Capturer struct {
	isRunning bool
	packets   chan models.Packet
}

// NewCapturer creates a new packet capturer
func NewCapturer() *Capturer {
	return &Capturer{
		packets: make(chan models.Packet, 1000),
	}
}

// Start begins packet capture (mock implementation for now)
func (c *Capturer) Start() error {
	if c.isRunning {
		return nil
	}
	
	c.isRunning = true
	log.Println("Starting packet capture...")
	
	// Mock packet generation for testing
	go c.generateMockPackets()
	
	return nil
}

// Stop stops packet capture
func (c *Capturer) Stop() {
	c.isRunning = false
	log.Println("Stopped packet capture")
}

// GetPackets returns the packet channel
func (c *Capturer) GetPackets() <-chan models.Packet {
	return c.packets
}

// generateMockPackets generates mock packets for testing
func (c *Capturer) generateMockPackets() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for c.isRunning {
		select {
		case <-ticker.C:
			packet := models.Packet{
				Timestamp: time.Now(),
				Length:    64,
				Protocol:  "TCP",
				SourceIP:  "192.168.1.100",
				DestIP:    "93.184.216.34",
			}
			
			select {
			case c.packets <- packet:
				log.Printf("Generated mock packet: %+v", packet)
			default:
				log.Println("Packet channel full, dropping packet")
			}
		}
	}
}