package capture

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
	"github.com/andy-zhangtao/NetFlow-Lens/internal/filter"
)

// Capturer handles network packet capture
type Capturer struct {
	isRunning      bool
	packets        chan models.Packet
	handle         *pcap.Handle
	source         string // 可以是网卡接口名或pcap文件路径
	sourceType     string // "interface" 或 "file"
	packetCount    int
	errorChannel   chan error
	filterManager  *filter.FilterManager
	filteredCount  int64
	droppedCount   int64
}

// NewCapturer creates a new packet capturer
func NewCapturer() *Capturer {
	return &Capturer{
		packets:       make(chan models.Packet, 1000),
		errorChannel:  make(chan error, 10),
		filterManager: filter.NewFilterManager(),
	}
}

// SetSource 设置数据源（网卡接口或pcap文件）
func (c *Capturer) SetSource(source, sourceType string) error {
	if c.isRunning {
		return fmt.Errorf("cannot change source while capturing")
	}

	c.source = source
	c.sourceType = sourceType
	return nil
}

// StartLiveCapture 开始实时网卡捕获
func (c *Capturer) StartLiveCapture(interfaceName string) error {
	if c.isRunning {
		return fmt.Errorf("capture already running")
	}

	// 打开网卡接口
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", interfaceName, err)
	}

	// 应用 BPF 过滤器（如果有活动过滤器）
	if err := c.applyBPFFilter(handle); err != nil {
		handle.Close()
		return fmt.Errorf("failed to apply BPF filter: %v", err)
	}

	c.handle = handle
	c.source = interfaceName
	c.sourceType = "interface"
	c.isRunning = true
	c.resetStats()

	filterInfo := ""
	if activeFilter := c.filterManager.GetActiveFilter(); activeFilter != nil {
		filterInfo = fmt.Sprintf(" (过滤器: %s)", activeFilter.Name)
	}
	log.Printf("开始从网卡 %s 捕获数据包%s...", interfaceName, filterInfo)

	// 启动数据包处理协程
	go c.processPackets()

	return nil
}

// StartFileCapture 开始从pcap文件读取
func (c *Capturer) StartFileCapture(filename string) error {
	if c.isRunning {
		return fmt.Errorf("capture already running")
	}

	// 检查文件是否存在
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return fmt.Errorf("pcap file does not exist: %s", filename)
	}

	// 打开pcap文件
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return fmt.Errorf("failed to open pcap file %s: %v", filename, err)
	}

	// 应用 BPF 过滤器（如果有活动过滤器）
	if err := c.applyBPFFilter(handle); err != nil {
		handle.Close()
		return fmt.Errorf("failed to apply BPF filter: %v", err)
	}

	c.handle = handle
	c.source = filename
	c.sourceType = "file"
	c.isRunning = true
	c.resetStats()

	filterInfo := ""
	if activeFilter := c.filterManager.GetActiveFilter(); activeFilter != nil {
		filterInfo = fmt.Sprintf(" (过滤器: %s)", activeFilter.Name)
	}
	log.Printf("开始读取pcap文件: %s%s", filename, filterInfo)

	// 启动数据包处理协程
	go c.processPackets()

	return nil
}

// Stop 停止数据包捕获
func (c *Capturer) Stop() {
	if !c.isRunning {
		return
	}

	c.isRunning = false

	if c.handle != nil {
		c.handle.Close()
		c.handle = nil
	}

	log.Printf("停止数据包捕获，共处理 %d 个数据包", c.packetCount)
}

// GetPackets 返回数据包通道
func (c *Capturer) GetPackets() <-chan models.Packet {
	return c.packets
}

// GetErrors 返回错误通道
func (c *Capturer) GetErrors() <-chan error {
	return c.errorChannel
}

// GetPacketCount 返回已处理的数据包数量
func (c *Capturer) GetPacketCount() int {
	return c.packetCount
}

// ListInterfaces 列出可用的网络接口
func (c *Capturer) ListInterfaces() ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var interfaces []string
	for _, device := range devices {
		if len(device.Addresses) > 0 {
			interfaces = append(interfaces, device.Name)
		}
	}

	return interfaces, nil
}

// processPackets 处理数据包的主循环
func (c *Capturer) processPackets() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("数据包处理协程panic: %v", r)
			c.errorChannel <- fmt.Errorf("packet processing panic: %v", r)
		}
	}()

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())

	for c.isRunning {
		packet, err := packetSource.NextPacket()
		if err != nil {
			if err.Error() == "EOF" && c.sourceType == "file" {
				log.Printf("pcap文件读取完成，共读取 %d 个数据包", c.packetCount)
				// 不要立即设置isRunning为false，让后台处理完剩余数据包
				break
			}
			log.Printf("读取数据包错误: %v", err)
			c.errorChannel <- err
			continue
		}

		// 解析数据包
		parsedPacket := c.parsePacket(packet)
		if parsedPacket != nil {
			select {
			case c.packets <- *parsedPacket:
				c.packetCount++
				c.filteredCount++ // 成功发送到通道的数据包
				if c.packetCount%50 == 0 { // 降低日志频率
					log.Printf("已处理 %d 个数据包", c.packetCount)
				}
			default:
				log.Println("数据包通道已满，丢弃数据包")
				c.droppedCount++ // 因通道满而丢弃的数据包
			}
		}
	}

	// 等待一小段时间让analyzer处理完剩余数据包
	if c.sourceType == "file" {
		log.Printf("等待analyzer处理完剩余数据包...")
		time.Sleep(100 * time.Millisecond)
	}

	log.Printf("数据包处理协程结束，总共处理了 %d 个数据包", c.packetCount)
}

// parsePacket 解析单个数据包
func (c *Capturer) parsePacket(packet gopacket.Packet) *models.Packet {
	if packet == nil {
		return nil
	}

	result := &models.Packet{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
	}

	// 解析IP层
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		result.SourceIP = ip.SrcIP.String()
		result.DestIP = ip.DstIP.String()
		result.Protocol = ip.Protocol.String()
	}

	// 解析TCP层
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		result.SourcePort = int(tcp.SrcPort)
		result.DestPort = int(tcp.DstPort)
		result.Protocol = "TCP"
		result.SeqNum = tcp.Seq
		result.AckNum = tcp.Ack

		// 解析TCP标志位
		var flags []string
		if tcp.SYN {
			flags = append(flags, "SYN")
		}
		if tcp.ACK {
			flags = append(flags, "ACK")
		}
		if tcp.FIN {
			flags = append(flags, "FIN")
		}
		if tcp.RST {
			flags = append(flags, "RST")
		}
		if tcp.PSH {
			flags = append(flags, "PSH")
		}
		if tcp.URG {
			flags = append(flags, "URG")
		}
		result.TCPFlags = flags

		// 获取TCP载荷
		if tcp.Payload != nil {
			result.Payload = tcp.Payload
			result.PayloadSize = len(tcp.Payload)
		}
	}

	// 解析UDP层
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		result.SourcePort = int(udp.SrcPort)
		result.DestPort = int(udp.DstPort)
		result.Protocol = "UDP"

		if udp.Payload != nil {
			result.Payload = udp.Payload
			result.PayloadSize = len(udp.Payload)
		}
	}

	return result
}

// GetPCAPFileInfo 获取pcap文件信息
func GetPCAPFileInfo(filename string) (*models.PCAPFileInfo, error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}

	info := &models.PCAPFileInfo{
		Filename:   filename,
		Size:       fileInfo.Size(),
		UploadTime: fileInfo.ModTime(),
		Status:     "ready",
	}

	// 快速扫描文件获取数据包数量
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		info.Status = "error"
		info.ErrorMessage = err.Error()
		return info, nil
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	count := 0
	for {
		_, err := packetSource.NextPacket()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Printf("扫描pcap文件时出错: %v", err)
			break
		}
		count++
	}

	info.PacketCount = count
	return info, nil
}

// IsValidInterface 检查网络接口是否有效
func IsValidInterface(interfaceName string) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range interfaces {
		if iface.Name == interfaceName {
			return true
		}
	}
	return false
}

// GetFilterManager returns the filter manager
func (c *Capturer) GetFilterManager() *filter.FilterManager {
	return c.filterManager
}

// applyBPFFilter applies the active BPF filter to the pcap handle
func (c *Capturer) applyBPFFilter(handle *pcap.Handle) error {
	expression := c.filterManager.GetActiveFilterExpression()
	if expression == "" {
		// 没有活动过滤器，不应用任何过滤
		return nil
	}

	log.Printf("应用 BPF 过滤器: %s", expression)
	err := handle.SetBPFFilter(expression)
	if err != nil {
		return fmt.Errorf("failed to set BPF filter '%s': %v", expression, err)
	}

	return nil
}

// resetStats resets capture statistics
func (c *Capturer) resetStats() {
	c.packetCount = 0
	c.filteredCount = 0
	c.droppedCount = 0
}

// updateFilterStats updates filter statistics
func (c *Capturer) updateFilterStats() {
	totalPackets := int64(c.packetCount)
	
	// 获取 pcap 统计信息
	var filteredPackets, droppedPackets int64
	if c.handle != nil {
		if stats, err := c.handle.Stats(); err == nil {
			// pcap stats 返回的是硬件级别的统计
			filteredPackets = int64(stats.PacketsReceived)
			droppedPackets = int64(stats.PacketsDropped)
		}
	}

	// 如果没有硬件统计，使用我们自己的计数
	if filteredPackets == 0 {
		filteredPackets = c.filteredCount
	}
	if droppedPackets == 0 {
		droppedPackets = c.droppedCount
	}

	// 更新过滤器管理器的统计信息
	c.filterManager.UpdateStats(totalPackets, filteredPackets, droppedPackets)
}

// GetFilterStats returns current filter statistics
func (c *Capturer) GetFilterStats() *models.FilterStats {
	c.updateFilterStats()
	return c.filterManager.GetStats()
}
