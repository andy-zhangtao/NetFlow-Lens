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
)

// Capturer handles network packet capture
type Capturer struct {
	isRunning    bool
	packets      chan models.Packet
	handle       *pcap.Handle
	source       string // 可以是网卡接口名或pcap文件路径
	sourceType   string // "interface" 或 "file"
	packetCount  int
	errorChannel chan error
}

// NewCapturer creates a new packet capturer
func NewCapturer() *Capturer {
	return &Capturer{
		packets:      make(chan models.Packet, 1000),
		errorChannel: make(chan error, 10),
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

	c.handle = handle
	c.source = interfaceName
	c.sourceType = "interface"
	c.isRunning = true

	log.Printf("开始从网卡 %s 捕获数据包...", interfaceName)

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

	c.handle = handle
	c.source = filename
	c.sourceType = "file"
	c.isRunning = true

	log.Printf("开始读取pcap文件: %s", filename)

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
				if c.packetCount%50 == 0 { // 降低日志频率
					log.Printf("已处理 %d 个数据包", c.packetCount)
				}
			default:
				log.Println("数据包通道已满，丢弃数据包")
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
