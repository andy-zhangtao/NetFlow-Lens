package analyzer

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

// EducationalAnalyzer provides educational network analysis features
type EducationalAnalyzer struct {
	layerModel     models.NetworkLayerModel
	packetHistory  []models.PacketJourney
	mutex          sync.RWMutex
	updateCallback func() // Callback for real-time updates
	maxHistory     int
}

// NewEducationalAnalyzer creates a new educational analyzer
func NewEducationalAnalyzer() *EducationalAnalyzer {
	ea := &EducationalAnalyzer{
		packetHistory: make([]models.PacketJourney, 0, 100),
		maxHistory:    100,
	}
	
	// Initialize the network layer models
	ea.initializeNetworkModels()
	
	return ea
}

// SetUpdateCallback sets callback function for real-time updates
func (ea *EducationalAnalyzer) SetUpdateCallback(callback func()) {
	ea.mutex.Lock()
	defer ea.mutex.Unlock()
	ea.updateCallback = callback
}

// initializeNetworkModels initializes both OSI and TCP/IP layer models
func (ea *EducationalAnalyzer) initializeNetworkModels() {
	// Initialize TCP/IP model (more commonly used)
	ea.layerModel = models.NetworkLayerModel{
		ModelType: "TCP_IP",
		Layers:    ea.createTCPIPLayers(),
		Statistics: models.LayerStats{
			LayerThroughput:      make(map[string]float64),
			LayerErrors:          make(map[string]int64),
			ProtocolDistribution: make(map[string]int64),
			AvgProcessingTime:    make(map[string]float64),
			LastUpdate:           time.Now(),
		},
		Timestamp: time.Now(),
	}
}

// createTCPIPLayers creates the standard TCP/IP layer model
func (ea *EducationalAnalyzer) createTCPIPLayers() []models.NetworkLayer {
	return []models.NetworkLayer{
		{
			ID:          "physical",
			Name:        "物理层",
			EnglishName: "Physical Layer",
			Level:       1,
			Description: "负责在物理媒介上传输原始的比特流，定义电气、物理、功能和规程的特性。",
			Functions: []string{
				"将数字信号转换为物理信号",
				"定义传输媒介的物理特性",
				"管理数据传输的电气特性",
				"处理信号调制和编码",
			},
			Protocols: []models.LayerProtocol{
				{Name: "Ethernet", FullName: "以太网物理层", Purpose: "有线网络物理连接", Example: "双绞线、光纤传输"},
				{Name: "WiFi", FullName: "无线网络物理层", Purpose: "无线网络物理连接", Example: "2.4GHz、5GHz无线信号"},
			},
			Examples: []string{"网线", "光纤", "无线电波", "蓝牙信号"},
			Headers:  []models.HeaderField{}, // Physical layer has no headers
			IsActive: false,
			DataFlow: models.LayerDataFlow{LastUpdate: time.Now()},
		},
		{
			ID:          "datalink",
			Name:        "数据链路层",
			EnglishName: "Data Link Layer",
			Level:       2,
			Description: "在直接连接的两个节点间提供可靠的数据传输，处理错误检测和纠正。",
			Functions: []string{
				"帧同步和帧定界",
				"错误检测和纠正",
				"流量控制",
				"MAC地址寻址",
			},
			Protocols: []models.LayerProtocol{
				{Name: "Ethernet", FullName: "以太网协议", Purpose: "局域网数据传输", Example: "MAC地址：AA:BB:CC:DD:EE:FF"},
				{Name: "PPP", FullName: "点对点协议", Purpose: "点对点连接", Example: "拨号上网连接"},
				{Name: "WiFi", FullName: "无线局域网", Purpose: "无线数据传输", Example: "WiFi网络帧"},
			},
			Examples: []string{"以太网帧", "WiFi帧", "PPP帧"},
			Headers: []models.HeaderField{
				{Name: "目标MAC", Size: 6, Description: "目标设备的MAC地址", IsImportant: true},
				{Name: "源MAC", Size: 6, Description: "源设备的MAC地址", IsImportant: true},
				{Name: "类型/长度", Size: 2, Description: "上层协议类型或帧长度", IsImportant: false},
				{Name: "帧校验序列", Size: 4, Description: "错误检测校验和", IsImportant: false},
			},
			IsActive: false,
			DataFlow: models.LayerDataFlow{LastUpdate: time.Now()},
		},
		{
			ID:          "network",
			Name:        "网络层",
			EnglishName: "Network Layer",
			Level:       3,
			Description: "负责数据包的路由和转发，实现不同网络间的互联互通。",
			Functions: []string{
				"路径选择和路由",
				"逻辑地址分配",
				"数据包转发",
				"拥塞控制",
			},
			Protocols: []models.LayerProtocol{
				{Name: "IP", FullName: "互联网协议", Purpose: "网络层寻址和路由", Example: "IPv4: 192.168.1.1"},
				{Name: "ICMP", FullName: "互联网控制消息协议", Purpose: "错误报告和诊断", Example: "ping, traceroute"},
				{Name: "ARP", FullName: "地址解析协议", Purpose: "IP地址到MAC地址映射", Example: "192.168.1.1 -> AA:BB:CC:DD:EE:FF"},
			},
			Examples: []string{"IP数据包", "路由表", "子网掩码"},
			Headers: []models.HeaderField{
				{Name: "版本", Size: 1, Description: "IP协议版本(IPv4/IPv6)", IsImportant: false},
				{Name: "首部长度", Size: 1, Description: "IP首部长度", IsImportant: false},
				{Name: "总长度", Size: 2, Description: "整个IP数据包长度", IsImportant: false},
				{Name: "标识", Size: 2, Description: "数据包分片标识", IsImportant: false},
				{Name: "生存时间", Size: 1, Description: "数据包最大跳数", IsImportant: true},
				{Name: "协议", Size: 1, Description: "上层协议类型", IsImportant: true},
				{Name: "源IP地址", Size: 4, Description: "发送方IP地址", IsImportant: true},
				{Name: "目标IP地址", Size: 4, Description: "接收方IP地址", IsImportant: true},
			},
			IsActive: false,
			DataFlow: models.LayerDataFlow{LastUpdate: time.Now()},
		},
		{
			ID:          "transport",
			Name:        "传输层",
			EnglishName: "Transport Layer",
			Level:       4,
			Description: "提供端到端的数据传输服务，确保数据完整性和可靠性。",
			Functions: []string{
				"端到端数据传输",
				"连接管理",
				"错误恢复",
				"流量控制",
			},
			Protocols: []models.LayerProtocol{
				{Name: "TCP", FullName: "传输控制协议", Purpose: "可靠的连接型传输", Example: "网页浏览、文件传输"},
				{Name: "UDP", FullName: "用户数据报协议", Purpose: "快速的无连接传输", Example: "视频流、DNS查询"},
			},
			Examples: []string{"TCP连接", "UDP数据报", "端口号"},
			Headers: []models.HeaderField{
				{Name: "源端口", Size: 2, Description: "发送方端口号", IsImportant: true},
				{Name: "目标端口", Size: 2, Description: "接收方端口号", IsImportant: true},
				{Name: "序列号", Size: 4, Description: "TCP数据序列号", IsImportant: true},
				{Name: "确认号", Size: 4, Description: "TCP确认序列号", IsImportant: true},
				{Name: "窗口大小", Size: 2, Description: "接收窗口大小", IsImportant: false},
				{Name: "校验和", Size: 2, Description: "错误检测校验和", IsImportant: false},
				{Name: "标志位", Size: 1, Description: "TCP控制标志", IsImportant: true},
			},
			IsActive: false,
			DataFlow: models.LayerDataFlow{LastUpdate: time.Now()},
		},
		{
			ID:          "application",
			Name:        "应用层",
			EnglishName: "Application Layer",
			Level:       5,
			Description: "为应用程序提供网络服务接口，直接与用户应用程序交互。",
			Functions: []string{
				"应用程序接口",
				"数据格式转换",
				"用户认证",
				"服务发现",
			},
			Protocols: []models.LayerProtocol{
				{Name: "HTTP", FullName: "超文本传输协议", Purpose: "Web页面传输", Example: "GET /index.html HTTP/1.1"},
				{Name: "HTTPS", FullName: "安全超文本传输协议", Purpose: "加密Web传输", Example: "安全的网页浏览", IsEncrypted: true},
				{Name: "FTP", FullName: "文件传输协议", Purpose: "文件上传下载", Example: "ftp://server.com/file.txt"},
				{Name: "SMTP", FullName: "简单邮件传输协议", Purpose: "邮件发送", Example: "发送电子邮件"},
				{Name: "DNS", FullName: "域名系统", Purpose: "域名解析", Example: "www.example.com -> 192.168.1.1"},
			},
			Examples: []string{"网页", "邮件", "文件传输", "即时消息"},
			Headers: []models.HeaderField{
				{Name: "请求方法", Size: 0, Description: "HTTP请求方法(GET/POST等)", IsImportant: true},
				{Name: "URL路径", Size: 0, Description: "请求的资源路径", IsImportant: true},
				{Name: "协议版本", Size: 0, Description: "HTTP协议版本", IsImportant: false},
				{Name: "主机", Size: 0, Description: "目标主机名", IsImportant: true},
				{Name: "用户代理", Size: 0, Description: "客户端信息", IsImportant: false},
				{Name: "内容类型", Size: 0, Description: "数据内容类型", IsImportant: true},
			},
			IsActive: false,
			DataFlow: models.LayerDataFlow{LastUpdate: time.Now()},
		},
	}
}

// ProcessPacketForEducation analyzes a packet for educational purposes
func (ea *EducationalAnalyzer) ProcessPacketForEducation(packet models.Packet) {
	ea.mutex.Lock()
	defer ea.mutex.Unlock()

	// Create packet journey
	journey := ea.createPacketJourney(packet)
	
	// Add to history
	ea.packetHistory = append(ea.packetHistory, journey)
	if len(ea.packetHistory) > ea.maxHistory {
		ea.packetHistory = ea.packetHistory[1:]
	}
	
	// Update current packet in layer model
	ea.layerModel.CurrentPacket = &journey
	ea.layerModel.Timestamp = time.Now()
	
	// Update layer statistics
	ea.updateLayerStatistics(packet)
	
	// Trigger update callback
	if ea.updateCallback != nil {
		go ea.updateCallback()
	}
}

// createPacketJourney creates a detailed journey for educational analysis
func (ea *EducationalAnalyzer) createPacketJourney(packet models.Packet) models.PacketJourney {
	packetID := fmt.Sprintf("pkt_%d", time.Now().UnixNano())
	startTime := time.Now()
	
	journey := models.PacketJourney{
		PacketID:       packetID,
		OriginalPacket: packet,
		LayerAnalysis:  make([]models.PacketLayerAnalysis, 0),
		CurrentLayer:   1, // Start from physical layer
		Direction:      ea.determineDirection(packet),
		StartTime:      startTime,
		ProcessingTime: make(map[string]float64),
		Encapsulation:  make([]models.EncapsulationStep, 0),
	}
	
	// Analyze packet at each layer
	journey.LayerAnalysis = append(journey.LayerAnalysis, ea.analyzePhysicalLayer(packet))
	journey.LayerAnalysis = append(journey.LayerAnalysis, ea.analyzeDataLinkLayer(packet))
	journey.LayerAnalysis = append(journey.LayerAnalysis, ea.analyzeNetworkLayer(packet))
	journey.LayerAnalysis = append(journey.LayerAnalysis, ea.analyzeTransportLayer(packet))
	journey.LayerAnalysis = append(journey.LayerAnalysis, ea.analyzeApplicationLayer(packet))
	
	// Create encapsulation steps
	journey.Encapsulation = ea.createEncapsulationSteps(packet)
	
	return journey
}

// determineDirection determines if packet is incoming or outgoing
func (ea *EducationalAnalyzer) determineDirection(packet models.Packet) string {
	// Simple heuristic: if source port > dest port, likely outgoing
	if packet.SourcePort > packet.DestPort {
		return "outgoing"
	}
	return "incoming"
}

// analyzePhysicalLayer simulates physical layer analysis
func (ea *EducationalAnalyzer) analyzePhysicalLayer(packet models.Packet) models.PacketLayerAnalysis {
	return models.PacketLayerAnalysis{
		LayerID:     "physical",
		HeaderData:  []models.HeaderField{}, // No headers at physical layer
		PayloadSize: packet.Length,
		Operations: []models.LayerOperation{
			{
				Name:        "信号检测",
				Description: "检测到网络接口上的电信号",
				Result:      "成功检测到数字信号",
				Duration:    0.1,
				IsSuccess:   true,
			},
			{
				Name:        "信号解调",
				Description: "将物理信号转换为数字比特流",
				Result:      fmt.Sprintf("解调出 %d 字节数据", packet.Length),
				Duration:    0.2,
				IsSuccess:   true,
			},
		},
		Decisions:    []models.LayerDecision{},
		NextLayer:    "datalink",
		IsError:      false,
		ErrorMessage: "",
	}
}

// analyzeDataLinkLayer analyzes data link layer
func (ea *EducationalAnalyzer) analyzeDataLinkLayer(packet models.Packet) models.PacketLayerAnalysis {
	headerFields := []models.HeaderField{
		{Name: "目标MAC", Size: 6, Description: "目标设备MAC地址", Value: "AA:BB:CC:DD:EE:FF", IsImportant: true},
		{Name: "源MAC", Size: 6, Description: "源设备MAC地址", Value: "11:22:33:44:55:66", IsImportant: true},
		{Name: "类型", Size: 2, Description: "上层协议类型", Value: "0x0800 (IPv4)", IsImportant: false},
	}
	
	operations := []models.LayerOperation{
		{
			Name:        "帧同步",
			Description: "识别帧的开始和结束",
			Result:      "成功识别以太网帧",
			Duration:    0.1,
			IsSuccess:   true,
		},
		{
			Name:        "MAC地址检查",
			Description: "检查目标MAC地址是否匹配",
			Result:      "MAC地址匹配，接受帧",
			Duration:    0.2,
			IsSuccess:   true,
		},
		{
			Name:        "CRC校验",
			Description: "校验帧完整性",
			Result:      "CRC校验通过",
			Duration:    0.1,
			IsSuccess:   true,
		},
	}
	
	return models.PacketLayerAnalysis{
		LayerID:      "datalink",
		HeaderData:   headerFields,
		PayloadSize:  packet.Length - 14, // Subtract Ethernet header
		Operations:   operations,
		Decisions:    []models.LayerDecision{},
		NextLayer:    "network",
		IsError:      false,
		ErrorMessage: "",
	}
}

// analyzeNetworkLayer analyzes network layer (IP)
func (ea *EducationalAnalyzer) analyzeNetworkLayer(packet models.Packet) models.PacketLayerAnalysis {
	headerFields := []models.HeaderField{
		{Name: "版本", Size: 1, Description: "IP版本", Value: "4 (IPv4)", IsImportant: false},
		{Name: "首部长度", Size: 1, Description: "IP首部长度", Value: "20 bytes", IsImportant: false},
		{Name: "总长度", Size: 2, Description: "IP数据包总长度", Value: fmt.Sprintf("%d bytes", packet.Length), IsImportant: false},
		{Name: "生存时间", Size: 1, Description: "TTL值", Value: "64", IsImportant: true},
		{Name: "协议", Size: 1, Description: "上层协议", Value: getProtocolName(packet.Protocol), IsImportant: true},
		{Name: "源IP", Size: 4, Description: "源IP地址", Value: packet.SourceIP, IsImportant: true},
		{Name: "目标IP", Size: 4, Description: "目标IP地址", Value: packet.DestIP, IsImportant: true},
	}
	
	operations := []models.LayerOperation{
		{
			Name:        "IP首部校验",
			Description: "验证IP首部校验和",
			Result:      "首部校验通过",
			Duration:    0.1,
			IsSuccess:   true,
		},
		{
			Name:        "TTL检查",
			Description: "检查生存时间是否大于0",
			Result:      "TTL=64, 继续转发",
			Duration:    0.05,
			IsSuccess:   true,
		},
		{
			Name:        "路由查找",
			Description: "在路由表中查找目标网络",
			Result:      "找到匹配路由",
			Duration:    0.3,
			IsSuccess:   true,
		},
	}
	
	decisions := []models.LayerDecision{
		{
			DecisionPoint: "路由决策",
			Options:       []string{"本地交付", "转发到下一跳", "丢弃数据包"},
			ChosenOption:  "本地交付",
			Reasoning:     "目标IP地址匹配本机接口",
		},
	}
	
	return models.PacketLayerAnalysis{
		LayerID:      "network",
		HeaderData:   headerFields,
		PayloadSize:  packet.Length - 34, // Subtract Ethernet + IP headers
		Operations:   operations,
		Decisions:    decisions,
		NextLayer:    "transport",
		IsError:      false,
		ErrorMessage: "",
	}
}

// analyzeTransportLayer analyzes transport layer (TCP/UDP)
func (ea *EducationalAnalyzer) analyzeTransportLayer(packet models.Packet) models.PacketLayerAnalysis {
	var headerFields []models.HeaderField
	var operations []models.LayerOperation
	var decisions []models.LayerDecision
	
	if packet.Protocol == "TCP" {
		headerFields = []models.HeaderField{
			{Name: "源端口", Size: 2, Description: "源端口号", Value: fmt.Sprintf("%d", packet.SourcePort), IsImportant: true},
			{Name: "目标端口", Size: 2, Description: "目标端口号", Value: fmt.Sprintf("%d", packet.DestPort), IsImportant: true},
			{Name: "序列号", Size: 4, Description: "TCP序列号", Value: fmt.Sprintf("%d", packet.SeqNum), IsImportant: true},
			{Name: "确认号", Size: 4, Description: "TCP确认号", Value: fmt.Sprintf("%d", packet.AckNum), IsImportant: true},
			{Name: "标志位", Size: 1, Description: "TCP控制标志", Value: strings.Join(packet.TCPFlags, ","), IsImportant: true},
			{Name: "窗口大小", Size: 2, Description: "接收窗口", Value: "65536", IsImportant: false},
		}
		
		operations = []models.LayerOperation{
			{
				Name:        "端口检查",
				Description: "检查目标端口是否有监听程序",
				Result:      fmt.Sprintf("端口 %d 有程序监听", packet.DestPort),
				Duration:    0.1,
				IsSuccess:   true,
			},
			{
				Name:        "TCP状态检查",
				Description: "检查TCP连接状态",
				Result:      "连接状态正常",
				Duration:    0.05,
				IsSuccess:   true,
			},
			{
				Name:        "序列号验证",
				Description: "验证数据包序列号",
				Result:      "序列号在期望范围内",
				Duration:    0.1,
				IsSuccess:   true,
			},
		}
		
		decisions = []models.LayerDecision{
			{
				DecisionPoint: "数据包处理",
				Options:       []string{"接受数据包", "丢弃数据包", "发送RST"},
				ChosenOption:  "接受数据包",
				Reasoning:     "数据包通过所有验证",
			},
		}
	} else if packet.Protocol == "UDP" {
		headerFields = []models.HeaderField{
			{Name: "源端口", Size: 2, Description: "源端口号", Value: fmt.Sprintf("%d", packet.SourcePort), IsImportant: true},
			{Name: "目标端口", Size: 2, Description: "目标端口号", Value: fmt.Sprintf("%d", packet.DestPort), IsImportant: true},
			{Name: "长度", Size: 2, Description: "UDP数据长度", Value: fmt.Sprintf("%d", packet.Length), IsImportant: false},
			{Name: "校验和", Size: 2, Description: "UDP校验和", Value: "0x1234", IsImportant: false},
		}
		
		operations = []models.LayerOperation{
			{
				Name:        "端口检查",
				Description: "检查目标端口是否有监听程序",
				Result:      fmt.Sprintf("端口 %d 有程序监听", packet.DestPort),
				Duration:    0.1,
				IsSuccess:   true,
			},
			{
				Name:        "UDP校验",
				Description: "验证UDP校验和",
				Result:      "校验和正确",
				Duration:    0.05,
				IsSuccess:   true,
			},
		}
		
		decisions = []models.LayerDecision{
			{
				DecisionPoint: "数据包处理",
				Options:       []string{"传递给应用程序", "丢弃数据包"},
				ChosenOption:  "传递给应用程序",
				Reasoning:     "UDP校验通过且端口有监听程序",
			},
		}
	}
	
	return models.PacketLayerAnalysis{
		LayerID:      "transport",
		HeaderData:   headerFields,
		PayloadSize:  packet.PayloadSize,
		Operations:   operations,
		Decisions:    decisions,
		NextLayer:    "application",
		IsError:      false,
		ErrorMessage: "",
	}
}

// analyzeApplicationLayer analyzes application layer
func (ea *EducationalAnalyzer) analyzeApplicationLayer(packet models.Packet) models.PacketLayerAnalysis {
	protocol := ea.guessApplicationProtocol(packet)
	
	var headerFields []models.HeaderField
	var operations []models.LayerOperation
	
	switch protocol {
	case "HTTP":
		headerFields = []models.HeaderField{
			{Name: "请求方法", Size: 0, Description: "HTTP方法", Value: "GET", IsImportant: true},
			{Name: "URL路径", Size: 0, Description: "请求路径", Value: "/index.html", IsImportant: true},
			{Name: "协议版本", Size: 0, Description: "HTTP版本", Value: "HTTP/1.1", IsImportant: false},
			{Name: "主机", Size: 0, Description: "目标主机", Value: "www.example.com", IsImportant: true},
		}
		
		operations = []models.LayerOperation{
			{
				Name:        "HTTP解析",
				Description: "解析HTTP请求头",
				Result:      "成功解析HTTP GET请求",
				Duration:    0.2,
				IsSuccess:   true,
			},
		}
		
	case "DNS":
		headerFields = []models.HeaderField{
			{Name: "查询ID", Size: 2, Description: "DNS查询标识", Value: "0x1234", IsImportant: true},
			{Name: "查询类型", Size: 2, Description: "查询记录类型", Value: "A (IPv4地址)", IsImportant: true},
			{Name: "域名", Size: 0, Description: "查询的域名", Value: "www.example.com", IsImportant: true},
		}
		
		operations = []models.LayerOperation{
			{
				Name:        "DNS查询解析",
				Description: "解析DNS查询请求",
				Result:      "域名解析查询",
				Duration:    0.1,
				IsSuccess:   true,
			},
		}
		
	default:
		headerFields = []models.HeaderField{
			{Name: "应用数据", Size: packet.PayloadSize, Description: "应用层载荷", Value: "二进制数据", IsImportant: true},
		}
		
		operations = []models.LayerOperation{
			{
				Name:        "数据传递",
				Description: "将数据传递给应用程序",
				Result:      "数据已传递给应用程序",
				Duration:    0.1,
				IsSuccess:   true,
			},
		}
	}
	
	return models.PacketLayerAnalysis{
		LayerID:      "application",
		HeaderData:   headerFields,
		PayloadSize:  packet.PayloadSize,
		Operations:   operations,
		Decisions:    []models.LayerDecision{},
		NextLayer:    "",
		IsError:      false,
		ErrorMessage: "",
	}
}

// createEncapsulationSteps creates the encapsulation visualization
func (ea *EducationalAnalyzer) createEncapsulationSteps(packet models.Packet) []models.EncapsulationStep {
	steps := []models.EncapsulationStep{}
	
	// Application layer (original data)
	appData := models.EncapsulationData{
		HeaderSize:    0,
		PayloadSize:   packet.PayloadSize,
		TotalSize:     packet.PayloadSize,
		Visualization: ea.createDataVisualization("应用数据", packet.PayloadSize),
	}
	
	// Transport layer (add TCP/UDP header)
	transportHeader := 20 // TCP header size
	if packet.Protocol == "UDP" {
		transportHeader = 8
	}
	transportData := models.EncapsulationData{
		HeaderSize:    transportHeader,
		PayloadSize:   packet.PayloadSize,
		TotalSize:     transportHeader + packet.PayloadSize,
		Visualization: ea.createDataVisualization(packet.Protocol+"首部|应用数据", transportHeader+packet.PayloadSize),
	}
	
	steps = append(steps, models.EncapsulationStep{
		LayerID:     "transport",
		Operation:   "encapsulate",
		HeaderAdded: ea.getTransportHeaders(packet),
		Before:      appData,
		After:       transportData,
	})
	
	// Network layer (add IP header)
	ipHeader := 20
	networkData := models.EncapsulationData{
		HeaderSize:    ipHeader + transportHeader,
		PayloadSize:   packet.PayloadSize,
		TotalSize:     ipHeader + transportHeader + packet.PayloadSize,
		Visualization: ea.createDataVisualization("IP首部|"+packet.Protocol+"首部|应用数据", ipHeader+transportHeader+packet.PayloadSize),
	}
	
	steps = append(steps, models.EncapsulationStep{
		LayerID:     "network",
		Operation:   "encapsulate",
		HeaderAdded: ea.getNetworkHeaders(packet),
		Before:      transportData,
		After:       networkData,
	})
	
	// Data link layer (add Ethernet header)
	ethHeader := 14
	linkData := models.EncapsulationData{
		HeaderSize:    ethHeader + ipHeader + transportHeader,
		PayloadSize:   packet.PayloadSize,
		TotalSize:     ethHeader + ipHeader + transportHeader + packet.PayloadSize,
		Visualization: ea.createDataVisualization("以太网首部|IP首部|"+packet.Protocol+"首部|应用数据", ethHeader+ipHeader+transportHeader+packet.PayloadSize),
	}
	
	steps = append(steps, models.EncapsulationStep{
		LayerID:     "datalink",
		Operation:   "encapsulate",
		HeaderAdded: ea.getDataLinkHeaders(),
		Before:      networkData,
		After:       linkData,
	})
	
	return steps
}

// Helper functions

func (ea *EducationalAnalyzer) updateLayerStatistics(packet models.Packet) {
	// Update packet count
	ea.layerModel.Statistics.TotalPacketsProcessed++
	
	// Update protocol distribution
	ea.layerModel.Statistics.ProtocolDistribution[packet.Protocol]++
	
	// Update layer throughput (simplified)
	for i := range ea.layerModel.Layers {
		layer := &ea.layerModel.Layers[i]
		layer.DataFlow.BytesIn += int64(packet.Length)
		layer.DataFlow.PacketsIn++
		layer.DataFlow.LastUpdate = time.Now()
		layer.IsActive = true
		
		// Calculate throughput
		if layer.DataFlow.PacketsIn > 0 {
			duration := time.Since(layer.DataFlow.LastUpdate).Seconds()
			if duration > 0 {
				layer.DataFlow.Throughput = float64(layer.DataFlow.BytesIn) / duration
			}
		}
	}
	
	ea.layerModel.Statistics.LastUpdate = time.Now()
}

func (ea *EducationalAnalyzer) guessApplicationProtocol(packet models.Packet) string {
	switch packet.DestPort {
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 53:
		return "DNS"
	case 21:
		return "FTP"
	case 25:
		return "SMTP"
	case 22:
		return "SSH"
	default:
		return "UNKNOWN"
	}
}

func (ea *EducationalAnalyzer) createDataVisualization(description string, size int) string {
	return fmt.Sprintf("[%s] (%d bytes)", description, size)
}

func (ea *EducationalAnalyzer) getTransportHeaders(packet models.Packet) []models.HeaderField {
	if packet.Protocol == "TCP" {
		return []models.HeaderField{
			{Name: "源端口", Size: 2, Description: "发送方端口", Value: fmt.Sprintf("%d", packet.SourcePort)},
			{Name: "目标端口", Size: 2, Description: "接收方端口", Value: fmt.Sprintf("%d", packet.DestPort)},
			{Name: "序列号", Size: 4, Description: "数据序列号", Value: fmt.Sprintf("%d", packet.SeqNum)},
		}
	}
	return []models.HeaderField{
		{Name: "源端口", Size: 2, Description: "发送方端口", Value: fmt.Sprintf("%d", packet.SourcePort)},
		{Name: "目标端口", Size: 2, Description: "接收方端口", Value: fmt.Sprintf("%d", packet.DestPort)},
	}
}

func (ea *EducationalAnalyzer) getNetworkHeaders(packet models.Packet) []models.HeaderField {
	return []models.HeaderField{
		{Name: "源IP", Size: 4, Description: "发送方IP地址", Value: packet.SourceIP},
		{Name: "目标IP", Size: 4, Description: "接收方IP地址", Value: packet.DestIP},
		{Name: "协议", Size: 1, Description: "上层协议类型", Value: packet.Protocol},
	}
}

func (ea *EducationalAnalyzer) getDataLinkHeaders() []models.HeaderField {
	return []models.HeaderField{
		{Name: "目标MAC", Size: 6, Description: "目标MAC地址", Value: "AA:BB:CC:DD:EE:FF"},
		{Name: "源MAC", Size: 6, Description: "源MAC地址", Value: "11:22:33:44:55:66"},
		{Name: "类型", Size: 2, Description: "上层协议类型", Value: "0x0800"},
	}
}

func getProtocolName(protocol string) string {
	switch protocol {
	case "TCP":
		return "6 (TCP)"
	case "UDP":
		return "17 (UDP)"
	case "ICMP":
		return "1 (ICMP)"
	default:
		return protocol
	}
}

// GetLayerModel returns the current network layer model for visualization
func (ea *EducationalAnalyzer) GetLayerModel() models.NetworkLayerModel {
	ea.mutex.RLock()
	defer ea.mutex.RUnlock()
	
	// Return a copy
	return ea.layerModel
}

// GetPacketHistory returns recent packet journeys
func (ea *EducationalAnalyzer) GetPacketHistory(limit int) []models.PacketJourney {
	ea.mutex.RLock()
	defer ea.mutex.RUnlock()
	
	if limit <= 0 || limit > len(ea.packetHistory) {
		limit = len(ea.packetHistory)
	}
	
	start := len(ea.packetHistory) - limit
	if start < 0 {
		start = 0
	}
	
	return ea.packetHistory[start:]
}

// ClearData clears all educational analysis data
func (ea *EducationalAnalyzer) ClearData() {
	ea.mutex.Lock()
	defer ea.mutex.Unlock()
	
	ea.packetHistory = ea.packetHistory[:0]
	ea.layerModel.CurrentPacket = nil
	ea.layerModel.Statistics = models.LayerStats{
		LayerThroughput:      make(map[string]float64),
		LayerErrors:          make(map[string]int64),
		ProtocolDistribution: make(map[string]int64),
		AvgProcessingTime:    make(map[string]float64),
		LastUpdate:           time.Now(),
	}
	
	// Reset layer activity
	for i := range ea.layerModel.Layers {
		ea.layerModel.Layers[i].IsActive = false
		ea.layerModel.Layers[i].DataFlow = models.LayerDataFlow{LastUpdate: time.Now()}
	}
	
	log.Println("教育分析数据已清空")
}