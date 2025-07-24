package filter

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/andy-zhangtao/NetFlow-Lens/pkg/models"
)

// FilterManager manages BPF filters
type FilterManager struct {
	filters      map[string]*models.FilterRule
	activeFilter *models.FilterRule
	stats        *models.FilterStats
	mutex        sync.RWMutex
	presets      []*models.PresetFilter
}

// NewFilterManager creates a new filter manager
func NewFilterManager() *FilterManager {
	fm := &FilterManager{
		filters: make(map[string]*models.FilterRule),
		stats:   &models.FilterStats{},
		presets: getPresetFilters(),
	}
	return fm
}

// ValidateFilter validates a BPF expression
func (fm *FilterManager) ValidateFilter(expression string) *models.FilterValidationResult {
	result := &models.FilterValidationResult{
		IsValid: false,
	}

	// 检查空表达式
	if strings.TrimSpace(expression) == "" {
		result.ErrorMessage = "Filter expression cannot be empty"
		return result
	}

	// 使用 pcap 库的 CompileBPFFilter 来验证 BPF 表达式
	_, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65536, expression)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Invalid BPF expression: %v", err)
		return result
	}

	result.IsValid = true
	
	// 解析表达式中的字段
	fm.parseFilterExpression(expression, result)
	
	return result
}

// parseFilterExpression parses the filter expression to extract protocols, ports, IPs
func (fm *FilterManager) parseFilterExpression(expression string, result *models.FilterValidationResult) {
	expr := strings.ToLower(strings.TrimSpace(expression))
	
	// 解析协议
	protocols := []string{}
	if strings.Contains(expr, "tcp") {
		protocols = append(protocols, "TCP")
	}
	if strings.Contains(expr, "udp") {
		protocols = append(protocols, "UDP")
	}
	if strings.Contains(expr, "icmp") {
		protocols = append(protocols, "ICMP")
	}
	if strings.Contains(expr, "ip") {
		protocols = append(protocols, "IP")
	}
	result.ParsedFields.Protocols = protocols

	// 解析端口
	ports := []int{}
	portRegex := regexp.MustCompile(`port\s+(\d+)`)
	matches := portRegex.FindAllStringSubmatch(expr, -1)
	for _, match := range matches {
		if len(match) > 1 {
			if port, err := strconv.Atoi(match[1]); err == nil {
				ports = append(ports, port)
			}
		}
	}
	result.ParsedFields.Ports = ports

	// 解析IP地址
	ips := []string{}
	ipRegex := regexp.MustCompile(`(?:host|src|dst)\s+(\d+\.\d+\.\d+\.\d+)`)
	ipMatches := ipRegex.FindAllStringSubmatch(expr, -1)
	for _, match := range ipMatches {
		if len(match) > 1 {
			ips = append(ips, match[1])
		}
	}
	result.ParsedFields.IPs = ips
}

// AddFilter adds a new filter rule
func (fm *FilterManager) AddFilter(rule *models.FilterRule) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	// 验证过滤器表达式
	validation := fm.ValidateFilter(rule.Expression)
	if !validation.IsValid {
		return fmt.Errorf("invalid filter expression: %s", validation.ErrorMessage)
	}

	// 生成 ID 如果没有提供
	if rule.ID == "" {
		rule.ID = generateFilterID()
	}

	// 设置时间戳
	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	fm.filters[rule.ID] = rule
	log.Printf("添加过滤器: %s (%s)", rule.Name, rule.Expression)
	
	return nil
}

// UpdateFilter updates an existing filter rule
func (fm *FilterManager) UpdateFilter(id string, updates *models.FilterRule) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	existing, exists := fm.filters[id]
	if !exists {
		return fmt.Errorf("filter with ID %s not found", id)
	}

	// 验证新的表达式（如果有更改）
	if updates.Expression != "" && updates.Expression != existing.Expression {
		validation := fm.ValidateFilter(updates.Expression)
		if !validation.IsValid {
			return fmt.Errorf("invalid filter expression: %s", validation.ErrorMessage)
		}
		existing.Expression = updates.Expression
	}

	// 更新其他字段
	if updates.Name != "" {
		existing.Name = updates.Name
	}
	if updates.Description != "" {
		existing.Description = updates.Description
	}
	if updates.IsActive != existing.IsActive {
		existing.IsActive = updates.IsActive
	}

	existing.UpdatedAt = time.Now()
	
	log.Printf("更新过滤器: %s", id)
	return nil
}

// DeleteFilter removes a filter rule
func (fm *FilterManager) DeleteFilter(id string) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if _, exists := fm.filters[id]; !exists {
		return fmt.Errorf("filter with ID %s not found", id)
	}

	// 如果删除的是当前活动过滤器，清除活动状态
	if fm.activeFilter != nil && fm.activeFilter.ID == id {
		fm.activeFilter = nil
		log.Printf("清除活动过滤器: %s", id)
	}

	delete(fm.filters, id)
	log.Printf("删除过滤器: %s", id)
	return nil
}

// GetFilter retrieves a filter by ID
func (fm *FilterManager) GetFilter(id string) (*models.FilterRule, error) {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	filter, exists := fm.filters[id]
	if !exists {
		return nil, fmt.Errorf("filter with ID %s not found", id)
	}

	// 返回副本以避免并发修改
	filterCopy := *filter
	return &filterCopy, nil
}

// ListFilters returns all saved filters
func (fm *FilterManager) ListFilters() []*models.FilterRule {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	filters := make([]*models.FilterRule, 0, len(fm.filters))
	for _, filter := range fm.filters {
		filterCopy := *filter
		filters = append(filters, &filterCopy)
	}

	return filters
}

// SetActiveFilter sets the active filter for packet capture
func (fm *FilterManager) SetActiveFilter(id string) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if id == "" {
		// 清除活动过滤器
		fm.activeFilter = nil
		log.Printf("清除活动过滤器")
		return nil
	}

	filter, exists := fm.filters[id]
	if !exists {
		return fmt.Errorf("filter with ID %s not found", id)
	}

	if !filter.IsActive {
		return fmt.Errorf("filter %s is not active", id)
	}

	fm.activeFilter = filter
	log.Printf("设置活动过滤器: %s (%s)", filter.Name, filter.Expression)
	return nil
}

// GetActiveFilter returns the currently active filter
func (fm *FilterManager) GetActiveFilter() *models.FilterRule {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	if fm.activeFilter == nil {
		return nil
	}

	// 返回副本
	filterCopy := *fm.activeFilter
	return &filterCopy
}

// GetActiveFilterExpression returns the expression of the active filter
func (fm *FilterManager) GetActiveFilterExpression() string {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	if fm.activeFilter == nil {
		return ""
	}
	return fm.activeFilter.Expression
}

// UpdateStats updates filter statistics
func (fm *FilterManager) UpdateStats(totalPackets, filteredPackets, droppedPackets int64) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	fm.stats.TotalPackets = totalPackets
	fm.stats.FilteredPackets = filteredPackets
	fm.stats.DroppedPackets = droppedPackets

	if totalPackets > 0 {
		fm.stats.FilterRatio = float64(filteredPackets) / float64(totalPackets)
	} else {
		fm.stats.FilterRatio = 0.0
	}
}

// GetStats returns current filter statistics
func (fm *FilterManager) GetStats() *models.FilterStats {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	statsCopy := *fm.stats
	return &statsCopy
}

// GetPresetFilters returns preset filter templates
func (fm *FilterManager) GetPresetFilters() []*models.PresetFilter {
	return fm.presets
}

// getPresetFilters returns common preset filters
func getPresetFilters() []*models.PresetFilter {
	return []*models.PresetFilter{
		{
			ID:          "preset_http",
			Name:        "HTTP 流量",
			Expression:  "tcp port 80",
			Description: "捕获 HTTP 网页流量",
			Category:    "protocol",
		},
		{
			ID:          "preset_https",
			Name:        "HTTPS 流量",
			Expression:  "tcp port 443",
			Description: "捕获 HTTPS 加密网页流量",
			Category:    "protocol",
		},
		{
			ID:          "preset_dns",
			Name:        "DNS 查询",
			Expression:  "udp port 53",
			Description: "捕获 DNS 域名解析流量",
			Category:    "protocol",
		},
		{
			ID:          "preset_ssh",
			Name:        "SSH 连接",
			Expression:  "tcp port 22",
			Description: "捕获 SSH 远程登录流量",
			Category:    "protocol",
		},
		{
			ID:          "preset_ftp",
			Name:        "FTP 传输",
			Expression:  "tcp port 21 or tcp port 20",
			Description: "捕获 FTP 文件传输流量",
			Category:    "protocol",
		},
		{
			ID:          "preset_tcp_only",
			Name:        "仅 TCP",
			Expression:  "tcp",
			Description: "仅捕获 TCP 协议数据包",
			Category:    "protocol",
		},
		{
			ID:          "preset_udp_only",
			Name:        "仅 UDP",
			Expression:  "udp",
			Description: "仅捕获 UDP 协议数据包",
			Category:    "protocol",
		},
		{
			ID:          "preset_icmp_only",
			Name:        "仅 ICMP",
			Expression:  "icmp",
			Description: "仅捕获 ICMP 协议数据包（ping等）",
			Category:    "protocol",
		},
		{
			ID:          "preset_syn_packets",
			Name:        "TCP SYN 包",
			Expression:  "tcp[tcpflags] & tcp-syn != 0",
			Description: "捕获 TCP 连接建立请求",
			Category:    "traffic",
		},
		{
			ID:          "preset_large_packets",
			Name:        "大数据包",
			Expression:  "greater 1000",
			Description: "捕获大于1000字节的数据包",
			Category:    "traffic",
		},
	}
}

// generateFilterID generates a unique filter ID
func generateFilterID() string {
	// 使用时间戳和随机字节确保唯一性
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	return fmt.Sprintf("filter_%d_%s", time.Now().UnixNano(), hex.EncodeToString(randomBytes))
}