package models

import (
	"time"
)

// FilterRule represents a BPF filter rule
type FilterRule struct {
	ID          string    `json:"id"`          // 唯一标识符
	Name        string    `json:"name"`        // 过滤器名称
	Expression  string    `json:"expression"`  // BPF表达式，如 "tcp port 80"
	Description string    `json:"description"` // 过滤器描述
	IsActive    bool      `json:"is_active"`   // 是否启用
	CreatedAt   time.Time `json:"created_at"`  // 创建时间
	UpdatedAt   time.Time `json:"updated_at"`  // 更新时间
}

// FilterStats represents filter statistics
type FilterStats struct {
	TotalPackets    int64 `json:"total_packets"`    // 总数据包数
	FilteredPackets int64 `json:"filtered_packets"` // 过滤后的数据包数
	DroppedPackets  int64 `json:"dropped_packets"`  // 被丢弃的数据包数
	FilterRatio     float64 `json:"filter_ratio"`   // 过滤比例 (filtered/total)
}

// FilterValidationResult represents filter validation result
type FilterValidationResult struct {
	IsValid      bool   `json:"is_valid"`      // 是否有效
	ErrorMessage string `json:"error_message"` // 错误信息
	ParsedFields struct {
		Protocols []string `json:"protocols"` // 解析出的协议
		Ports     []int    `json:"ports"`     // 解析出的端口
		IPs       []string `json:"ips"`       // 解析出的IP地址
	} `json:"parsed_fields"`
}

// PresetFilter represents common preset filters
type PresetFilter struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
	Category    string `json:"category"` // 类别：protocol, port, traffic, etc.
}

// FilterRequest represents a filter application request
type FilterRequest struct {
	FilterID   string `json:"filter_id,omitempty"`   // 使用已保存的过滤器
	Expression string `json:"expression,omitempty"`  // 或直接使用表达式
	SaveAs     string `json:"save_as,omitempty"`     // 可选：保存为新过滤器的名称
}

// FilterResponse represents the response after applying a filter
type FilterResponse struct {
	Status       string       `json:"status"`        // success, error
	Message      string       `json:"message"`       // 状态消息
	AppliedRule  *FilterRule  `json:"applied_rule"`  // 已应用的过滤器
	Stats        *FilterStats `json:"stats"`         // 统计信息
	ErrorDetails string       `json:"error_details"` // 详细错误信息
}