package verdict

import (
	"net"
	"strings"
	"sync"
)

type Action uint8

const (
	ALLOW Action = iota // Changed from Allow to ALLOW
	BLOCK               // Changed from Block to BLOCK
)

// Add String method for Action type
func (a Action) String() string {
	switch a {
	case ALLOW: // Updated to use ALLOW
		return "ALLOW"
	case BLOCK: // Updated to use BLOCK
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

type Rule struct {
	Name        string
	Action      Action
	ProcessName string
	ProcessPath string
	SrcIP       net.IP
	DstIP       net.IP
	DstPort     uint16
	Protocol    uint8
}

type RuleSet struct {
	rules []Rule
	mu    sync.RWMutex
}

func NewRuleSet() *RuleSet {
	return &RuleSet{
		rules: make([]Rule, 0),
	}
}

func (rs *RuleSet) AddRule(rule Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = append(rs.rules, rule)
}

func (rs *RuleSet) CheckVerdict(process, path string, srcIP, dstIP net.IP, dstPort uint16, protocol uint8) (Action, string) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	for _, rule := range rs.rules {
		if rule.matches(process, path, srcIP, dstIP, dstPort, protocol) {
			return rule.Action, rule.Name
		}
	}

	// Default allow if no rules match
	return ALLOW, "default"
}

func (r *Rule) matches(process, path string, srcIP, dstIP net.IP, dstPort uint16, protocol uint8) bool {
	if r.ProcessName != "" && !strings.Contains(strings.ToLower(process), strings.ToLower(r.ProcessName)) {
		return false
	}

	if r.ProcessPath != "" && !strings.Contains(strings.ToLower(path), strings.ToLower(r.ProcessPath)) {
		return false
	}

	if r.SrcIP != nil && !r.SrcIP.Equal(srcIP) {
		return false
	}

	if r.DstIP != nil && !r.DstIP.Equal(dstIP) {
		return false
	}

	if r.DstPort != 0 && r.DstPort != dstPort {
		return false
	}

	if r.Protocol != 0 && r.Protocol != protocol {
		return false
	}

	return true
}
