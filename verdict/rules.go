package verdict

import (
	"fmt"
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
			fmt.Printf("Rule matched: %s, Action: %s\n", rule.Name, rule.Action.String())
			return rule.Action, rule.Name
		}
	}

	// Default allow if no rules match
	return ALLOW, "default"
}

func (r *Rule) matches(process, path string, srcIP, dstIP net.IP, dstPort uint16, protocol uint8) bool {
	fmt.Printf("Checking rule: %s\n", r.Name)
	if r.ProcessName != "" && !strings.Contains(strings.ToLower(process), strings.ToLower(r.ProcessName)) {
		fmt.Printf("Process name does not match: %s\n", r.ProcessName)
		return false
	}

	if r.ProcessPath != "" && !strings.Contains(strings.ToLower(path), strings.ToLower(r.ProcessPath)) {
		fmt.Printf("Process path does not match: %s\n", r.ProcessPath)
		return false
	}

	if r.SrcIP != nil && !r.SrcIP.Equal(srcIP) {
		fmt.Printf("Source IP does not match: %s\n", r.SrcIP.String())
		return false
	}

	if r.DstIP != nil && !r.DstIP.Equal(dstIP) {
		fmt.Printf("Destination IP does not match: %s\n", r.DstIP.String())
		return false
	}

	if r.DstPort != 0 && r.DstPort != dstPort {
		fmt.Printf("Destination port does not match: %d\n", r.DstPort)
		return false
	}

	if r.Protocol != 0 && r.Protocol != protocol {
		fmt.Printf("Protocol does not match: %d\n", r.Protocol)
		return false
	}

	return true
}
