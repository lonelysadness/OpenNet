package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"nettest/verdict" // Change this line to use relative import

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang capture bpf/capture.c -- -I/usr/include/bpf -I/usr/include

type ConnectionInfo struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	IsOutgoing uint8 // New field to track packet direction
}

type ConnectionState string

const (
	StateNew         ConnectionState = "NEW"
	StateEstablished ConnectionState = "ESTABLISHED"
	StateClosed      ConnectionState = "CLOSED"
)

type Connection struct {
	SrcIP         net.IP
	DstIP         net.IP
	SrcPort       uint16
	DstPort       uint16
	Protocol      uint8
	State         ConnectionState
	ProcessInfo   ProcessInfo
	FirstSeen     time.Time
	LastSeen      time.Time
	Verdict       verdict.Action
	VerdictReason string
}

type ProcessInfo struct {
	PID         int
	Name        string
	Path        string
	CommandLine string
}

type ConnectionTracker struct {
	connections map[string]*Connection
	mu          sync.RWMutex
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]*Connection),
	}
}

func (ct *ConnectionTracker) key(conn *ConnectionInfo) string {
	src := make([]byte, 4)
	dst := make([]byte, 4)
	binary.LittleEndian.PutUint32(src, conn.SrcIP)
	binary.LittleEndian.PutUint32(dst, conn.DstIP)
	return fmt.Sprintf("%s:%d-%s:%d-%d",
		net.IP(src).String(), conn.SrcPort,
		net.IP(dst).String(), conn.DstPort,
		conn.Protocol)
}

// Add global ruleset
var globalRules = verdict.NewRuleSet()

func init() {
	// Add some example rules
	globalRules.AddRule(verdict.Rule{
		Name:        "Block Social Media",
		Action:      verdict.BLOCK, // Changed from Block to BLOCK
		ProcessName: "chrome",
		DstIP:       net.ParseIP("157.240.1.1"), // example Facebook IP
	})

	globalRules.AddRule(verdict.Rule{
		Name:        "Block Gaming During Work",
		Action:      verdict.BLOCK, // Changed from Block to BLOCK
		ProcessName: "steam",
	})
}

func (ct *ConnectionTracker) Update(conn *ConnectionInfo) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	key := ct.key(conn)
	now := time.Now()

	srcIP := make([]byte, 4)
	dstIP := make([]byte, 4)
	binary.LittleEndian.PutUint32(srcIP, conn.SrcIP)
	binary.LittleEndian.PutUint32(dstIP, conn.DstIP)

	if existing, exists := ct.connections[key]; exists {
		existing.LastSeen = now
		return
	}

	procInfo := findProcess(conn.SrcIP, conn.SrcPort, conn.Protocol)

	// Get verdict from rules
	action, reason := globalRules.CheckVerdict(
		procInfo.Name,
		procInfo.Path,
		net.IP(srcIP),
		net.IP(dstIP),
		conn.DstPort,
		conn.Protocol,
	)

	newConn := &Connection{
		SrcIP:         net.IP(srcIP),
		DstIP:         net.IP(dstIP),
		SrcPort:       conn.SrcPort,
		DstPort:       conn.DstPort,
		Protocol:      conn.Protocol,
		State:         StateNew,
		ProcessInfo:   procInfo,
		FirstSeen:     now,
		LastSeen:      now,
		Verdict:       action,
		VerdictReason: reason,
	}

	ct.connections[key] = newConn
	printNewConnection(newConn)
}

// Add this helper function
func isLocalIP(ip net.IP) bool {
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}

func findProcess(srcIP uint32, srcPort uint16, protocol uint8) ProcessInfo {
	// First just use /proc parsing since we're not getting PID from eBPF yet
	return findProcessBySocket(protocol, srcIP, srcPort)
}

func printNewConnection(conn *Connection) {
	proto := "unknown"
	switch conn.Protocol {
	case 6:
		proto = "TCP"
	case 17:
		proto = "UDP"
	}

	verdict := "✅ ALLOW"
	if conn.Verdict == verdict.BLOCK { // Changed from Block to BLOCK
		verdict = "❌ BLOCK"
	}

	procInfo := "Unknown Process"
	if conn.ProcessInfo.Name != "" {
		procInfo = fmt.Sprintf("%s (PID: %d)", conn.ProcessInfo.Name, conn.ProcessInfo.PID)
	}

	fmt.Printf("[%s] %s (%s) - %s %s:%d → %s:%d | Process: %s\n",
		time.Now().Format("15:04:05"),
		verdict,
		conn.VerdictReason,
		proto,
		conn.SrcIP.String(), conn.SrcPort,
		conn.DstIP.String(), conn.DstPort,
		procInfo)
}

func isBlockedDomain(ip string) bool {
	// Add your blocking logic here
	blockedIPs := map[string]bool{
		"192.168.1.1": true, // Example
	}
	return blockedIPs[ip]
}

func cleanupOldConnections(ct *ConnectionTracker) {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		ct.mu.Lock()
		now := time.Now()
		for key, conn := range ct.connections {
			if now.Sub(conn.LastSeen) > 5*time.Minute {
				delete(ct.connections, key)
			}
		}
		ct.mu.Unlock()
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Please specify network interface")
	}
	ifaceName := os.Args[1]

	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("looking up interface %q: %v", ifaceName, err)
	}

	// Load pre-compiled programs
	objs := captureObjects{}
	if err := loadCaptureObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach XDP program to network interface
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CapturePackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attaching XDP: %v", err)
	}
	defer xdpLink.Close()

	// Open perf event reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %v", err)
	}
	defer rd.Close()

	// Handle signals for cleanup
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	fmt.Printf("Capturing packets on %s...\n", ifaceName)

	tracker := NewConnectionTracker()
	go cleanupOldConnections(tracker)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading perf event: %v", err)
				continue
			}

			var connInfo ConnectionInfo
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &connInfo); err != nil {
				log.Printf("parsing perf event: %v", err)
				continue
			}

			tracker.Update(&connInfo)
		}
	}()

	<-c
	fmt.Println("\nDetaching program and exiting...")
}
