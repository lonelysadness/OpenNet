package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type socketInfo struct {
	inode string
	uid   int
}

func findProcessBySocket(protocol uint8, srcIP uint32, srcPort uint16) ProcessInfo {
	// Try to find socket in /proc/net/tcp or /proc/net/udp
	var netFile string
	switch protocol {
	case 6:
		netFile = "/proc/net/tcp"
	case 17:
		netFile = "/proc/net/udp"
	default:
		return ProcessInfo{}
	}

	socketInode := findSocketInode(netFile, srcIP, srcPort)
	if socketInode == "" {
		return ProcessInfo{}
	}

	// Find process using socket inode
	pid := findPidByInode(socketInode)
	if pid == -1 {
		return ProcessInfo{}
	}

	return getProcessInfo(pid)
}

func findSocketInode(netFile string, srcIP uint32, srcPort uint16) string {
	file, err := os.Open(netFile)
	if err != nil {
		return ""
	}
	defer file.Close()

	// Convert IP to hex format used in proc
	localAddr := fmt.Sprintf("%08X:%04X", srcIP, srcPort)

	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		// Check both local and remote addresses
		if fields[1] == localAddr || fields[2] == localAddr {
			return fields[9] // inode field
		}
	}
	return ""
}

func findPidByInode(inode string) int {
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}

	for _, process := range processes {
		pid, err := strconv.Atoi(process.Name())
		if err != nil {
			continue
		}

		fdPath := filepath.Join("/proc", process.Name(), "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if err != nil {
				continue
			}

			if strings.Contains(link, "socket:["+inode+"]") {
				return pid
			}
		}
	}
	return -1
}

func getProcessInfo(pid int) ProcessInfo {
	if pid <= 0 {
		return ProcessInfo{}
	}

	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	cmdline, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return ProcessInfo{PID: pid}
	}

	// Clean up cmdline
	cmdlineStr := strings.TrimRight(string(cmdline), "\x00")
	parts := strings.Split(cmdlineStr, "\x00")
	name := filepath.Base(parts[0])

	exePath, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))

	return ProcessInfo{
		PID:         pid,
		Name:        name,
		Path:        exePath,
		CommandLine: strings.Join(parts, " "),
	}
}
