package agent

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// commonPorts is the list of ports scanned on the local host.
// Add or remove ports here to change what gets scanned.
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443,
	445, 993, 995, 1433, 1723, 3306, 3389,
	5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
}

// OpenPort represents a single open port found during a scan.
type OpenPort struct {
	Port int    `json:"port"`
	Proto string `json:"proto"`
}

// ScanLocalPorts checks each port in commonPorts against localhost
// and returns the ones that accept a TCP connection.
// timeout controls how long to wait per port (keep this small).
func ScanLocalPorts(timeout time.Duration) []OpenPort {
	results := make([]OpenPort, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("127.0.0.1:%d", p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return // port closed/filtered, skip
			}
			conn.Close()
			
			mu.Lock()
			results = append(results, OpenPort{Port: p, Proto: "tcp"})
			mu.Unlock()
		}(port)
	}
	
	wg.Wait()
	return results
}

// LogOpenPorts runs a scan and logs the results. Call this on a timer
// from the agent (see integration note in agent.go).
func LogOpenPorts() {
	ports := ScanLocalPorts(300 * time.Millisecond)
	if len(ports) == 0 {
		slog.Info("Port scan: no open ports found in scanned list")
		return
	}
	nums := make([]int, len(ports))
	for i, p := range ports {
		nums[i] = p.Port
	}
	slog.Info("Port scan results", "open_ports", nums, "count", len(nums))
}
