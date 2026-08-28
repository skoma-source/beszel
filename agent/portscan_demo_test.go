package agent

import (
	"testing"
	"time"
)

func TestPortScanDemo(t *testing.T) {
	ports := ScanLocalPorts(300 * time.Millisecond)
	t.Logf("Open ports found: %+v", ports)
}
