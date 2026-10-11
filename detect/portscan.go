package detect

import (
	"net"
	"sync"
	"time"
)

type portScanTracker struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	activity  map[string]*scanActivity
}

type scanActivity struct {
	ports map[uint16]time.Time
}

func newPortScanTracker(window time.Duration, threshold int) *portScanTracker {
	return &portScanTracker{
		window:    window,
		threshold: threshold,
		activity:  make(map[string]*scanActivity),
	}
}

func (p *portScanTracker) record(srcIP net.IP, dstPort uint16) (fired bool, distinctCount int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := srcIP.String()
	now := time.Now()

	act, ok := p.activity[key]
	if !ok {
		act = &scanActivity{ports: make(map[uint16]time.Time)}
		p.activity[key] = act
	}
	for port, seenAt := range act.ports {
		if now.Sub(seenAt) > p.window {
			delete(act.ports, port)
		}
	}

	act.ports[dstPort] = now

	if len(act.ports) >= p.threshold {
		count := len(act.ports)
		act.ports = make(map[uint16]time.Time)
		return true, count
	}
	return false, len(act.ports)
}
