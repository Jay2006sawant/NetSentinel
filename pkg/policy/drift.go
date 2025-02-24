package policy

import (
	"fmt"
	"sync"
	"time"

	"github.com/netsentinel/pkg/ebpf"
	"github.com/sirupsen/logrus"
)

// DriftDetector identifies discrepancies between declared policies and actual traffic
type DriftDetector struct {
	complianceChecker *ComplianceChecker
	trafficStats      map[string]*TrafficStats
	mu               sync.RWMutex
	log              *logrus.Logger
}

// TrafficStats tracks traffic statistics for policy analysis
type TrafficStats struct {
	AllowedBytes    uint64
	BlockedBytes    uint64
	AllowedPackets  uint64
	BlockedPackets  uint64
	LastSeen        time.Time
	ViolationCount  uint64
}

// NewDriftDetector creates a new policy drift detector
func NewDriftDetector(complianceChecker *ComplianceChecker) *DriftDetector {
	return &DriftDetector{
		complianceChecker: complianceChecker,
		trafficStats:      make(map[string]*TrafficStats),
		log:              logrus.New(),
	}
}

// ProcessEvent analyzes a traffic event for policy drift
func (d *DriftDetector) ProcessEvent(event ebpf.TrafficEvent) {
	key := fmt.Sprintf("%s/%s", event.PodNamespace, event.PodName)
	
	d.mu.Lock()
	defer d.mu.Unlock()

	stats, exists := d.trafficStats[key]
	if !exists {
		stats = &TrafficStats{}
		d.trafficStats[key] = stats
	}

	stats.LastSeen = time.Now()

	// Check policy compliance
	allowed, reason, err := d.complianceChecker.CheckCompliance(event)
	if err != nil {
		d.log.WithError(err).Error("Error checking policy compliance")
		return
	}

	if allowed {
		stats.AllowedBytes += event.Bytes
		stats.AllowedPackets++
	} else {
		stats.BlockedBytes += event.Bytes
		stats.BlockedPackets++
		stats.ViolationCount++
		
		d.log.WithFields(logrus.Fields{
			"pod":           key,
			"source_ip":     event.SourceIP,
			"dest_ip":       event.DestIP,
			"source_port":   event.SourcePort,
			"dest_port":     event.DestPort,
			"protocol":      event.Protocol,
			"reason":        reason,
			"violation_count": stats.ViolationCount,
		}).Warn("Policy violation detected")
	}
}

// GetDriftReport generates a report of policy drift
func (d *DriftDetector) GetDriftReport() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	report := make(map[string]interface{})
	for key, stats := range d.trafficStats {
		if stats.ViolationCount > 0 {
			report[key] = map[string]interface{}{
				"violation_count":  stats.ViolationCount,
				"allowed_bytes":    stats.AllowedBytes,
				"blocked_bytes":    stats.BlockedBytes,
				"allowed_packets":  stats.AllowedPackets,
				"blocked_packets":  stats.BlockedPackets,
				"last_seen":        stats.LastSeen,
			}
		}
	}
	return report
}

// Cleanup removes stale traffic statistics
func (d *DriftDetector) Cleanup(maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	for key, stats := range d.trafficStats {
		if now.Sub(stats.LastSeen) > maxAge {
			delete(d.trafficStats, key)
		}
	}
} 