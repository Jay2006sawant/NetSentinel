package anomaly

import (
	"sync"
	"time"

	"github.com/netsentinel/pkg/ebpf"
	"github.com/sirupsen/logrus"
)

// LateralDetector identifies suspicious pod-to-pod communication patterns
type LateralDetector struct {
	// Connection graph
	connections map[string]map[string]*ConnectionStats
	// Configuration
	config *LateralConfig
	// Mutex for thread safety
	mu sync.RWMutex
	// Logger
	log *logrus.Logger
}

// LateralConfig holds lateral movement detection configuration
type LateralConfig struct {
	// Minimum number of connections to consider suspicious
	MinConnections int
	// Time window for connection analysis
	AnalysisWindow time.Duration
	// Threshold for connection rate anomalies
	RateThreshold float64
}

// ConnectionStats tracks connection statistics between pods
type ConnectionStats struct {
	Count         int
	LastSeen      time.Time
	FirstSeen     time.Time
	Bytes         uint64
	Packets       uint64
	ConnectionRate float64
}

// NewLateralDetector creates a new lateral movement detector
func NewLateralDetector(config *LateralConfig) *LateralDetector {
	if config == nil {
		config = &LateralConfig{
			MinConnections:  5,
			AnalysisWindow:  1 * time.Hour,
			RateThreshold:   3.0,
		}
	}

	return &LateralDetector{
		connections: make(map[string]map[string]*ConnectionStats),
		config:      config,
		log:        logrus.New(),
	}
}

// ProcessEvent analyzes a traffic event for lateral movement patterns
func (d *LateralDetector) ProcessEvent(event ebpf.TrafficEvent) {
	sourceKey := event.PodNamespace + "/" + event.PodName
	destKey := event.DestIP // In a real implementation, this would be resolved to a pod

	d.mu.Lock()
	defer d.mu.Unlock()

	// Initialize connection maps if needed
	if _, exists := d.connections[sourceKey]; !exists {
		d.connections[sourceKey] = make(map[string]*ConnectionStats)
	}

	// Update connection statistics
	stats, exists := d.connections[sourceKey][destKey]
	if !exists {
		stats = &ConnectionStats{
			FirstSeen: time.Now(),
		}
		d.connections[sourceKey][destKey] = stats
	}

	now := time.Now()
	timeDiff := now.Sub(stats.LastSeen).Seconds()
	if timeDiff > 0 {
		stats.ConnectionRate = 1.0 / timeDiff
	}

	stats.Count++
	stats.Bytes += event.Bytes
	stats.Packets++
	stats.LastSeen = now

	// Check for lateral movement patterns
	d.checkLateralMovement(sourceKey, destKey, stats)
}

// checkLateralMovement detects suspicious pod-to-pod communication patterns
func (d *LateralDetector) checkLateralMovement(sourceKey, destKey string, stats *ConnectionStats) {
	// Check for high connection count
	if stats.Count >= d.config.MinConnections {
		d.log.WithFields(logrus.Fields{
			"source_pod": sourceKey,
			"dest_pod":   destKey,
			"count":      stats.Count,
		}).Warn("High connection count detected")
	}

	// Check for rapid connection rate
	if stats.ConnectionRate > d.config.RateThreshold {
		d.log.WithFields(logrus.Fields{
			"source_pod":     sourceKey,
			"dest_pod":       destKey,
			"connection_rate": stats.ConnectionRate,
		}).Warn("Rapid connection rate detected")
	}

	// Check for connections to multiple pods
	if len(d.connections[sourceKey]) > d.config.MinConnections {
		d.log.WithFields(logrus.Fields{
			"source_pod": sourceKey,
			"pod_count":  len(d.connections[sourceKey]),
		}).Warn("Multiple pod connections detected")
	}
}

// GetLateralReport returns a report of detected lateral movement patterns
func (d *LateralDetector) GetLateralReport() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	report := make(map[string]interface{})
	for sourceKey, connections := range d.connections {
		sourceReport := make(map[string]interface{})
		for destKey, stats := range connections {
			sourceReport[destKey] = map[string]interface{}{
				"count":           stats.Count,
				"bytes":           stats.Bytes,
				"packets":         stats.Packets,
				"connection_rate": stats.ConnectionRate,
				"first_seen":      stats.FirstSeen,
				"last_seen":       stats.LastSeen,
			}
		}
		report[sourceKey] = sourceReport
	}
	return report
}

// Cleanup removes stale connection data
func (d *LateralDetector) Cleanup(maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	for sourceKey, connections := range d.connections {
		for destKey, stats := range connections {
			if now.Sub(stats.LastSeen) > maxAge {
				delete(connections, destKey)
			}
		}
		if len(connections) == 0 {
			delete(d.connections, sourceKey)
		}
	}
} 