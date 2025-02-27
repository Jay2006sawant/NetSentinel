package anomaly

import (
	"math"
	"sync"
	"time"

	"github.com/netsentinel/pkg/ebpf"
	"github.com/sirupsen/logrus"
)

// AnomalyDetector identifies suspicious network patterns
type AnomalyDetector struct {
	// Traffic statistics
	trafficStats map[string]*TrafficStats
	// Baseline statistics
	baselines map[string]*BaselineStats
	// Configuration
	config *Config
	// Mutex for thread safety
	mu sync.RWMutex
	// Logger
	log *logrus.Logger
}

// Config holds anomaly detection configuration
type Config struct {
	// Threshold for traffic volume anomalies (standard deviations)
	VolumeThreshold float64
	// Threshold for connection rate anomalies (standard deviations)
	RateThreshold float64
	// Time window for baseline calculation
	BaselineWindow time.Duration
	// Minimum number of samples for baseline
	MinSamples int
}

// TrafficStats tracks traffic statistics for a pod
type TrafficStats struct {
	Bytes          uint64
	Packets        uint64
	Connections    uint64
	LastSeen       time.Time
	ConnectionRate float64
	ByteRate       float64
}

// BaselineStats holds baseline statistics for a pod
type BaselineStats struct {
	MeanBytes       float64
	StdDevBytes     float64
	MeanPackets     float64
	StdDevPackets   float64
	MeanConnections float64
	StdDevConnections float64
	LastUpdated     time.Time
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(config *Config) *AnomalyDetector {
	if config == nil {
		config = &Config{
			VolumeThreshold:  3.0,
			RateThreshold:    3.0,
			BaselineWindow:   24 * time.Hour,
			MinSamples:       100,
		}
	}

	return &AnomalyDetector{
		trafficStats: make(map[string]*TrafficStats),
		baselines:    make(map[string]*BaselineStats),
		config:       config,
		log:         logrus.New(),
	}
}

// ProcessEvent analyzes a traffic event for anomalies
func (d *AnomalyDetector) ProcessEvent(event ebpf.TrafficEvent) {
	key := event.PodNamespace + "/" + event.PodName

	d.mu.Lock()
	defer d.mu.Unlock()

	// Update traffic statistics
	stats, exists := d.trafficStats[key]
	if !exists {
		stats = &TrafficStats{}
		d.trafficStats[key] = stats
	}

	now := time.Now()
	timeDiff := now.Sub(stats.LastSeen).Seconds()
	if timeDiff > 0 {
		stats.ByteRate = float64(event.Bytes) / timeDiff
		stats.ConnectionRate = 1.0 / timeDiff
	}

	stats.Bytes += event.Bytes
	stats.Packets++
	stats.Connections++
	stats.LastSeen = now

	// Check for anomalies
	d.checkAnomalies(key, stats)
}

// checkAnomalies detects anomalies in traffic patterns
func (d *AnomalyDetector) checkAnomalies(key string, stats *TrafficStats) {
	baseline, exists := d.baselines[key]
	if !exists {
		// Initialize baseline if not exists
		baseline = &BaselineStats{
			MeanBytes:       float64(stats.Bytes),
			MeanPackets:     float64(stats.Packets),
			MeanConnections: float64(stats.Connections),
			LastUpdated:     time.Now(),
		}
		d.baselines[key] = baseline
		return
	}

	// Check for volume anomalies
	if d.isAnomaly(float64(stats.Bytes), baseline.MeanBytes, baseline.StdDevBytes, d.config.VolumeThreshold) {
		d.log.WithFields(logrus.Fields{
			"pod":           key,
			"current_bytes": stats.Bytes,
			"mean_bytes":    baseline.MeanBytes,
			"std_dev":       baseline.StdDevBytes,
		}).Warn("Volume anomaly detected")
	}

	// Check for rate anomalies
	if d.isAnomaly(stats.ConnectionRate, baseline.MeanConnections, baseline.StdDevConnections, d.config.RateThreshold) {
		d.log.WithFields(logrus.Fields{
			"pod":               key,
			"current_rate":      stats.ConnectionRate,
			"mean_connections":  baseline.MeanConnections,
			"std_dev":          baseline.StdDevConnections,
		}).Warn("Connection rate anomaly detected")
	}

	// Update baseline periodically
	if time.Since(baseline.LastUpdated) > d.config.BaselineWindow {
		d.updateBaseline(key, stats)
	}
}

// isAnomaly checks if a value is anomalous based on mean and standard deviation
func (d *AnomalyDetector) isAnomaly(value, mean, stdDev, threshold float64) bool {
	if stdDev == 0 {
		return false
	}
	zScore := math.Abs((value - mean) / stdDev)
	return zScore > threshold
}

// updateBaseline updates the baseline statistics for a pod
func (d *AnomalyDetector) updateBaseline(key string, stats *TrafficStats) {
	baseline := d.baselines[key]
	
	// Update mean and standard deviation using Welford's online algorithm
	delta := float64(stats.Bytes) - baseline.MeanBytes
	baseline.MeanBytes += delta / float64(d.config.MinSamples)
	baseline.StdDevBytes = math.Sqrt(baseline.StdDevBytes*baseline.StdDevBytes + 
		delta*(float64(stats.Bytes)-baseline.MeanBytes)/float64(d.config.MinSamples))

	delta = float64(stats.Packets) - baseline.MeanPackets
	baseline.MeanPackets += delta / float64(d.config.MinSamples)
	baseline.StdDevPackets = math.Sqrt(baseline.StdDevPackets*baseline.StdDevPackets + 
		delta*(float64(stats.Packets)-baseline.MeanPackets)/float64(d.config.MinSamples))

	delta = float64(stats.Connections) - baseline.MeanConnections
	baseline.MeanConnections += delta / float64(d.config.MinSamples)
	baseline.StdDevConnections = math.Sqrt(baseline.StdDevConnections*baseline.StdDevConnections + 
		delta*(float64(stats.Connections)-baseline.MeanConnections)/float64(d.config.MinSamples))

	baseline.LastUpdated = time.Now()
}

// GetAnomalyReport returns a report of detected anomalies
func (d *AnomalyDetector) GetAnomalyReport() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	report := make(map[string]interface{})
	for key, stats := range d.trafficStats {
		baseline := d.baselines[key]
		if baseline == nil {
			continue
		}

		report[key] = map[string]interface{}{
			"current_bytes":      stats.Bytes,
			"baseline_bytes":     baseline.MeanBytes,
			"bytes_std_dev":      baseline.StdDevBytes,
			"current_rate":       stats.ConnectionRate,
			"baseline_rate":      baseline.MeanConnections,
			"rate_std_dev":       baseline.StdDevConnections,
			"last_updated":       baseline.LastUpdated,
		}
	}
	return report
} 