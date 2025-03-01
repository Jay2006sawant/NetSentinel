package metrics

import (
	"sync"

	"github.com/netsentinel/pkg/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// Collector manages Prometheus metrics collection
type Collector struct {
	// Traffic metrics
	trafficBytes *prometheus.CounterVec
	trafficPackets *prometheus.CounterVec
	trafficConnections *prometheus.CounterVec
	trafficLatency *prometheus.HistogramVec

	// Policy metrics
	policyViolations *prometheus.CounterVec
	policyCompliance *prometheus.GaugeVec

	// Anomaly metrics
	anomalyScore *prometheus.GaugeVec
	anomalyCount *prometheus.CounterVec

	// Lateral movement metrics
	lateralConnections *prometheus.GaugeVec
	lateralRates *prometheus.GaugeVec

	// Mutex for thread safety
	mu sync.RWMutex
	// Logger
	log *logrus.Logger
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	c := &Collector{
		trafficBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "netsentinel_traffic_bytes_total",
				Help: "Total bytes of network traffic",
			},
			[]string{"namespace", "pod", "direction", "protocol"},
		),
		trafficPackets: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "netsentinel_traffic_packets_total",
				Help: "Total packets of network traffic",
			},
			[]string{"namespace", "pod", "direction", "protocol"},
		),
		trafficConnections: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "netsentinel_traffic_connections_total",
				Help: "Total network connections",
			},
			[]string{"namespace", "pod", "direction"},
		),
		trafficLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "netsentinel_traffic_latency_seconds",
				Help:    "Network traffic latency in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"namespace", "pod", "direction"},
		),
		policyViolations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "netsentinel_policy_violations_total",
				Help: "Total number of policy violations",
			},
			[]string{"namespace", "pod", "policy", "reason"},
		),
		policyCompliance: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netsentinel_policy_compliance",
				Help: "Policy compliance status (1 = compliant, 0 = non-compliant)",
			},
			[]string{"namespace", "pod", "policy"},
		),
		anomalyScore: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netsentinel_anomaly_score",
				Help: "Anomaly detection score",
			},
			[]string{"namespace", "pod", "type"},
		),
		anomalyCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "netsentinel_anomalies_total",
				Help: "Total number of anomalies detected",
			},
			[]string{"namespace", "pod", "type"},
		),
		lateralConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netsentinel_lateral_connections",
				Help: "Number of lateral connections",
			},
			[]string{"namespace", "pod", "target"},
		),
		lateralRates: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netsentinel_lateral_connection_rate",
				Help: "Rate of lateral connections",
			},
			[]string{"namespace", "pod", "target"},
		),
		log: logrus.New(),
	}

	// Register metrics
	prometheus.MustRegister(
		c.trafficBytes,
		c.trafficPackets,
		c.trafficConnections,
		c.trafficLatency,
		c.policyViolations,
		c.policyCompliance,
		c.anomalyScore,
		c.anomalyCount,
		c.lateralConnections,
		c.lateralRates,
	)

	return c
}

// RecordTrafficEvent records metrics for a traffic event
func (c *Collector) RecordTrafficEvent(event ebpf.TrafficEvent) {
	labels := prometheus.Labels{
		"namespace": event.PodNamespace,
		"pod":      event.PodName,
		"direction": "egress",
		"protocol": event.Protocol,
	}

	c.trafficBytes.With(labels).Add(float64(event.Bytes))
	c.trafficPackets.With(labels).Inc()
	c.trafficConnections.With(prometheus.Labels{
		"namespace": event.PodNamespace,
		"pod":      event.PodName,
		"direction": "egress",
	}).Inc()
}

// RecordPolicyViolation records metrics for a policy violation
func (c *Collector) RecordPolicyViolation(namespace, pod, policy, reason string) {
	labels := prometheus.Labels{
		"namespace": namespace,
		"pod":      pod,
		"policy":   policy,
		"reason":   reason,
	}

	c.policyViolations.With(labels).Inc()
	c.policyCompliance.With(prometheus.Labels{
		"namespace": namespace,
		"pod":      pod,
		"policy":   policy,
	}).Set(0)
}

// RecordPolicyCompliance records metrics for policy compliance
func (c *Collector) RecordPolicyCompliance(namespace, pod, policy string, compliant bool) {
	value := 0.0
	if compliant {
		value = 1.0
	}

	c.policyCompliance.With(prometheus.Labels{
		"namespace": namespace,
		"pod":      pod,
		"policy":   policy,
	}).Set(value)
}

// RecordAnomaly records metrics for an anomaly detection
func (c *Collector) RecordAnomaly(namespace, pod, anomalyType string, score float64) {
	labels := prometheus.Labels{
		"namespace": namespace,
		"pod":      pod,
		"type":     anomalyType,
	}

	c.anomalyScore.With(labels).Set(score)
	c.anomalyCount.With(labels).Inc()
}

// RecordLateralMovement records metrics for lateral movement detection
func (c *Collector) RecordLateralMovement(namespace, pod, target string, connections int, rate float64) {
	labels := prometheus.Labels{
		"namespace": namespace,
		"pod":      pod,
		"target":   target,
	}

	c.lateralConnections.With(labels).Set(float64(connections))
	c.lateralRates.With(labels).Set(rate)
} 