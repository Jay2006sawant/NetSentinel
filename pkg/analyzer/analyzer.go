package analyzer

import (
	"context"
	"net/http"
	"sync"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	"github.com/netsentinel/pkg/ebpf"
	"github.com/netsentinel/pkg/policy"
	"github.com/netsentinel/pkg/anomaly"
	"github.com/netsentinel/pkg/metrics"
	"github.com/sirupsen/logrus"
)

// Analyzer processes network traffic events and detects policy violations
type Analyzer struct {
	trafficMonitor    *ebpf.TrafficMonitor
	complianceChecker *policy.ComplianceChecker
	driftDetector     *policy.DriftDetector
	anomalyDetector   *anomaly.AnomalyDetector
	lateralDetector   *anomaly.LateralDetector
	metricsCollector  *metrics.Collector
	metricsServer     *metrics.Server
	stopCh           chan struct{}
	wg               sync.WaitGroup
	log              *logrus.Logger
}

// NewAnalyzer creates a new traffic analyzer
func NewAnalyzer(metricsAddr string) (*Analyzer, error) {
	monitor, err := ebpf.NewTrafficMonitor()
	if err != nil {
		return nil, err
	}

	complianceChecker := policy.NewComplianceChecker()
	driftDetector := policy.NewDriftDetector(complianceChecker)
	anomalyDetector := anomaly.NewAnomalyDetector(nil)
	lateralDetector := anomaly.NewLateralDetector(nil)
	metricsCollector := metrics.NewCollector()
	metricsServer := metrics.NewServer(metricsAddr)

	return &Analyzer{
		trafficMonitor:    monitor,
		complianceChecker: complianceChecker,
		driftDetector:     driftDetector,
		anomalyDetector:   anomalyDetector,
		lateralDetector:   lateralDetector,
		metricsCollector:  metricsCollector,
		metricsServer:     metricsServer,
		stopCh:           make(chan struct{}),
		log:              logrus.New(),
	}, nil
}

// Start begins the traffic analysis
func (a *Analyzer) Start(ctx context.Context) error {
	if err := a.trafficMonitor.Start(); err != nil {
		return err
	}

	a.wg.Add(3)
	go a.processEvents(ctx)
	go a.cleanupLoop(ctx)
	go a.startMetricsServer(ctx)

	return nil
}

// Stop gracefully shuts down the analyzer
func (a *Analyzer) Stop() {
	close(a.stopCh)
	a.trafficMonitor.Stop()
	a.metricsServer.Stop(context.Background())
	a.wg.Wait()
}

// AddPolicy adds a NetworkPolicy to the compliance checker
func (a *Analyzer) AddPolicy(policy *networkingv1.NetworkPolicy) {
	a.complianceChecker.AddPolicy(policy)
}

// RemovePolicy removes a NetworkPolicy from the compliance checker
func (a *Analyzer) RemovePolicy(namespace, name string) {
	a.complianceChecker.RemovePolicy(namespace, name)
}

// GetDriftReport returns the current policy drift report
func (a *Analyzer) GetDriftReport() map[string]interface{} {
	return a.driftDetector.GetDriftReport()
}

// GetAnomalyReport returns the current anomaly detection report
func (a *Analyzer) GetAnomalyReport() map[string]interface{} {
	return a.anomalyDetector.GetAnomalyReport()
}

// GetLateralReport returns the current lateral movement report
func (a *Analyzer) GetLateralReport() map[string]interface{} {
	return a.lateralDetector.GetLateralReport()
}

func (a *Analyzer) processEvents(ctx context.Context) {
	defer a.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case event := <-a.trafficMonitor.Events():
			a.analyzeEvent(event)
		}
	}
}

func (a *Analyzer) cleanupLoop(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.driftDetector.Cleanup(1 * time.Hour)
			a.lateralDetector.Cleanup(1 * time.Hour)
		}
	}
}

func (a *Analyzer) startMetricsServer(ctx context.Context) {
	defer a.wg.Done()

	if err := a.metricsServer.Start(); err != nil && err != http.ErrServerClosed {
		a.log.WithError(err).Error("Metrics server error")
	}
}

func (a *Analyzer) analyzeEvent(event ebpf.TrafficEvent) {
	// Record traffic metrics
	a.metricsCollector.RecordTrafficEvent(event)

	// Process the event for policy drift detection
	a.driftDetector.ProcessEvent(event)

	// Process the event for anomaly detection
	a.anomalyDetector.ProcessEvent(event)

	// Process the event for lateral movement detection
	a.lateralDetector.ProcessEvent(event)

	// Log the event with policy compliance information
	allowed, reason, err := a.complianceChecker.CheckCompliance(event)
	if err != nil {
		a.log.WithError(err).Error("Error checking policy compliance")
		return
	}

	// Record policy compliance metrics
	a.metricsCollector.RecordPolicyCompliance(
		event.PodNamespace,
		event.PodName,
		"network-policy",
		allowed,
	)

	if !allowed {
		a.metricsCollector.RecordPolicyViolation(
			event.PodNamespace,
			event.PodName,
			"network-policy",
			reason,
		)
	}

	a.log.WithFields(logrus.Fields{
		"source_ip":      event.SourceIP,
		"dest_ip":        event.DestIP,
		"source_port":    event.SourcePort,
		"dest_port":      event.DestPort,
		"protocol":       event.Protocol,
		"pod_namespace":  event.PodNamespace,
		"pod_name":       event.PodName,
		"container_id":   event.ContainerID,
		"bytes":          event.Bytes,
		"timestamp":      time.Unix(0, int64(event.Timestamp)),
		"allowed":        allowed,
		"reason":         reason,
	}).Debug("Processing traffic event")
}