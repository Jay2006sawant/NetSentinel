package analyzer

import (
	"context"
	"sync"
	"time"

	"github.com/netsentinel/pkg/ebpf"
	"github.com/sirupsen/logrus"
)

// Analyzer processes network traffic events and detects policy violations
type Analyzer struct {
	trafficMonitor *ebpf.TrafficMonitor
	stopCh         chan struct{}
	wg             sync.WaitGroup
	log            *logrus.Logger
}

// NewAnalyzer creates a new traffic analyzer
func NewAnalyzer() (*Analyzer, error) {
	monitor, err := ebpf.NewTrafficMonitor()
	if err != nil {
		return nil, err
	}

	return &Analyzer{
		trafficMonitor: monitor,
		stopCh:         make(chan struct{}),
		log:            logrus.New(),
	}, nil
}

// Start begins the traffic analysis
func (a *Analyzer) Start(ctx context.Context) error {
	if err := a.trafficMonitor.Start(); err != nil {
		return err
	}

	a.wg.Add(1)
	go a.processEvents(ctx)

	return nil
}

// Stop gracefully shuts down the analyzer
func (a *Analyzer) Stop() {
	close(a.stopCh)
	a.trafficMonitor.Stop()
	a.wg.Wait()
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

func (a *Analyzer) analyzeEvent(event ebpf.TrafficEvent) {
	// TODO: Implement policy compliance checking
	// TODO: Implement anomaly detection
	// TODO: Update metrics

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
	}).Debug("Processing traffic event")
} 