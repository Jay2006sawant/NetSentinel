package ebpf

import (
	"fmt"
	"log"
	"net"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// TrafficEvent represents a network traffic event
type TrafficEvent struct {
	SourceIP      net.IP
	DestIP        net.IP
	SourcePort    uint16
	DestPort      uint16
	Protocol      uint8
	PodNamespace  string
	PodName       string
	ContainerID   string
	Bytes         uint64
	Timestamp     uint64
}

// TrafficMonitor handles eBPF-based traffic monitoring
type TrafficMonitor struct {
	objs       *bpfObjects
	link       link.Link
	events     chan TrafficEvent
	stopCh     chan struct{}
}

// NewTrafficMonitor creates a new eBPF traffic monitor
func NewTrafficMonitor() (*TrafficMonitor, error) {
	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory lock: %v", err)
	}

	// Load pre-compiled programs and maps
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}

	// Attach the program to the network interface
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: "eth0", // TODO: Make this configurable
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching XDP program: %v", err)
	}

	return &TrafficMonitor{
		objs:   &objs,
		link:   link,
		events: make(chan TrafficEvent, 1000),
		stopCh: make(chan struct{}),
	}, nil
}

// Start begins traffic monitoring
func (tm *TrafficMonitor) Start() error {
	go tm.processEvents()
	return nil
}

// Stop gracefully shuts down the monitor
func (tm *TrafficMonitor) Stop() {
	close(tm.stopCh)
	if tm.link != nil {
		tm.link.Close()
	}
	if tm.objs != nil {
		tm.objs.Close()
	}
}

// Events returns the channel for receiving traffic events
func (tm *TrafficMonitor) Events() <-chan TrafficEvent {
	return tm.events
}

func (tm *TrafficMonitor) processEvents() {
	for {
		select {
		case <-tm.stopCh:
			return
		default:
			// Read events from the eBPF map
			var event bpfEvent
			if err := tm.objs.EventsMap.LookupAndDelete(nil, unsafe.Pointer(&event)); err != nil {
				continue
			}

			tm.events <- TrafficEvent{
				SourceIP:     net.IP(event.SourceIP[:]),
				DestIP:       net.IP(event.DestIP[:]),
				SourcePort:   event.SourcePort,
				DestPort:     event.DestPort,
				Protocol:     event.Protocol,
				PodNamespace: string(event.PodNamespace[:]),
				PodName:      string(event.PodName[:]),
				ContainerID:  string(event.ContainerID[:]),
				Bytes:        event.Bytes,
				Timestamp:    event.Timestamp,
			}
		}
	}
} 