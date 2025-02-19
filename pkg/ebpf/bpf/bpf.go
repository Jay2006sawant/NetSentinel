package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang traffic_monitor bpf/traffic_monitor.c -- -I/usr/include/linux -I/usr/include/x86_64-linux-gnu

// bpfEvent represents the event structure from the eBPF program
type bpfEvent struct {
	SourceIP     [4]byte
	DestIP       [4]byte
	SourcePort   uint16
	DestPort     uint16
	Protocol     uint8
	PodNamespace [64]byte
	PodName      [64]byte
	ContainerID  [64]byte
	Bytes        uint64
	Timestamp    uint64
} 