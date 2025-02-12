# NetSentinel

NetSentinel is a Kubernetes NetworkPolicy monitoring and enforcement tool that provides real-time visibility into pod traffic and policy compliance using eBPF and flow export technologies.

## Features

- Real-time monitoring of Kubernetes NetworkPolicy resources
- Pod traffic analysis using eBPF
- Network policy drift detection
- Anomaly detection for lateral movement
- Prometheus metrics and Grafana dashboards
- Flow export integration (Antrea/IPFIX)

## Architecture

NetSentinel consists of several components:
- Policy Controller: Monitors NetworkPolicy resources
- Traffic Analyzer: Collects pod traffic data using eBPF
- Drift Detector: Analyzes policy compliance
- Anomaly Detector: Identifies suspicious network patterns
- Metrics Exporter: Exposes Prometheus metrics

## Prerequisites

- Kubernetes cluster (v1.19+)
- Go 1.21+
- eBPF support in kernel
- Prometheus and Grafana (for metrics visualization)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netsentinel.git

# Build the project
make build

# Deploy to Kubernetes
kubectl apply -f deploy/
```

## Usage

```bash
# Start the controller
./netsentinel controller

# Start the analyzer
./netsentinel analyzer
```

## License

MIT License 