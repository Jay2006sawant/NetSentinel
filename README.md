# 🛡️ NetSentinel

NetSentinel is a Kubernetes-native network security monitoring and policy enforcement tool that provides real-time visibility into network traffic, detects policy violations, and identifies potential security threats.

## ✨ Features

- 🔒 **Network Policy Compliance**: Monitor and enforce Kubernetes NetworkPolicy compliance
- 📊 **Policy Drift Detection**: Detect deviations from defined network policies
- 🚨 **Anomaly Detection**: Identify suspicious network patterns and traffic anomalies
- 🔄 **Lateral Movement Detection**: Track and analyze pod-to-pod communication
- 📈 **Metrics & Monitoring**: Prometheus metrics and Grafana dashboards
- ⚡ **Alerting**: Configurable alerts for security events

## 📋 Prerequisites

- 🐳 Kubernetes cluster (v1.19+)
- 🔧 eBPF support in the kernel
- 📦 Helm 3.x
- 🛠️ kubectl configured

## 🚀 Quick Start

1. Add the NetSentinel Helm repository:
   ```bash
   helm repo add netsentinel https://netsentinel.github.io/charts
   helm repo update
   ```

2. Install NetSentinel:
   ```bash
   helm install netsentinel netsentinel/netsentinel \
     --namespace monitoring \
     --create-namespace
   ```

3. Access the dashboards:
   - 📊 Grafana: `http://localhost:3000`
   - 📈 Prometheus: `http://localhost:9090`
   - ⚡ Alertmanager: `http://localhost:9093`

## ⚙️ Configuration

### 🔧 NetSentinel Configuration

```yaml
metrics:
  enabled: true
  port: 9090

policy:
  drift:
    max_age: 24h
    cleanup_interval: 1h

anomaly:
  detector:
    window: 1h
    min_samples: 100
    thresholds:
      traffic_volume: 2.0
      connection_rate: 2.0
  lateral:
    min_connections: 5
    analysis_window: 1h
    rate_threshold: 10
```

### 🔔 Alerting Configuration

Configure alert receivers in `alertmanager.yml`:
```yaml
receivers:
  - name: 'slack-notifications'
    slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK'
        channel: '#network-alerts'
  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_KEY'
```

## 🏗️ Architecture

NetSentinel consists of several components:

1. **Core Components**:
   - ✅ Policy Compliance Checker
   - 📊 Drift Detector
   - 🚨 Anomaly Detector
   - 🔄 Lateral Movement Detector

2. **Monitoring Stack**:
   - 📈 Prometheus for metrics collection
   - 📊 Grafana for visualization
   - ⚡ Alertmanager for alert routing

3. **eBPF Components**:
   - 🔍 Traffic Monitor
   - 📦 Packet Analysis

## 🔒 Security

NetSentinel requires privileged access to the host network for eBPF functionality. The following security measures are implemented:

- 👥 RBAC with least privilege
- 🌐 Network policy isolation
- 🔐 Secure metrics endpoints
- 🔒 Encrypted communication

## 🛠️ Troubleshooting

Common issues and solutions:

1. **eBPF Loading Failed**:
   - ✅ Verify kernel version (4.9+)
   - 🔍 Check for eBPF support
   - 🔐 Ensure privileged mode is enabled

2. **Metrics Not Showing**:
   - ⚙️ Check Prometheus configuration
   - 🔍 Verify service endpoints
   - 🌐 Check network policies

3. **High Resource Usage**:
   - ⚡ Adjust sampling rate
   - 📊 Modify retention periods
   - 📈 Scale resources

## 🤝 Contributing

1. 🍴 Fork the repository
2. 🌿 Create a feature branch
3. 💾 Commit your changes
4. 📤 Push to the branch
5. 🔄 Create a Pull Request

## 📄 License

Apache License 2.0 