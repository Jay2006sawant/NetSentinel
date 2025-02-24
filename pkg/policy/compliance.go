package policy

import (
	"fmt"
	"net"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	"github.com/netsentinel/pkg/ebpf"
)

// ComplianceChecker verifies network traffic against NetworkPolicy rules
type ComplianceChecker struct {
	policies map[string]*networkingv1.NetworkPolicy
}

// NewComplianceChecker creates a new policy compliance checker
func NewComplianceChecker() *ComplianceChecker {
	return &ComplianceChecker{
		policies: make(map[string]*networkingv1.NetworkPolicy),
	}
}

// AddPolicy adds a NetworkPolicy to the checker
func (c *ComplianceChecker) AddPolicy(policy *networkingv1.NetworkPolicy) {
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	c.policies[key] = policy
}

// RemovePolicy removes a NetworkPolicy from the checker
func (c *ComplianceChecker) RemovePolicy(namespace, name string) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	delete(c.policies, key)
}

// CheckCompliance verifies if a traffic event complies with NetworkPolicy rules
func (c *ComplianceChecker) CheckCompliance(event ebpf.TrafficEvent) (bool, string, error) {
	// Find applicable policies for the source pod
	var applicablePolicies []*networkingv1.NetworkPolicy
	for _, policy := range c.policies {
		if policy.Namespace == event.PodNamespace {
			if matchesPodSelector(policy.Spec.PodSelector, event.PodName) {
				applicablePolicies = append(applicablePolicies, policy)
			}
		}
	}

	if len(applicablePolicies) == 0 {
		return true, "No policies apply to this pod", nil
	}

	// Check if traffic is allowed by any policy
	for _, policy := range applicablePolicies {
		if isTrafficAllowed(policy, event) {
			return true, fmt.Sprintf("Traffic allowed by policy %s/%s", policy.Namespace, policy.Name), nil
		}
	}

	return false, "Traffic blocked by all applicable policies", nil
}

func matchesPodSelector(selector metav1.LabelSelector, podName string) bool {
	// TODO: Implement proper label selector matching
	// For now, just check if the pod name matches
	return true
}

func isTrafficAllowed(policy *networkingv1.NetworkPolicy, event ebpf.TrafficEvent) bool {
	// Check ingress rules
	for _, rule := range policy.Spec.Ingress {
		if ruleMatches(rule, event) {
			return true
		}
	}

	// Check egress rules
	for _, rule := range policy.Spec.Egress {
		if ruleMatches(rule, event) {
			return true
		}
	}

	return false
}

func ruleMatches(rule networkingv1.NetworkPolicyRule, event ebpf.TrafficEvent) bool {
	// Check ports
	if len(rule.Ports) > 0 {
		portMatch := false
		for _, port := range rule.Ports {
			if port.Protocol != nil && *port.Protocol == getProtocol(event.Protocol) {
				if port.Port != nil && port.Port.IntVal == int32(event.DestPort) {
					portMatch = true
					break
				}
			}
		}
		if !portMatch {
			return false
		}
	}

	// Check IP blocks
	if len(rule.From) > 0 {
		ipMatch := false
		for _, peer := range rule.From {
			if peer.IPBlock != nil {
				if isIPInCIDR(event.SourceIP, peer.IPBlock.CIDR) {
					ipMatch = true
					break
				}
			}
		}
		if !ipMatch {
			return false
		}
	}

	return true
}

func getProtocol(protocol uint8) networkingv1.Protocol {
	switch protocol {
	case 6: // TCP
		return networkingv1.ProtocolTCP
	case 17: // UDP
		return networkingv1.ProtocolUDP
	default:
		return networkingv1.Protocol("")
	}
}

func isIPInCIDR(ip net.IP, cidr string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipnet.Contains(ip)
} 