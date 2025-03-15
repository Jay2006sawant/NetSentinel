package policy

import (
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestComplianceChecker(t *testing.T) {
	tests := []struct {
		name     string
		policy   *networkingv1.NetworkPolicy
		event    *TrafficEvent
		expected bool
		reason   string
	}{
		{
			name: "Allow matching pod selector",
			policy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"role": "frontend",
										},
									},
								},
							},
						},
					},
				},
			},
			event: &TrafficEvent{
				SourcePod: &PodInfo{
					Labels: map[string]string{
						"role": "frontend",
					},
				},
				DestPod: &PodInfo{
					Labels: map[string]string{
						"app": "test",
					},
				},
				Protocol: "TCP",
				Port:     80,
			},
			expected: true,
			reason:   "",
		},
		{
			name: "Deny non-matching port",
			policy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     &intstr80,
								},
							},
						},
					},
				},
			},
			event: &TrafficEvent{
				SourcePod: &PodInfo{
					Labels: map[string]string{
						"role": "frontend",
					},
				},
				DestPod: &PodInfo{
					Labels: map[string]string{
						"app": "test",
					},
				},
				Protocol: "TCP",
				Port:     443,
			},
			expected: false,
			reason:   "port not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewComplianceChecker()
			checker.AddPolicy(tt.policy)

			compliant, reason := checker.CheckCompliance(tt.event)
			if compliant != tt.expected {
				t.Errorf("expected compliance %v, got %v", tt.expected, compliant)
			}
			if tt.reason != "" && reason != tt.reason {
				t.Errorf("expected reason %q, got %q", tt.reason, reason)
			}
		})
	}
}

func TestDriftDetector(t *testing.T) {
	checker := NewComplianceChecker()
	detector := NewDriftDetector(checker)

	// Add a policy
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "test",
				},
			},
		},
	}
	checker.AddPolicy(policy)

	// Process some events
	events := []*TrafficEvent{
		{
			SourcePod: &PodInfo{
				Name: "pod1",
				Labels: map[string]string{
					"app": "test",
				},
			},
			DestPod: &PodInfo{
				Name: "pod2",
				Labels: map[string]string{
					"app": "test",
				},
			},
			Protocol: "TCP",
			Port:     80,
			Timestamp: time.Now(),
		},
		{
			SourcePod: &PodInfo{
				Name: "pod3",
				Labels: map[string]string{
					"app": "test",
				},
			},
			DestPod: &PodInfo{
				Name: "pod4",
				Labels: map[string]string{
					"app": "test",
				},
			},
			Protocol: "TCP",
			Port:     443,
			Timestamp: time.Now(),
		},
	}

	for _, event := range events {
		detector.ProcessEvent(event)
	}

	// Get drift report
	report := detector.GetDriftReport()
	if len(report) == 0 {
		t.Error("expected non-empty drift report")
	}

	// Test cleanup
	detector.Cleanup(24 * time.Hour)
	report = detector.GetDriftReport()
	if len(report) != 0 {
		t.Error("expected empty drift report after cleanup")
	}
} 