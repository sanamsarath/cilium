package policy

import (
	"testing"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertToCRPRuleSet(t *testing.T) {
	tests := []struct {
		name        string
		spec        *v2alpha1.CiliumResolvedPolicySpec
		expected    *CRPRuleSet
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil spec",
			spec:        nil,
			expected:    nil,
			expectError: true,
			errorMsg:    "CiliumResolvedPolicySpec is nil",
		},
		{
			name: "empty UID",
			spec: &v2alpha1.CiliumResolvedPolicySpec{
				PolicyRef: v2alpha1.PolicyRef{
					UID: "",
				},
			},
			expected:    nil,
			expectError: true,
			errorMsg:    "unable to construct SourcePolicyUID from PolicyRef",
		},
		{
			name: "valid spec with all fields",
			spec: &v2alpha1.CiliumResolvedPolicySpec{
				PolicyRef: v2alpha1.PolicyRef{
					UID: "test-uid-123",
				},
				SubjectIdentities: []identity.NumericIdentity{1, 2, 3},
				IngressRuleIdentities: []v2alpha1.CRPPeerRule{
					{
						MatchingPeerIdentities: []identity.NumericIdentity{10, 20},
						ToPorts: api.PortRules{
							{
								Ports: []api.PortProtocol{
									{Port: "80", Protocol: api.ProtoTCP},
								},
							},
						},
					},
				},
				IngressDenyRuleIdentities: []v2alpha1.CRPPeerRule{
					{
						MatchingPeerIdentities: []identity.NumericIdentity{30},
						ToPorts: api.PortRules{
							{
								Ports: []api.PortProtocol{
									{Port: "443", Protocol: api.ProtoTCP},
								},
							},
						},
					},
				},
				EgressRuleIdentities: []v2alpha1.CRPPeerRule{
					{
						MatchingPeerIdentities: []identity.NumericIdentity{40, 50},
						ToPorts:                api.PortRules{},
					},
				},
				EgressDenyRuleIdentities: []v2alpha1.CRPPeerRule{
					{
						MatchingPeerIdentities: []identity.NumericIdentity{60},
						ToPorts:                nil,
					},
				},
			},
			expected: &CRPRuleSet{
				SourcePolicyUID: "test-uid-123",
				SubjectIdentities: map[identity.NumericIdentity]struct{}{
					1: {},
					2: {},
					3: {},
				},
				IngressRules: []CRPPeerRule{
					{
						MatchingPeerIdentities: map[identity.NumericIdentity]struct{}{
							10: {},
							20: {},
						},
						ToPorts: api.PortRules{
							{
								Ports: []api.PortProtocol{
									{Port: "80", Protocol: api.ProtoTCP},
								},
							},
						},
					},
				},
				IngressDenyRules: []CRPPeerRule{
					{
						MatchingPeerIdentities: map[identity.NumericIdentity]struct{}{
							30: {},
						},
						ToPorts: api.PortRules{
							{
								Ports: []api.PortProtocol{
									{Port: "443", Protocol: api.ProtoTCP},
								},
							},
						},
					},
				},
				EgressRules: []CRPPeerRule{
					{
						MatchingPeerIdentities: map[identity.NumericIdentity]struct{}{
							40: {},
							50: {},
						},
						ToPorts: api.PortRules{},
					},
				},
				EgressDenyRules: []CRPPeerRule{
					{
						MatchingPeerIdentities: map[identity.NumericIdentity]struct{}{
							60: {},
						},
						ToPorts: nil,
					},
				},
			},
			expectError: false,
		},
		{
			name: "minimal valid spec",
			spec: &v2alpha1.CiliumResolvedPolicySpec{
				PolicyRef: v2alpha1.PolicyRef{
					UID: "minimal-uid",
				},
				SubjectIdentities: []identity.NumericIdentity{},
			},
			expected: &CRPRuleSet{
				SourcePolicyUID:   "minimal-uid",
				SubjectIdentities: map[identity.NumericIdentity]struct{}{},
				IngressRules:      nil,
				IngressDenyRules:  nil,
				EgressRules:       nil,
				EgressDenyRules:   nil,
			},
			expectError: false,
		},
		{
			name: "spec with duplicate subject identities",
			spec: &v2alpha1.CiliumResolvedPolicySpec{
				PolicyRef: v2alpha1.PolicyRef{
					UID: "duplicate-uid",
				},
				SubjectIdentities: []identity.NumericIdentity{1, 2, 1, 3, 2},
			},
			expected: &CRPRuleSet{
				SourcePolicyUID: "duplicate-uid",
				SubjectIdentities: map[identity.NumericIdentity]struct{}{
					1: {},
					2: {},
					3: {},
				},
				IngressRules:     nil,
				IngressDenyRules: nil,
				EgressRules:      nil,
				EgressDenyRules:  nil,
			},
			expectError: false,
		},
		{
			name: "spec with empty peer rule identities",
			spec: &v2alpha1.CiliumResolvedPolicySpec{
				PolicyRef: v2alpha1.PolicyRef{
					UID: "empty-peers-uid",
				},
				SubjectIdentities: []identity.NumericIdentity{1},
				IngressRuleIdentities: []v2alpha1.CRPPeerRule{
					{
						MatchingPeerIdentities: []identity.NumericIdentity{},
						ToPorts:                api.PortRules{},
					},
				},
			},
			expected: &CRPRuleSet{
				SourcePolicyUID: "empty-peers-uid",
				SubjectIdentities: map[identity.NumericIdentity]struct{}{
					1: {},
				},
				IngressRules: []CRPPeerRule{
					{
						MatchingPeerIdentities: map[identity.NumericIdentity]struct{}{},
						ToPorts:                api.PortRules{},
					},
				},
				IngressDenyRules: nil,
				EgressRules:      nil,
				EgressDenyRules:  nil,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ConvertToCRPRuleSet(tt.spec)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
