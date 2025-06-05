package policy

import (
	"fmt"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

// CRPPeerRule is the agent's internal representation of a resolved peer rule
// (Ingress/Egress).
type CRPPeerRule struct {
	// MatchingPeerIdentities is a set of peer NumericIdentities.
	MatchingPeerIdentities map[identity.NumericIdentity]struct{}

	// ToPorts is a list of destination ports identified by port number and
	// protocol, along with optional L7 rules and authentication requirements.
	ToPorts api.PortRules

	// ICMPs is a list of ICMP rule identified by type number
	// which the endpoint subject to the rule is allowed to
	// receive connections on.
	ICMPs api.ICMPRules

	// FromCIDRs applies only for Ingress rules, not supported yet
	FromCIDRs []string

	// ToFQDNs is a list of FQDNs that the endpoint subject to the rule is allowed to
	// connect to. applies only for Egress rules, not supported yet
	ToFQDNs []string
}

type ResolvedPolicy struct {
	// SourcePolicyUID is an identifier for the original K8s policy object
	// (e.g., Kubernetes NetworkPolicy UID, or CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy Name/Namespace)
	// from which this resolved policy was derived. This can be constructed from v2alpha1.PolicyRef.
	SourcePolicyUID string

	// IngressRules is a list of resolved ingress rules.
	IngressRules []CRPPeerRule

	// IngressDenyRules is a list of resolved ingress deny rules.
	IngressDenyRules []CRPPeerRule

	// EgressRules is a list of resolved egress rules.
	EgressRules []CRPPeerRule

	// EgressDenyRules is a list of resolved egress deny rules.
	EgressDenyRules []CRPPeerRule

	// subject identities that this policy applies to
	// Note: this is not the same as the identities in CRPPeerRule.MatchingPeerIdentities,
	// which are the identities that match the rule. This is the set of identities that
	// the policy applies to.
	AppliesTo map[identity.NumericIdentity]struct{}
}

type MatchingResolvedPolicies map[string]*ResolvedPolicy

// IdentityPolicyState holds the computed policy and related metadata for a subject identity
// when centralized policies are enabled.
type IdentityPolicyState struct {
	// lock
	lock.Mutex

	// ComputedPolicy is the cached selector policy for this subject, derived from CRPs.
	// The selectorPolicy type is an existing type within the policy package and
	// will be populated directly from resolved data provided by CRPRuleSets.
	ComputedPolicy *selectorPolicy

	// MatchingCRPUIDset maps the UID of source network policy (CNP,CCNP,KNP) of a
	// CiliumResolvedPolicy CR to the agent's CRPRuleSet derived from it, for all
	// CRPs that apply to this subject.
	MatchingCRPUIDset MatchingResolvedPolicies

	// ingressEnabled
	IngressPolicyEnabled bool

	// egressEnabled
	EgressPolicyEnabled bool
}

// Helper function to create a ResolvedPolicy from a CiliumResolvedPolicySpec.
func ConvertToResolvedPolicy(spec *v2alpha1.CiliumResolvedPolicySpec, RuleKey string) (*ResolvedPolicy, error) {
	// Basic validation (e.g., spec != nil)
	if spec == nil {
		return nil, fmt.Errorf("CiliumResolvedPolicySpec is nil")
	}

	// Convert slice of appliesTo identities to map for efficient lookup
	appliesToIdentitiesMap := make(map[identity.NumericIdentity]struct{})
	for _, id := range spec.AppliesTo.Identities {
		appliesToIdentitiesMap[id] = struct{}{}
	}

	sourceUID := RuleKey
	if sourceUID == "" {
		return nil, fmt.Errorf("sourcePolicyUID is empty, cannot create ResolvedPolicy")
	}

	// Helper function to convert v2alpha1 peer rules to internal representation
	convertIngressRule := func(rules []v2alpha1.IngressResolvedRule) []CRPPeerRule {
		if rules == nil {
			return nil
		}
		ingressRules := make([]CRPPeerRule, len(rules))
		for i, rule := range rules {
			// Convert slice of peer identities to map for efficient lookup
			matchingIdentitiesMap := make(map[identity.NumericIdentity]struct{})
			for _, id := range rule.FromIdentities {
				matchingIdentitiesMap[id] = struct{}{}
			}
			ingressRules[i] = CRPPeerRule{
				MatchingPeerIdentities: matchingIdentitiesMap,
				ToPorts:                rule.ToPorts,
				ICMPs:                  rule.ICMPs,
				FromCIDRs:              rule.FromCIDRs,
			}
		}
		return ingressRules
	}

	convertEgressRule := func(rules []v2alpha1.EgressResolvedRule) []CRPPeerRule {
		if rules == nil {
			return nil
		}
		egressRules := make([]CRPPeerRule, len(rules))
		for i, rule := range rules {
			// Convert slice of peer identities to map for efficient lookup
			matchingIdentitiesMap := make(map[identity.NumericIdentity]struct{})
			for _, id := range rule.ToIdentities {
				matchingIdentitiesMap[id] = struct{}{}
			}
			egressRules[i] = CRPPeerRule{
				MatchingPeerIdentities: matchingIdentitiesMap,
				ToPorts:                rule.ToPorts,
				ICMPs:                  rule.ICMPs,
				ToFQDNs:                rule.ToFQDNs,
			}
		}
		return egressRules
	}

	// Create and return the internal CRPRuleSet representation
	return &ResolvedPolicy{
		SourcePolicyUID:  sourceUID,
		IngressRules:     convertIngressRule(spec.IngressRules),
		IngressDenyRules: convertIngressRule(spec.IngressDenyRules),
		EgressRules:      convertEgressRule(spec.EgressRules),
		EgressDenyRules:  convertEgressRule(spec.EgressDenyRules),
		AppliesTo:        appliesToIdentitiesMap,
	}, nil
}

// ResolvedIdentityPolicyOperation represents the type of operation to perform on resolved identity policy
type ResolvedIdentityPolicyOperation int

const (
	// ResolvedIdentityPolicyUpsert indicates an upsert operation
	ResolvedIdentityPolicyUpsert ResolvedIdentityPolicyOperation = iota
	// ResolvedIdentityPolicyDelete indicates a delete operation
	ResolvedIdentityPolicyDelete
)

// String returns the string representation of the operation
func (op ResolvedIdentityPolicyOperation) String() string {
	switch op {
	case ResolvedIdentityPolicyUpsert:
		return "Upsert"
	case ResolvedIdentityPolicyDelete:
		return "Delete"
	default:
		return "Unknown"
	}
}

// ResolvedIdentityPolicyUpdate represents an update to resolved identity policy
// this struct is used to push updates from policy watcher to the policy importer
type ResolvedIdentityPolicyUpdate struct {
	// The time the policy initially began to be processed in Cilium, such as when the
	// policy was received from the API server.
	ProcessingStartTime time.Time

	// ResolvedPolicy is the resolved identity policy to be applied.
	ResolvedPolicy *ResolvedPolicy

	// UID is the unique identifier for the policy update
	Uid string

	// DoneChan, if not nil, will have a single value emitted: the revision of the
	// policy repository when the update has been processed.
	// Thus must be a buffered channel!
	DoneChan chan<- uint64

	// Operation indicates the type of operation to perform (Upsert or Delete).
	Operation ResolvedIdentityPolicyOperation
}
