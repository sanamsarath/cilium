package policy

import (
	"fmt"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
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

	// DoneChan, if not nil, will have a single value emitted: the revision of the
	// policy repository when the update has been processed.
	// Thus must be a buffered channel!
	DoneChan chan<- uint64

	// Operation indicates the type of operation to perform (Upsert or Delete).
	Operation ResolvedIdentityPolicyOperation
}

func (rules MatchingResolvedPolicies) resolveL4IngressPolicy(policyCtx PolicyContext) (ingressPolicyMap L4PolicyMap, ingress bool, err error) {
	result := NewL4PolicyMap()
	ingress = false // default to no ingress policy

	policyCtx.PolicyTrace("resolving ingress policy")

	state := traceState{}

	for _, rp := range rules {
		if len(rp.IngressRules) > 0 || len(rp.IngressDenyRules) > 0 {
			ingress = true
		}
		// check if the resolved policy is nil or has no ingress rules to resolve
		if rp != nil && len(rp.IngressRules) > 0 || len(rp.IngressDenyRules) > 0 {
			_, err := rp.resolveIngressPolicy(policyCtx, &state, result)
			if err != nil {
				return nil, ingress, fmt.Errorf("failed to resolve ingress policy for ResolvedPolicy %s: %w", rp.SourcePolicyUID, err)
			}
			state.ruleID++
		}
	}

	state.trace(len(rules), policyCtx)
	return result, ingress, nil
}

func (rules MatchingResolvedPolicies) resolveL4EgressPolicy(policyCtx PolicyContext) (egressPolicyMap L4PolicyMap, egress bool, err error) {
	result := NewL4PolicyMap()

	policyCtx.PolicyTrace("resolving egress policy")

	state := traceState{}

	for _, rp := range rules {
		if len(rp.EgressRules) > 0 || len(rp.EgressDenyRules) > 0 {
			egress = true
		}
		// check if the CRPRuleSet is nil or has no egress rules to resolve
		if rp != nil && len(rp.EgressRules) > 0 || len(rp.EgressDenyRules) > 0 {
			_, err := rp.resolveEgressPolicy(policyCtx, &state, result)
			if err != nil {
				return nil, egress, fmt.Errorf("failed to resolve egress policy for CRPRuleSet %s: %w", rp.SourcePolicyUID, err)
			}
			state.ruleID++
		}
	}

	state.trace(len(rules), policyCtx)
	return result, egress, nil
}

func (rp *ResolvedPolicy) resolveIngressPolicy(
	policyCtx PolicyContext,
	state *traceState,
	result L4PolicyMap,
) (L4PolicyMap, error) {
	found, foundDeny := 0, 0
	for _, peerRule := range rp.IngressRules {
		if len(peerRule.MatchingPeerIdentities) == 0 {
			continue // Skip rules with no matching identities
		}
		// make a copy of the map instead of passing the original
		// reference to avoid modifying the original during iteration
		peerIdentitites := make(map[identity.NumericIdentity]struct{}, len(peerRule.MatchingPeerIdentities))
		for id := range peerRule.MatchingPeerIdentities {
			peerIdentitites[id] = struct{}{}
		}

		// Merge the ingress rules
		cnt, err := mergeIngressWithIdentities(
			policyCtx,
			peerIdentitites,
			nil, // TODO: handle authentication
			peerRule.ToPorts,
			peerRule.ICMPs,
			EmptyStringLabels,
			result,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to merge ingress policy for CRPRuleSet %s: %w", rp.SourcePolicyUID, err)
		}
		if cnt > 0 {
			found += cnt
		}
	}

	oldDeny := policyCtx.SetDeny(true)
	defer policyCtx.SetDeny(oldDeny)
	for _, peerRule := range rp.IngressDenyRules {
		if len(peerRule.MatchingPeerIdentities) == 0 {
			continue // Skip rules with no matching identities
		}
		// make a copy of the map instead of passing the original
		// reference to avoid modifying the original during iteration
		peerIdentitites := make(map[identity.NumericIdentity]struct{}, len(peerRule.MatchingPeerIdentities))
		for id := range peerRule.MatchingPeerIdentities {
			peerIdentitites[id] = struct{}{}
		}

		// Merge the deny rules
		cnt, err := mergeIngressWithIdentities(
			policyCtx,
			peerIdentitites,
			nil, // TODO: handle authentication
			peerRule.ToPorts,
			peerRule.ICMPs,
			EmptyStringLabels,
			result,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to merge ingress deny policy for CRPRuleSet %s: %w", rp.SourcePolicyUID, err)
		}
		if cnt > 0 {
			foundDeny += cnt
		}
	}

	if found+foundDeny > 0 {
		if found != 0 {
			state.matchedRules++
		}
		if foundDeny != 0 {
			state.matchedDenyRules++
		}
		return result, nil
	}
	return nil, nil
}

func (rp *ResolvedPolicy) resolveEgressPolicy(
	policyCtx PolicyContext,
	state *traceState,
	result L4PolicyMap,
) (L4PolicyMap, error) {
	found, foundDeny := 0, 0
	for _, peerRule := range rp.EgressRules {
		if len(peerRule.MatchingPeerIdentities) == 0 {
			continue // Skip rules with no matching identities
		}
		// make a copy of the map instead of passing the original
		// reference to avoid modifying the original during iteration
		peerIdentitites := make(map[identity.NumericIdentity]struct{}, len(peerRule.MatchingPeerIdentities))
		for id := range peerRule.MatchingPeerIdentities {
			peerIdentitites[id] = struct{}{}
		}

		// Merge the ingress rules
		cnt, err := mergeEgressWithIdentities(
			policyCtx,
			peerIdentitites,
			nil, // TODO: handle authentication
			peerRule.ToPorts,
			peerRule.ICMPs,
			EmptyStringLabels,
			result,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to merge Egress policy for CRPRuleSet %s: %w", rp.SourcePolicyUID, err)
		}
		if cnt > 0 {
			found += cnt
		}
	}

	oldDeny := policyCtx.SetDeny(true)
	defer policyCtx.SetDeny(oldDeny)
	for _, peerRule := range rp.EgressDenyRules {
		if len(peerRule.MatchingPeerIdentities) == 0 {
			continue // Skip rules with no matching identities
		}
		// make a copy of the map instead of passing the original
		// reference to avoid modifying the original during iteration
		peerIdentitites := make(map[identity.NumericIdentity]struct{}, len(peerRule.MatchingPeerIdentities))
		for id := range peerRule.MatchingPeerIdentities {
			peerIdentitites[id] = struct{}{}
		}

		// Merge the deny rules
		cnt, err := mergeEgressWithIdentities(
			policyCtx,
			peerIdentitites,
			nil, // TODO: handle authentication
			peerRule.ToPorts,
			peerRule.ICMPs,
			EmptyStringLabels,
			result,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to merge Egress deny policy for CRPRuleSet %s: %w", rp.SourcePolicyUID, err)
		}
		if cnt > 0 {
			foundDeny += cnt
		}
	}

	if found+foundDeny > 0 {
		if found != 0 {
			state.matchedRules++
		}
		if foundDeny != 0 {
			state.matchedDenyRules++
		}
		return result, nil
	}
	return nil, nil
}

func mergeIngressWithIdentities(policyCtx PolicyContext, fromEndpoints map[identity.NumericIdentity]struct{}, auth *api.Authentication, toPorts, icmp api.PortsIterator, ruleLabels stringLabels, resMap L4PolicyMap) (int, error) {
	found := 0

	// short-circuit if no endpoint is selected
	if len(fromEndpoints) == 0 {
		// return error here, always expect fromEndpoints to be populated
		// by centralized policy controller. For wildcard endpoint selector,
		// worldwide reserved identity is used.
		return found, fmt.Errorf("no fromEndpoints provided for ingress policy merge")
	}

	// Daemon options may induce L3 allows for host/world. In this case, if
	// we find any L7 rules matching host/world then we need to turn any L7
	// restrictions on these endpoints into L7 allow-all so that the
	// traffic is always allowed, but is also always redirected through the
	// proxy
	hostWildcardL7 := make([]string, 0, 2)
	if option.Config.AlwaysAllowLocalhost() {
		hostWildcardL7 = append(hostWildcardL7, labels.IDNameHost)
	}

	var (
		cnt int
		err error
	)

	// L3-only rule (with requirements folded into fromEndpoints).
	if toPorts.Len() == 0 && icmp.Len() == 0 {
		cnt, err = mergeIngressPortProtoWithIdentities(policyCtx, fromEndpoints, auth, hostWildcardL7, &api.PortRule{}, api.PortProtocol{Port: "0", Protocol: api.ProtoAny}, api.ProtoAny, ruleLabels, resMap)
		if err != nil {
			return found, err
		}
	}

	found += cnt

	err = toPorts.Iterate(func(r api.Ports) error {
		if !policyCtx.IsDeny() {
			policyCtx.PolicyTrace("      Allows port %v\n", r.GetPortProtocols())
		} else {
			policyCtx.PolicyTrace("      Denies port %v\n", r.GetPortProtocols())
		}

		pr := r.GetPortRule()
		if pr != nil {
			if pr.Rules != nil && pr.Rules.L7Proto != "" {
				policyCtx.PolicyTrace("        l7proto: \"%s\"\n", pr.Rules.L7Proto)
			}
			if !pr.Rules.IsEmpty() {
				for _, l7 := range pr.Rules.HTTP {
					policyCtx.PolicyTrace("          %+v\n", l7)
				}
				for _, l7 := range pr.Rules.Kafka {
					policyCtx.PolicyTrace("          %+v\n", l7)
				}
				for _, l7 := range pr.Rules.L7 {
					policyCtx.PolicyTrace("          %+v\n", l7)
				}
			}
		}

		for _, p := range r.GetPortProtocols() {
			if p.Protocol.IsAny() {
				cnt, err := mergeIngressPortProtoWithIdentities(policyCtx, fromEndpoints, auth, hostWildcardL7, r, p, api.ProtoTCP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeIngressPortProtoWithIdentities(policyCtx, fromEndpoints, auth, hostWildcardL7, r, p, api.ProtoUDP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeIngressPortProtoWithIdentities(policyCtx, fromEndpoints, auth, hostWildcardL7, r, p, api.ProtoSCTP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt
			} else {
				cnt, err := mergeIngressPortProtoWithIdentities(policyCtx, fromEndpoints, auth, hostWildcardL7, r, p, p.Protocol, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt
			}
		}
		return nil
	})
	if err != nil {
		return found, err
	}

	err = icmp.Iterate(func(r api.Ports) error {
		if !policyCtx.IsDeny() {
			policyCtx.PolicyTrace("      Allows ICMP type %v\n", r.GetPortProtocols())
		} else {
			policyCtx.PolicyTrace("      Denies ICMP type %v\n", r.GetPortProtocols())
		}

		for _, p := range r.GetPortProtocols() {
			cnt, err := mergeIngressPortProtoWithIdentities(policyCtx, fromEndpoints, auth, hostWildcardL7, r, p, p.Protocol, ruleLabels, resMap)
			if err != nil {
				return err
			}
			found += cnt
		}
		return nil
	})

	return found, err
}

func mergeEgressWithIdentities(policyCtx PolicyContext, toEndpoints map[identity.NumericIdentity]struct{}, auth *api.Authentication, toPorts, icmp api.PortsIterator, ruleLabels stringLabels, resMap L4PolicyMap) (int, error) {
	found := 0

	// short-circuit if no endpoint is selected
	if len(toEndpoints) == 0 {
		// return error here, always expect fromEndpoints to be populated
		// by centralized policy controller. For wildcard endpoint selector,
		// worldwide reserved identity is used.
		return found, fmt.Errorf("no fromEndpoints provided for ingress policy merge")
	}

	var (
		cnt int
		err error
	)

	// L3-only rule (with requirements folded into fromEndpoints).
	if toPorts.Len() == 0 && icmp.Len() == 0 {
		cnt, err = mergeEgressPortProtoWithIdentities(policyCtx, toEndpoints, auth, &api.PortRule{}, api.PortProtocol{Port: "0", Protocol: api.ProtoAny}, api.ProtoAny, ruleLabels, resMap)
		if err != nil {
			return found, err
		}
	}

	found += cnt

	err = toPorts.Iterate(func(r api.Ports) error {
		if !policyCtx.IsDeny() {
			policyCtx.PolicyTrace("      Allows port %v\n", r.GetPortProtocols())
		} else {
			policyCtx.PolicyTrace("      Denies port %v\n", r.GetPortProtocols())
		}

		pr := r.GetPortRule()
		if pr != nil {
			if pr.Rules != nil && pr.Rules.L7Proto != "" {
				policyCtx.PolicyTrace("        l7proto: \"%s\"\n", pr.Rules.L7Proto)
			}
			if !pr.Rules.IsEmpty() {
				for _, l7 := range pr.Rules.HTTP {
					policyCtx.PolicyTrace("          %+v\n", l7)
				}
				for _, l7 := range pr.Rules.Kafka {
					policyCtx.PolicyTrace("          %+v\n", l7)
				}
				for _, l7 := range pr.Rules.L7 {
					policyCtx.PolicyTrace("          %+v\n", l7)
				}
			}
		}

		for _, p := range r.GetPortProtocols() {
			if p.Protocol.IsAny() {
				cnt, err := mergeEgressPortProtoWithIdentities(policyCtx, toEndpoints, auth, r, p, api.ProtoTCP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeEgressPortProtoWithIdentities(policyCtx, toEndpoints, auth, r, p, api.ProtoUDP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt

				cnt, err = mergeEgressPortProtoWithIdentities(policyCtx, toEndpoints, auth, r, p, api.ProtoSCTP, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt
			} else {
				cnt, err := mergeEgressPortProtoWithIdentities(policyCtx, toEndpoints, auth, r, p, p.Protocol, ruleLabels, resMap)
				if err != nil {
					return err
				}
				found += cnt
			}
		}
		return nil
	})
	if err != nil {
		return found, err
	}

	err = icmp.Iterate(func(r api.Ports) error {
		if !policyCtx.IsDeny() {
			policyCtx.PolicyTrace("      Allows ICMP type %v\n", r.GetPortProtocols())
		} else {
			policyCtx.PolicyTrace("      Denies ICMP type %v\n", r.GetPortProtocols())
		}

		for _, p := range r.GetPortProtocols() {
			cnt, err := mergeEgressPortProtoWithIdentities(policyCtx, toEndpoints, auth, r, p, p.Protocol, ruleLabels, resMap)
			if err != nil {
				return err
			}
			found += cnt
		}
		return nil
	})

	return found, err
}

// mergePortProto merges the L7-related data from the filter to merge
// with the L7-related data already in the existing filter, filters store
// L7rules in PerIdentitiesPolicies, and no selectors are used in this case.
func mergePortProtoWithIdentities(policyCtx PolicyContext, existingFilter, filterToMerge *L4Filter) (err error) {
	for idset, newL7Rules := range filterToMerge.PerIdentityPolicies {
		// delete the idset from the filter to merge
		delete(filterToMerge.PerIdentityPolicies, idset)

		if l7Rules, ok := existingFilter.PerIdentityPolicies[idset]; ok {
			// existing filter already has 'idset' in it, merge the rules
			if l7Rules.Equal(newL7Rules) {
				continue // identical rules need no merging
			}

			// Merge two non-identical sets of non-nil rules
			if l7Rules != nil && l7Rules.IsDeny {
				// If existing rule is deny then it's a no-op
				// Denies takes priority over any rule.
				continue
			} else if newL7Rules != nil && newL7Rules.IsDeny {
				// Overwrite existing filter if the new rule is a deny case
				// Denies takes priority over any rule.
				existingFilter.PerIdentityPolicies[idset] = newL7Rules
				continue
			}

			// One of the rules may be a nil rule, expand it to an empty non-nil rule
			if l7Rules == nil {
				l7Rules = &PerSelectorPolicy{}
			}
			if newL7Rules == nil {
				newL7Rules = &PerSelectorPolicy{}
			}

			// Merge Redirect
			if err := l7Rules.mergeRedirect(newL7Rules); err != nil {
				policyCtx.PolicyTrace("   Merge conflict: %s\n", err.Error())
				return err
			}

			if l7Rules.Authentication == nil || newL7Rules.Authentication == nil {
				if newL7Rules.Authentication != nil {
					l7Rules.Authentication = newL7Rules.Authentication
				}
			} else if !newL7Rules.Authentication.DeepEqual(l7Rules.Authentication) {
				policyCtx.PolicyTrace("   Merge conflict: mismatching auth types %s/%s\n", newL7Rules.Authentication.Mode, l7Rules.Authentication.Mode)
				return fmt.Errorf("cannot merge conflicting authentication types (%s/%s)", newL7Rules.Authentication.Mode, l7Rules.Authentication.Mode)
			}

			if l7Rules.TerminatingTLS == nil || newL7Rules.TerminatingTLS == nil {
				if newL7Rules.TerminatingTLS != nil {
					l7Rules.TerminatingTLS = newL7Rules.TerminatingTLS
				}
			} else if !newL7Rules.TerminatingTLS.Equal(l7Rules.TerminatingTLS) {
				policyCtx.PolicyTrace("   Merge conflict: mismatching terminating TLS contexts %v/%v\n", newL7Rules.TerminatingTLS, l7Rules.TerminatingTLS)
				return fmt.Errorf("cannot merge conflicting terminating TLS contexts for cached selector %s: (%v/%v)", idset, newL7Rules.TerminatingTLS, l7Rules.TerminatingTLS)
			}
			if l7Rules.OriginatingTLS == nil || newL7Rules.OriginatingTLS == nil {
				if newL7Rules.OriginatingTLS != nil {
					l7Rules.OriginatingTLS = newL7Rules.OriginatingTLS
				}
			} else if !newL7Rules.OriginatingTLS.Equal(l7Rules.OriginatingTLS) {
				policyCtx.PolicyTrace("   Merge conflict: mismatching originating TLS contexts %v/%v\n", newL7Rules.OriginatingTLS, l7Rules.OriginatingTLS)
				return fmt.Errorf("cannot merge conflicting originating TLS contexts for cached selector %s: (%v/%v)", idset, newL7Rules.OriginatingTLS, l7Rules.OriginatingTLS)
			}

			// For now we simply merge the set of allowed SNIs from different rules
			// to/from the *same remote*, port, and protocol. This means that if any
			// rule requires SNI, then all traffic to that remote/port requires TLS,
			// even if other merged rules would be fine without TLS. Any SNI from all
			// applicable rules is allowed.
			//
			// Preferably we could allow different rules for each SNI, but for now the
			// combination of all L7 rules is allowed for all the SNIs. For example, if
			// SNI and TLS termination are used together so that L7 filtering is
			// possible, in this example:
			//
			// - existing: SNI: public.example.com
			// - new:      SNI: private.example.com HTTP: path="/public"
			//
			// Separately, these rule allow access to all paths at SNI
			// public.example.com and path private.example.com/public, but currently we
			// allow all paths also at private.example.com. This may be clamped down if
			// there is sufficient demand for SNI and TLS termination together.
			//
			// Note however that SNI rules are typically used with `toFQDNs`, each of
			// which defines a separate destination, so that SNIs for different
			// `toFQDNs` will not be merged together.
			l7Rules.ServerNames = l7Rules.ServerNames.Merge(newL7Rules.ServerNames)

			// L7 rules can be applied with SNI filtering only if the TLS is also
			// terminated
			if len(l7Rules.ServerNames) > 0 && !l7Rules.L7Rules.IsEmpty() && l7Rules.TerminatingTLS == nil {
				policyCtx.PolicyTrace("   Merge conflict: cannot use SNI filtering with L7 rules without TLS termination: %v\n", l7Rules.ServerNames)
				return fmt.Errorf("cannot merge L7 rules for cached selector %s with SNI filtering without TLS termination: %v", idset, l7Rules.ServerNames)
			}

			// empty L7 rules effectively wildcard L7. When merging with a non-empty
			// rule, the empty must be expanded to an actual wildcard rule for the
			// specific L7
			if !l7Rules.HasL7Rules() && newL7Rules.HasL7Rules() {
				l7Rules.L7Rules = newL7Rules.appendL7WildcardRule(policyCtx)
				existingFilter.PerIdentityPolicies[idset] = l7Rules
				continue
			}
			if l7Rules.HasL7Rules() && !newL7Rules.HasL7Rules() {
				l7Rules.appendL7WildcardRule(policyCtx)
				existingFilter.PerIdentityPolicies[idset] = l7Rules
				continue
			}

			// We already know from the L7Parser.Merge() above that there are no
			// conflicting parser types, and rule validation only allows one type of L7
			// rules in a rule, so we can just merge the rules here.
			for _, newRule := range newL7Rules.HTTP {
				if !newRule.Exists(l7Rules.L7Rules) {
					l7Rules.HTTP = append(l7Rules.HTTP, newRule)
				}
			}
			for _, newRule := range newL7Rules.Kafka {
				if !newRule.Exists(l7Rules.L7Rules.Kafka) {
					l7Rules.Kafka = append(l7Rules.Kafka, newRule)
				}
			}
			if l7Rules.L7Proto == "" && newL7Rules.L7Proto != "" {
				l7Rules.L7Proto = newL7Rules.L7Proto
			}
			for _, newRule := range newL7Rules.L7 {
				if !newRule.Exists(l7Rules.L7Rules) {
					l7Rules.L7 = append(l7Rules.L7, newRule)
				}
			}
			for _, newRule := range newL7Rules.DNS {
				if !newRule.Exists(l7Rules.L7Rules) {
					l7Rules.DNS = append(l7Rules.DNS, newRule)
				}
			}
			// Update the pointer in the map in case it was newly allocated
			existingFilter.PerIdentityPolicies[idset] = l7Rules
		} else { // 'idset' is not in the existing filter, add it

			// Move L7 rules over.
			existingFilter.PerIdentityPolicies[idset] = newL7Rules

			if idset == "0" {
				existingFilter.wildcardId = true
			}
		}
	}

	return nil
}

func mergeIngressPortProtoWithIdentities(policyCtx PolicyContext, endpoints map[identity.NumericIdentity]struct{}, auth *api.Authentication, hostWildcardL7 []string,
	r api.Ports, p api.PortProtocol, proto api.L4Proto, ruleLabels stringLabels, resMap L4PolicyMap) (int, error) {
	// Create a new L4Filter
	filterToMerge, err := createL4IngressFilterFromIdentities(policyCtx, endpoints, auth, hostWildcardL7, r, p, proto, ruleLabels)
	if err != nil {
		return 0, err
	}

	err = addL4Filter(policyCtx, resMap, p, proto, filterToMerge)
	if err != nil {
		return 0, err
	}
	return 1, err
}

func mergeEgressPortProtoWithIdentities(policyCtx PolicyContext, endpoints map[identity.NumericIdentity]struct{}, auth *api.Authentication,
	r api.Ports, p api.PortProtocol, proto api.L4Proto, ruleLabels stringLabels, resMap L4PolicyMap) (int, error) {
	// Create a new L4Filter
	filterToMerge, err := createL4EgressFilterFromIdentities(policyCtx, endpoints, auth, r, p, proto, ruleLabels)
	if err != nil {
		return 0, err
	}

	err = addL4Filter(policyCtx, resMap, p, proto, filterToMerge)
	if err != nil {
		return 0, err
	}
	return 1, err
}
