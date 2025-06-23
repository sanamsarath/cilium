package policy

/*
resolvedIdentityPolicyCache is a cache for storing resolved policies within policy repository.
This file defines the structure and methods for managing the cache of resolved policies.
*/

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/container/set"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type resolvedIdentityPolicyCache struct {
	lock.Mutex
	logger   *slog.Logger
	repo     *Repository
	policies map[identityPkg.NumericIdentity]*IdentityPolicyState
}

// newresolvedIdentityPolicyCache creates a new cache of IdentityPolicyState.
func newresolvedIdentityPolicyCache(repo *Repository) *resolvedIdentityPolicyCache {
	return &resolvedIdentityPolicyCache{
		logger:   repo.logger.With("subsys", "resolvedIdentityPolicyCache"),
		repo:     repo,
		policies: make(map[identityPkg.NumericIdentity]*IdentityPolicyState),
	}
}

// UpdateResolvedPolicy in the resolvedIdentityPolicyCache.
func (cache *resolvedIdentityPolicyCache) UpdateResolvedPolicy(rp *ResolvedPolicy) *set.Set[identityPkg.NumericIdentity] {
	// for each identity in the resolved policy, lookup or create
	// IdentityPolicyState and add a map entry reference to the ResolvedPolicy.
	// Return the set of identities that were updated.
	affectedIdentities := &set.Set[identityPkg.NumericIdentity]{}
	for id := range rp.AppliesTo {
		// lookup or create IdentityPolicyState for the identity
		ips := cache.lookupOrCreateIdentityPolicyState(id)
		if ips == nil {
			cache.logger.Error("Failed to lookup or create IdentityPolicyState for ResolvedPolicy",
				"sourcePolicyUID", rp.SourcePolicyUID, "subjectID", id)
			continue
		}
		ips.upsertResolvedPolicy(rp)
		affectedIdentities.Insert(id)
	}
	return affectedIdentities
}

// DeleteResolvedPolicy in the resolvedIdentityPolicyCache.
func (cache *resolvedIdentityPolicyCache) DeleteResolvedPolicy(rp *ResolvedPolicy) *set.Set[identityPkg.NumericIdentity] {
	// for each matching identity in the ResolvedPolicy, lookup IdentityPolicyState
	// and delete the map entry for ResolvedPolicy stored inside IdentityPolicyState.
	affectedIdentities := &set.Set[identityPkg.NumericIdentity]{}
	for id := range rp.AppliesTo {
		// lookup IdentityPolicyState for the identity
		ips := cache.lookupIdentityPolicyState(id)
		if ips == nil {
			cache.logger.Debug("IdentityPolicyState for ResolvedPolicy",
				"sourcePolicyUID", rp.SourcePolicyUID, "subjectID", id, "notFound", true)
			continue
		}
		ips.deleteResolvedPolicy(rp.SourcePolicyUID)
		affectedIdentities.Insert(id)
	}
	return affectedIdentities
}

// lookupOrCreate adds a new IdentityPolicyState for the specified Identity,
// if it does not already exist, and returns the existing or newly created.
func (cache *resolvedIdentityPolicyCache) lookupOrCreateIdentityPolicyState(id identityPkg.NumericIdentity) *IdentityPolicyState {
	cache.Lock()
	defer cache.Unlock()
	ips, ok := cache.policies[id]
	if !ok {
		ips = &IdentityPolicyState{
			ComputedPolicy:    nil,
			MatchingCRPUIDset: make(map[string]*ResolvedPolicy),
		}
		cache.policies[id] = ips
	}
	return ips
}

// lookupIdentityPolicyState returns the IdentityPolicyState for the specified identity,
func (cache *resolvedIdentityPolicyCache) lookupIdentityPolicyState(id identityPkg.NumericIdentity) *IdentityPolicyState {
	cache.Lock()
	defer cache.Unlock()
	return cache.policies[id]
}

// getPolicy returns the cached selectorPolicy from the IdentityPolicyState
// lock should be held on the IdentityPolicyState when calling this method.
func (ips *IdentityPolicyState) getPolicy() *selectorPolicy {
	return ips.ComputedPolicy
}

// upsertResolvedPolicy adds a ResolvedPolicy to the IdentityPolicyState for the specified identity.
func (ips *IdentityPolicyState) upsertResolvedPolicy(rp *ResolvedPolicy) {
	// acquire lock
	ips.Lock()
	defer ips.Unlock()
	ips.MatchingCRPUIDset[rp.SourcePolicyUID] = rp
	ips.RecomputePolicy = true // Mark that the policy needs to be recomputed
}

// deleteResolvedPolicy removes a ResolvedPolicy from the IdentityPolicyState for the specified identity.
func (ips *IdentityPolicyState) deleteResolvedPolicy(sourceUID string) {
	// acquire lock
	ips.Lock()
	defer ips.Unlock()
	delete(ips.MatchingCRPUIDset, sourceUID)
	ips.RecomputePolicy = true // Mark that the policy needs to be recomputed
}

// updateSelectorPolicy resolves the policy for the security identity of the
// specified endpoint and stores it internally. It will skip policy resolution
// if the cached policy is already at the revision specified in the repo.
// endpointID
//
// Returns whether the cache was updated, or an error.
func (cache *resolvedIdentityPolicyCache) updateSelectorPolicy(identity *identityPkg.Identity) (*selectorPolicy, bool, error) {
	ips := cache.lookupOrCreateIdentityPolicyState(identity.ID)

	// Lock the 'ips' for the duration of the revision check and
	// the possible policy update.
	ips.Lock()
	defer ips.Unlock()

	// repo revision
	rev := cache.repo.GetRevision()
	// Don't resolve policy if it was already done for this or later revision.
	if selPolicy := ips.getPolicy(); selPolicy != nil && selPolicy.Revision >= rev {
		return selPolicy, false, nil
	}

	// Don't resolve policy if the policy is not marked for recompute. Just update
	// the revision in the selectorPolicy and return it. This will avoid unnecessary
	// recomputations of the policy during the periodic endpoint regeneration.
	if selPolicy := ips.getPolicy(); selPolicy != nil && !ips.RecomputePolicy {
		// Update the revision in the existing policy
		selPolicy.Revision = rev
		return selPolicy, false, nil
	}

	// Resolve the policies, which could fail
	selPolicy, err := ips.resolvePolicyLocked(identity, rev, cache.repo)
	if err != nil {
		return nil, false, err
	}

	// Set the computed policy in the IdentityPolicyState
	ips.ComputedPolicy = selPolicy

	// set revision in the selectorPolicy
	selPolicy.Revision = rev

	// Reset the recompute flag after successful policy resolution
	ips.RecomputePolicy = false

	return selPolicy, true, nil
}

func (ips *IdentityPolicyState) resolvePolicyLocked(securityIdentity *identityPkg.Identity, rev uint64, repo *Repository) (*selectorPolicy, error) {
	calculatedPolicy := &selectorPolicy{
		Revision:      rev,
		SelectorCache: repo.GetSelectorCache(), // passing this to satisfy selctorPolicy attach and detach called by callers(like Endpoints)
		L4Policy:      NewL4Policy(rev),
	}

	policyCtx := policyContext{
		repo:               repo,
		ns:                 securityIdentity.LabelArray.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel),
		defaultDenyIngress: false, // controller is expected to handle this?? otherwise we can fix it here
		defaultDenyEgress:  false, // controller is expected to handle this?? otherwise we can fix it here
		traceEnabled:       option.Config.TracingEnabled(),
		logger:             repo.logger.With(logfields.Identity, securityIdentity.ID),
	}

	newL4IngressPolicy, ingressExists, err := ips.MatchingCRPUIDset.resolveL4IngressPolicy(&policyCtx)
	if err != nil {
		return nil, err
	}

	newL4EgressPolicy, egressExists, err := ips.MatchingCRPUIDset.resolveL4EgressPolicy(&policyCtx)
	if err != nil {
		return nil, err
	}

	// Set the L4 policies in the calculated policy
	if newL4IngressPolicy != nil {
		calculatedPolicy.L4Policy.Ingress.PortRules = newL4IngressPolicy
	}

	if ingressExists {
		calculatedPolicy.IngressPolicyEnabled = true
	}

	if newL4EgressPolicy != nil {
		calculatedPolicy.L4Policy.Egress.PortRules = newL4EgressPolicy
	}

	if egressExists {
		calculatedPolicy.EgressPolicyEnabled = true
	}

	// Attach doesn't do much in centralized mode, as we don't listen on increamental updates
	// from the L4 Filters but calculates redirect features from all the all L4 filters and
	// update the L4Policy in the selectorPolicy.
	calculatedPolicy.Attach(&policyCtx)

	return calculatedPolicy, nil
}
