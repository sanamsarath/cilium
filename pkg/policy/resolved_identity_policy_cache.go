package policy

/*
resolvedIdentityPolicyCache is a cache for storing resolved policies within policy repository.
This file defines the structure and methods for managing the cache of resolved policies.
*/

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/container/set"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
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
		ips := cache.lookupOrCreateIdentityPolicyState(id)
		if ips == nil {
			cache.logger.Info("Failed to lookup IdentityPolicyState for ResolvedPolicy",
				"sourcePolicyUID", rp.SourcePolicyUID, "subjectID", id)
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

// delete removes the IdentityPolicyState for the specified identity.
func (cache *resolvedIdentityPolicyCache) delete(identity *identityPkg.Identity) bool {
	cache.Lock()
	defer cache.Unlock()
	ips, ok := cache.policies[identity.ID]
	if ok {
		delete(cache.policies, identity.ID)
		ips.ComputedPolicy = nil // Clear the cached policy
	}
	return ok
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
}

// deleteResolvedPolicy removes a ResolvedPolicy from the IdentityPolicyState for the specified identity.
func (ips *IdentityPolicyState) deleteResolvedPolicy(sourceUID string) {
	// acquire lock
	ips.Lock()
	defer ips.Unlock()
	delete(ips.MatchingCRPUIDset, sourceUID)
}
