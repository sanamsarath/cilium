package k8s

import (
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

// onCRPUpsert handles CiliumResolvedPolicy update events.
func (p *policyWatcher) onUpsertCRP(
	crp *types.SlimCRP,
	key resource.Key,
	apiGroup string,
	dc chan uint64,
) error {
	initialRecvTime := time.Now()

	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	// Check if the CiliumResolvedPolicy has changed.
	oldCRP, ok := p.crpCache[key]
	if ok {
		// No generation change; this was a status update.
		if oldCRP.Generation == crp.Generation {
			return nil
		}
		if oldCRP.DeepEqual(crp) {
			return nil
		}

		p.log.Debug(
			"Modified CiliumResolvedPolicy",
			logfields.K8sAPIVersion, crp.TypeMeta.APIVersion,
			logfields.Name, crp.ObjectMeta.Name,
		)
	}

	// Convert the CiliumResolvedPolicy spec to CRPRuleSet.
	crpRuleset, err := policy.ConvertToCRPRuleSet(crp.Spec)
	if err != nil {
		p.log.Info(
			"Failed to convert CiliumResolvedPolicy spec to CRPRuleSet",
			logfields.K8sAPIVersion, crp.TypeMeta.APIVersion,
			logfields.Name, crp.ObjectMeta.Name)
		return err
	}

	if dc != nil {
		p.crpSyncPending.Add(1)
	}

	// Policy update
	upd := &policy.ResolvedIdentityPolicyUpdate{
		ProcessingStartTime: initialRecvTime,
		CrpRuleSet:          crpRuleset,
		DoneChan:            dc,
		Operation:           policy.ResolvedIdentityPolicyUpsert,
	}

	// Forward upsert event to the policy importer.
	p.policyImporter.UpdateResolvedIdentityPolicy(upd)

	// updat the cache with the new CiliumResolvedPolicy.
	p.crpCache[key] = crp

	return nil
}

// onCRPDelete handles CiliumResolvedPolicy delete events.
func (p *policyWatcher) onDeleteCRP(
	crp *types.SlimCRP,
	key resource.Key,
	apiGroup string,
	dc chan uint64,
) {

	intialRecvTime := time.Now()
	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()

	// Get oldCRP from the cache and pass it to policyImporter for processing,
	// with delete operation. SubjectIdentity list stored in oldCRP will be used
	// to remove the identities from the cache.
	oldCRP, ok := p.crpCache[key]
	if !ok {
		p.log.Debug(
			"Deleted CiliumResolvedPolicy not found in cache",
			logfields.K8sAPIVersion, crp.TypeMeta.APIVersion,
			logfields.Name, crp.ObjectMeta.Name,
		)
		return
	}

	// convert the CiliumResolvedPolicy spec to CRPRuleSet
	crpRuleset, err := policy.ConvertToCRPRuleSet(oldCRP.Spec)
	if err != nil {
		p.log.Info(
			"Failed to convert CiliumResolvedPolicy spec to CRPRuleSet",
			logfields.K8sAPIVersion, oldCRP.TypeMeta.APIVersion,
			logfields.Name, oldCRP.ObjectMeta.Name)
		return
	}

	if dc != nil {
		p.crpSyncPending.Add(1)
	}

	// Forward delete event to the policy importer.
	upd := &policy.ResolvedIdentityPolicyUpdate{
		ProcessingStartTime: intialRecvTime,
		CrpRuleSet:          crpRuleset,
		DoneChan:            dc,
		Operation:           policy.ResolvedIdentityPolicyDelete,
	}

	p.policyImporter.UpdateResolvedIdentityPolicy(upd)

	// Remove the CiliumResolvedPolicy from the cache.
	delete(p.crpCache, key)
}
