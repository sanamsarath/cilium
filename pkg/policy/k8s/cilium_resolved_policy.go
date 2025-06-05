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

	// If CRP status is not Synced, we do not process it.
	// if crp.Status.SyncState != v2alpha1.SyncStateSynced {
	// 	p.log.Debug(
	// 		"CRPUpsert: Skipping CiliumResolvedPolicy update as status is not Synced",
	// 		logfields.K8sAPIVersion, crp.TypeMeta.APIVersion,
	// 		logfields.Name, crp.ObjectMeta.Name,
	// 		logfields.Status, crp.Status,
	// 	)
	// 	return nil
	// }

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
			"CRPUpsert: Modified CiliumResolvedPolicy",
			logfields.K8sAPIVersion, crp.TypeMeta.APIVersion,
			logfields.Name, crp.ObjectMeta.Name,
		)
	}

	// Convert the CiliumResolvedPolicy spec to internal crp internal struct ResolvedPolicy
	resolvedPolicy, err := policy.ConvertToResolvedPolicy(&crp.Spec, string(crp.UID))
	if err != nil {
		p.log.Info(
			"CRPUpsert: Failed to process CiliumResolvedPolicy spec",
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
		ResolvedPolicy:      resolvedPolicy,
		DoneChan:            dc,
		Operation:           policy.ResolvedIdentityPolicyUpsert,
	}

	// Forward upsert event to the policy importer.
	p.policyImporter.UpdateResolvedIdentityPolicy(upd)

	// update the cache with the new CiliumResolvedPolicy.
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
			"CRPDelete: CiliumResolvedPolicy not found in cache, ignoring delete event",
			logfields.K8sAPIVersion, crp.TypeMeta.APIVersion,
			logfields.Name, crp.ObjectMeta.Name,
		)
		return
	}

	// Convert the CiliumResolvedPolicy spec to internal crp internal struct ResolvedPolicy
	resolvedPolicy, err := policy.ConvertToResolvedPolicy(&oldCRP.Spec, string(oldCRP.UID))
	if err != nil {
		p.log.Info(
			"CRPDelete: Failed to process CiliumResolvedPolicy spec",
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
		ResolvedPolicy:      resolvedPolicy,
		DoneChan:            dc,
		Operation:           policy.ResolvedIdentityPolicyDelete,
	}

	p.policyImporter.UpdateResolvedIdentityPolicy(upd)

	// Remove the CiliumResolvedPolicy from the cache.
	delete(p.crpCache, key)
}
